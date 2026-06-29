#!/usr/bin/env python3
"""
wazuh_gui.py
============
Local web GUI for the Wazuh reporting tool.

Two jobs:
  1. Edit the YAML configuration file (config/reports.conf.yaml) through a
     browser form instead of hand-editing YAML.
  2. Run on-demand reports with a button and watch the live log output.

It does NOT reimplement any report logic. Running a report shells out to the
existing scripts/wazuh_report_runner.py, so the GUI stays a thin front-end and
behaves identically to the CLI.

Place this file in the repo's scripts/ directory (next to
wazuh_report_runner.py) and run:

    pip3 install flask pyyaml
    python3 scripts/wazuh_gui.py

Then open http://127.0.0.1:5000 in your browser.

Options:
    --host 127.0.0.1     Bind address (use 0.0.0.0 to reach it from outside a VM)
    --port 5000          Port (default: 5000)
    --config PATH        Config file (default: <repo>/config/reports.conf.yaml)
    --auth USER:PASS     Enable HTTP Basic Auth (or set WAZUH_GUI_AUTH env var)

SECURITY NOTE: this UI exposes and edits credentials in the config file.
Keep the default 127.0.0.1 bind so it is reachable only from this machine.
If you bind to 0.0.0.0 to access it from outside a VM, also set --auth so the
page is not open to the whole network.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("Missing dependency: pyyaml.  Install with:  pip3 install pyyaml")

try:
    from flask import Flask, Response, jsonify, render_template_string, request
except ImportError:
    sys.exit("Missing dependency: flask.  Install with:  pip3 install flask")


# -- Paths ---------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
CONFIG_DIR = PROJECT_ROOT / "config"
LIVE_CONFIG = CONFIG_DIR / "reports.conf.yaml"
EXAMPLE_CONFIG = CONFIG_DIR / "reports.conf.example.yaml"
RUNNER = SCRIPT_DIR / "wazuh_report_runner.py"

# Overridden by --config at startup.
CONFIG_PATH = LIVE_CONFIG

# Optional HTTP Basic Auth, set at startup from --auth or WAZUH_GUI_AUTH ("user:pass").
# When set, every request must supply matching credentials. Recommended whenever the
# GUI is bound to anything other than 127.0.0.1.
AUTH_USER = None
AUTH_PASS = None

app = Flask(__name__)


# -- Optional HTTP Basic Auth --------------------------------------------------

@app.before_request
def _require_auth():
    if AUTH_USER is None:
        return None  # auth disabled
    import hmac
    from flask import Response as _R
    a = request.authorization
    ok = (a and a.username is not None and a.password is not None
          and hmac.compare_digest(a.username, AUTH_USER)
          and hmac.compare_digest(a.password, AUTH_PASS))
    if not ok:
        return _R("Authentication required.", 401,
                  {"WWW-Authenticate": 'Basic realm="Wazuh Reporting GUI"'})
    return None


# -- YAML helpers --------------------------------------------------------------

class _LiteralStr(str):
    """A string that yaml should dump as a literal block scalar (| style)."""


def _literal_representer(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


yaml.add_representer(_LiteralStr, _literal_representer)


def _mark_multiline(obj):
    """Recursively convert multi-line strings so they dump as | blocks.

    Keeps email_body and similar fields readable in the saved YAML instead of
    a single quoted line with \\n escapes.
    """
    if isinstance(obj, dict):
        return {k: _mark_multiline(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mark_multiline(v) for v in obj]
    if isinstance(obj, str) and "\n" in obj:
        return _LiteralStr(obj)
    return obj


def load_config():
    """Load the live config; fall back to the example template if absent."""
    path = CONFIG_PATH if CONFIG_PATH.exists() else EXAMPLE_CONFIG
    if not path.exists():
        return {}, False
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return data, CONFIG_PATH.exists()


def save_config(data):
    """Write config to CONFIG_PATH, backing up any existing file first."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_PATH.exists():
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + f".bak.{stamp}")
        shutil.copy2(CONFIG_PATH, backup)
    payload = _mark_multiline(data)
    with open(CONFIG_PATH, "w") as f:
        f.write("# Managed by wazuh_gui.py — edits made in the web UI are saved here.\n")
        f.write(f"# Last saved: {datetime.now().isoformat(timespec='seconds')}\n\n")
        yaml.dump(payload, f, default_flow_style=False, sort_keys=False,
                  allow_unicode=True, width=100)


def on_demand_reports(cfg):
    """Reports the runner will accept: enabled and not scheduled."""
    out = []
    for r in cfg.get("reports", []) or []:
        if r.get("scheduled", False):
            continue
        out.append({
            "id": r.get("id", ""),
            "label": r.get("label", r.get("id", "")),
            "enabled": r.get("enabled", True),
            "format": r.get("format", "xlsx"),
            "send_as_pdf": r.get("send_as_pdf", False),
        })
    return out


# -- Routes: config API --------------------------------------------------------

@app.get("/api/config")
def api_get_config():
    cfg, live = load_config()
    return jsonify({
        "config": cfg,
        "live_exists": live,
        "config_path": str(CONFIG_PATH),
        "example_exists": EXAMPLE_CONFIG.exists(),
    })


@app.post("/api/config")
def api_save_config():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Invalid JSON payload."}), 400
    try:
        save_config(data)
    except Exception as exc:  # noqa: BLE001
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "config_path": str(CONFIG_PATH)})


@app.get("/api/reports")
def api_reports():
    cfg, _ = load_config()
    return jsonify({"reports": on_demand_reports(cfg)})


# -- Routes: run a report (streamed) -------------------------------------------

@app.get("/api/run")
def api_run():
    report_id = request.args.get("id", "")
    run_all = request.args.get("all") == "1"
    dry_run = request.args.get("dry_run") == "1"
    verbose = request.args.get("verbose") == "1"

    if not RUNNER.exists():
        def err():
            yield _sse(f"ERROR: runner not found at {RUNNER}\n")
            yield _sse("__DONE__:1")
        return Response(err(), mimetype="text/event-stream")

    cmd = [sys.executable, str(RUNNER), "--config", str(CONFIG_PATH)]
    if run_all:
        cmd.append("--all")
    elif report_id:
        cmd += ["--report", report_id]
    else:
        def noid():
            yield _sse("ERROR: no report selected.\n")
            yield _sse("__DONE__:1")
        return Response(noid(), mimetype="text/event-stream")
    if dry_run:
        cmd.append("--dry-run")
    if verbose:
        cmd.append("--verbose")

    def generate():
        yield _sse("$ " + " ".join(cmd) + "\n\n")
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as exc:  # noqa: BLE001
            yield _sse(f"ERROR launching runner: {exc}\n")
            yield _sse("__DONE__:1")
            return
        for line in iter(proc.stdout.readline, ""):
            yield _sse(line.rstrip("\n"))
        proc.stdout.close()
        rc = proc.wait()
        yield _sse(f"\n--- runner exited with code {rc} ---")
        yield _sse(f"__DONE__:{rc}")

    return Response(generate(), mimetype="text/event-stream")


def _sse(text):
    """Format a Server-Sent-Events data frame (handles multi-line safely)."""
    return "".join(f"data: {ln}\n" for ln in text.split("\n")) + "\n"


# -- Route: page ---------------------------------------------------------------

@app.get("/")
def index():
    return render_template_string(PAGE)


PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wazuh Reporting — Config & Runner</title>
<style>
  :root{
    --bg:#0f1419; --panel:#1a2129; --panel2:#222b36; --line:#2d3947;
    --txt:#e6edf3; --muted:#8b98a5; --accent:#3b82f6; --accent2:#2563eb;
    --ok:#22c55e; --warn:#f59e0b; --err:#ef4444; --radius:8px;
  }
  *{box-sizing:border-box}
  body{margin:0;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
       background:var(--bg);color:var(--txt);font-size:14px;line-height:1.5}
  header{background:var(--panel);border-bottom:1px solid var(--line);
         padding:14px 22px;display:flex;align-items:center;gap:14px;position:sticky;top:0;z-index:10}
  header h1{font-size:17px;margin:0;font-weight:600}
  header .path{color:var(--muted);font-size:12px;font-family:ui-monospace,monospace}
  .badge{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line)}
  .badge.live{color:var(--ok);border-color:var(--ok)}
  .badge.example{color:var(--warn);border-color:var(--warn)}
  .wrap{display:flex;gap:0;min-height:calc(100vh - 53px)}
  nav{width:190px;background:var(--panel);border-right:1px solid var(--line);padding:10px 0;flex:none}
  nav button{display:block;width:100%;text-align:left;background:none;border:none;color:var(--muted);
       padding:10px 22px;cursor:pointer;font-size:13px;border-left:3px solid transparent}
  nav button:hover{color:var(--txt);background:var(--panel2)}
  nav button.active{color:var(--txt);border-left-color:var(--accent);background:var(--panel2)}
  main{flex:1;padding:22px 28px;overflow:auto}
  section{display:none;max-width:920px}
  section.active{display:block}
  h2{font-size:15px;margin:0 0 4px;font-weight:600}
  .hint{color:var(--muted);font-size:12px;margin:0 0 18px}
  .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);
        padding:18px;margin-bottom:16px}
  .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  .field{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
  .field.full{grid-column:1 / -1}
  label{font-size:12px;color:var(--muted);font-weight:500}
  input,select,textarea{background:var(--bg);border:1px solid var(--line);color:var(--txt);
        padding:8px 10px;border-radius:6px;font-size:13px;font-family:inherit;width:100%}
  input:focus,select:focus,textarea:focus{outline:none;border-color:var(--accent)}
  textarea{resize:vertical;min-height:80px;font-family:ui-monospace,monospace;font-size:12px}
  .row-check{display:flex;align-items:center;gap:8px;margin-bottom:12px}
  .row-check input{width:auto}
  button.btn{background:var(--accent);color:#fff;border:none;padding:9px 16px;border-radius:6px;
        cursor:pointer;font-size:13px;font-weight:500}
  button.btn:hover{background:var(--accent2)}
  button.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
  button.btn.ghost:hover{border-color:var(--accent)}
  button.btn.danger{background:transparent;border:1px solid var(--err);color:var(--err)}
  button.btn.danger:hover{background:var(--err);color:#fff}
  button.btn.sm{padding:5px 10px;font-size:12px}
  .toolbar{display:flex;gap:10px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
  .spacer{flex:1}
  .group, .report{background:var(--panel2);border:1px solid var(--line);border-radius:var(--radius);
        padding:14px;margin-bottom:12px}
  .group-head,.report-head{display:flex;align-items:center;gap:10px;margin-bottom:10px}
  .group-head input{font-weight:600}
  .report-head .rid{font-weight:600;color:var(--accent)}
  .taglist{display:flex;flex-direction:column;gap:6px}
  .tag-row{display:flex;gap:6px}
  .tag-row input{flex:1}
  .muted-note{color:var(--muted);font-size:11px;margin-top:-6px;margin-bottom:10px}
  .toast{position:fixed;bottom:20px;right:20px;background:var(--panel);border:1px solid var(--line);
        border-left:4px solid var(--accent);padding:12px 18px;border-radius:6px;opacity:0;
        transform:translateY(10px);transition:.2s;pointer-events:none;z-index:50;max-width:380px}
  .toast.show{opacity:1;transform:translateY(0)}
  .toast.ok{border-left-color:var(--ok)} .toast.err{border-left-color:var(--err)}
  .run-list{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
  .run-item{display:flex;align-items:center;gap:12px;background:var(--panel2);
        border:1px solid var(--line);border-radius:6px;padding:10px 14px}
  .run-item .meta{flex:1}
  .run-item .meta .lbl{font-weight:500}
  .run-item .meta .sub{color:var(--muted);font-size:12px;font-family:ui-monospace,monospace}
  .pill{font-size:10px;padding:1px 7px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
  .pill.off{color:var(--err);border-color:var(--err)}
  .console{background:#05080b;border:1px solid var(--line);border-radius:var(--radius);
        padding:14px;font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;
        height:340px;overflow:auto;color:#c5d1dc}
  .console .e{color:var(--err)} .console .w{color:var(--warn)} .console .ok{color:var(--ok)}
  .console .cmd{color:var(--accent)}
  details summary{cursor:pointer;color:var(--muted);font-size:12px;margin-bottom:8px}
  code{background:var(--panel2);padding:1px 5px;border-radius:4px;font-size:12px}
</style>
</head>
<body>
<header>
  <h1>Wazuh Reporting</h1>
  <span id="statusBadge" class="badge">loading…</span>
  <span class="path" id="cfgPath"></span>
  <div class="spacer" style="flex:1"></div>
  <button class="btn ghost sm" onclick="reload()">Reload</button>
  <button class="btn" onclick="saveAll()">Save config</button>
</header>

<div class="wrap">
  <nav>
    <button data-tab="connection" class="active">Connection</button>
    <button data-tab="smtp">SMTP / Email</button>
    <button data-tab="groups">Recipient groups</button>
    <button data-tab="reports">Reports</button>
    <button data-tab="advanced">Storage / Logging</button>
    <button data-tab="run">▶ Run reports</button>
  </nav>

  <main>
    <section id="connection" class="active">
      <h2>Dashboard connection</h2>
      <p class="hint">Connection to your Wazuh / OpenSearch Dashboards instance. The password
        can be overridden at runtime with the <code>WAZUH_DASH_PASS</code> env var.</p>
      <div class="card">
        <div class="grid">
          <div class="field full"><label>Dashboard URL</label>
            <input id="d_url" placeholder="https://wazuh.corp.example.com:443"></div>
          <div class="field"><label>Username</label><input id="d_username"></div>
          <div class="field"><label>Password</label><input id="d_password" type="password"></div>
          <div class="field"><label>Timezone (IANA)</label>
            <input id="d_timezone" placeholder="America/Asuncion"></div>
          <div class="field"><label>Timeout (seconds)</label>
            <input id="d_timeout" type="number" min="1"></div>
          <div class="field"><label>Date format</label>
            <input id="d_dateformat" placeholder="MMM D, YYYY @ HH:mm:ss.SSS"></div>
          <div class="field"><label>CSV separator</label><input id="d_csvsep"></div>
        </div>
        <div class="row-check"><input type="checkbox" id="d_verify"><label for="d_verify"
          style="color:var(--txt)">Verify SSL certificate (enable in production)</label></div>
      </div>
    </section>

    <section id="smtp">
      <h2>SMTP / Email delivery</h2>
      <p class="hint">Used to email generated reports. Password can be overridden with
        <code>WAZUH_SMTP_PASS</code>. Gmail: <code>smtp.gmail.com:587</code> + App Password.
        Office 365: <code>smtp.office365.com:587</code>.</p>
      <div class="card">
        <div class="grid">
          <div class="field"><label>SMTP host</label><input id="s_host"></div>
          <div class="field"><label>Port</label><input id="s_port" type="number"></div>
          <div class="field"><label>Username</label><input id="s_username"></div>
          <div class="field"><label>Password</label><input id="s_password" type="password"></div>
          <div class="field"><label>From address</label><input id="s_from"></div>
          <div class="field"><label>From name</label><input id="s_fromname"></div>
        </div>
        <div class="row-check"><input type="checkbox" id="s_tls"><label for="s_tls"
          style="color:var(--txt)">Use STARTTLS</label></div>
      </div>
    </section>

    <section id="groups">
      <h2>Recipient groups</h2>
      <p class="hint">Named lists of email addresses. Reference a group by name in a report's
        recipients, or use a raw address directly.</p>
      <div class="toolbar">
        <button class="btn ghost sm" onclick="addGroup()">+ Add group</button>
      </div>
      <div id="groupsList"></div>
    </section>

    <section id="reports">
      <h2>Report definitions</h2>
      <p class="hint">Each report maps to a Report Definition in the Wazuh Dashboard.
        <code>report_def_id</code> comes from the Report Definition edit URL. Scheduled reports
        require <code>report_name_match</code> and <code>check_window_minutes</code>.</p>
      <div class="toolbar">
        <button class="btn ghost sm" onclick="addReport(false)">+ On-demand report</button>
        <button class="btn ghost sm" onclick="addReport(true)">+ Scheduled report</button>
      </div>
      <div id="reportsList"></div>
    </section>

    <section id="advanced">
      <h2>Storage &amp; logging</h2>
      <p class="hint">Where downloaded report files and logs are written (relative to the
        project root, or absolute paths).</p>
      <div class="card">
        <div class="grid">
          <div class="field"><label>Output directory</label><input id="st_dir" placeholder="logs/downloads"></div>
          <div class="field"><label>Keep files (days)</label><input id="st_keep" type="number"></div>
          <div class="field"><label>Log file</label><input id="lg_file" placeholder="logs/report-runner.log"></div>
          <div class="field"><label>Log level</label>
            <select id="lg_level"><option>DEBUG</option><option>INFO</option>
              <option>WARNING</option><option>ERROR</option></select></div>
        </div>
      </div>
    </section>

    <section id="run">
      <h2>Run reports on demand</h2>
      <p class="hint">Runs <code>wazuh_report_runner.py</code> against the saved config. Only
        enabled, non-scheduled reports appear here. <strong>Save your config first</strong> so the
        runner picks up your latest changes.</p>
      <div class="toolbar">
        <button class="btn" onclick="runReport('', true)">▶ Run ALL enabled</button>
        <label class="row-check" style="margin:0"><input type="checkbox" id="opt_dry">
          <span style="color:var(--txt)">Dry-run (no API call, no email)</span></label>
        <label class="row-check" style="margin:0"><input type="checkbox" id="opt_verbose">
          <span style="color:var(--txt)">Verbose</span></label>
      </div>
      <div id="runList" class="run-list"></div>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <strong style="font-size:13px">Output</strong>
        <button class="btn ghost sm" onclick="clearConsole()">Clear</button>
        <span id="runStatus" class="badge"></span>
      </div>
      <div id="console" class="console">Idle. Select a report above to run it.</div>
    </section>
  </main>
</div>

<div id="toast" class="toast"></div>

<script>
let CFG = {};

document.querySelectorAll('nav button').forEach(b=>{
  b.onclick=()=>{
    document.querySelectorAll('nav button').forEach(x=>x.classList.remove('active'));
    document.querySelectorAll('section').forEach(x=>x.classList.remove('active'));
    b.classList.add('active');
    document.getElementById(b.dataset.tab).classList.add('active');
    if(b.dataset.tab==='run') refreshRunList();
  };
});

function toast(msg, kind){
  const t=document.getElementById('toast');
  t.textContent=msg; t.className='toast show '+(kind||'');
  setTimeout(()=>t.className='toast '+(kind||''),3200);
}
const val=(id,v)=>{const e=document.getElementById(id); if(e) e.value=(v??'');};
const get=(id)=>{const e=document.getElementById(id); return e?e.value:'';};
const chk=(id,v)=>{const e=document.getElementById(id); if(e) e.checked=!!v;};
const isChk=(id)=>{const e=document.getElementById(id); return e?e.checked:false;};

async function reload(){
  const r=await fetch('/api/config'); const j=await r.json();
  CFG=j.config||{};
  document.getElementById('cfgPath').textContent=j.config_path;
  const b=document.getElementById('statusBadge');
  if(j.live_exists){b.textContent='live config'; b.className='badge live';}
  else {b.textContent='example (not yet saved)'; b.className='badge example';}
  populate();
}

function populate(){
  const d=CFG.dashboard||{};
  val('d_url',d.url); val('d_username',d.username); val('d_password',d.password);
  val('d_timezone',d.timezone); val('d_timeout',d.timeout_seconds);
  val('d_dateformat',d.date_format); val('d_csvsep',d.csv_separator);
  chk('d_verify',d.verify_ssl);

  const s=CFG.smtp||{};
  val('s_host',s.host); val('s_port',s.port); val('s_username',s.username);
  val('s_password',s.password); val('s_from',s.from_address); val('s_fromname',s.from_name);
  chk('s_tls',s.use_tls!==false);

  renderGroups(); renderReports();

  const st=CFG.storage||{}; val('st_dir',st.output_dir); val('st_keep',st.keep_days);
  const lg=CFG.logging||{}; val('lg_file',lg.log_file);
  document.getElementById('lg_level').value=(lg.level||'INFO');
}

function renderGroups(){
  const wrap=document.getElementById('groupsList'); wrap.innerHTML='';
  const groups=CFG.recipient_groups||{};
  Object.keys(groups).forEach(name=>groupCard(name, groups[name]||[]));
  if(!Object.keys(groups).length) wrap.innerHTML='<p class="hint">No groups yet.</p>';
}
function groupCard(name, emails){
  const wrap=document.getElementById('groupsList');
  const el=document.createElement('div'); el.className='group';
  el.innerHTML=`
    <div class="group-head">
      <input class="g-name" value="${esc(name)}" placeholder="group_name">
      <div class="spacer" style="flex:1"></div>
      <button class="btn sm ghost" onclick="this.closest('.group').querySelector('.taglist')
        .appendChild(emailRow(''))">+ Email</button>
      <button class="btn sm danger" onclick="this.closest('.group').remove()">Remove</button>
    </div>
    <div class="taglist"></div>`;
  const tl=el.querySelector('.taglist');
  (emails.length?emails:['']).forEach(e=>tl.appendChild(emailRow(e)));
  wrap.appendChild(el);
}
function emailRow(v){
  const r=document.createElement('div'); r.className='tag-row';
  r.innerHTML=`<input value="${esc(v)}" placeholder="user@example.com">
    <button class="btn sm danger" onclick="this.closest('.tag-row').remove()">×</button>`;
  return r;
}
function addGroup(){
  if(document.getElementById('groupsList').querySelector('.hint'))
    document.getElementById('groupsList').innerHTML='';
  groupCard('new_group',['']);
}

function renderReports(){
  const wrap=document.getElementById('reportsList'); wrap.innerHTML='';
  (CFG.reports||[]).forEach(r=>reportCard(r));
  if(!(CFG.reports||[]).length) wrap.innerHTML='<p class="hint">No reports yet.</p>';
}
function reportCard(r){
  const wrap=document.getElementById('reportsList');
  const sched=!!r.scheduled;
  const el=document.createElement('div'); el.className='report'; el.dataset.scheduled=sched;
  el.innerHTML=`
    <div class="report-head">
      <span class="rid">${sched?'⏱ scheduled':'▶ on-demand'}</span>
      <input class="r-id" value="${esc(r.id||'')}" placeholder="unique_id" style="max-width:240px">
      <div class="spacer" style="flex:1"></div>
      <label class="row-check" style="margin:0"><input type="checkbox" class="r-enabled" ${r.enabled!==false?'checked':''}>
        <span style="color:var(--txt);font-size:12px">enabled</span></label>
      <button class="btn sm danger" onclick="this.closest('.report').remove()">Remove</button>
    </div>
    <div class="grid">
      <div class="field full"><label>Label</label><input class="r-label" value="${esc(r.label||'')}"></div>
      <div class="field"><label>Report Definition ID</label><input class="r-defid" value="${esc(r.report_def_id||'')}"></div>
      <div class="field"><label>Format</label><select class="r-format">
        <option ${r.format==='xlsx'?'selected':''}>xlsx</option>
        <option ${r.format==='csv'?'selected':''}>csv</option></select></div>
      <div class="field">
        <label class="row-check" style="margin:0">
          <input type="checkbox" class="r-send-pdf" ${r.send_as_pdf?'checked':''}>
          <span style="color:var(--txt)">Convert to PDF before emailing</span>
        </label>
        <span class="muted-note">Converts XLSX/CSV to a formatted PDF using fpdf2.</span>
      </div>
      ${sched?`
      <div class="field"><label>report_name_match (exact Dashboard name)</label>
        <input class="r-namematch" value="${esc(r.report_name_match||'')}"></div>
      <div class="field"><label>check_window_minutes</label>
        <input class="r-window" type="number" value="${esc(r.check_window_minutes??90)}"></div>
      <div class="field full"><label>schedule_label</label>
        <input class="r-schedlabel" value="${esc(r.schedule_label||'')}"></div>`:''}
      <div class="field full"><label>Recipients (one per line — group name or raw email)</label>
        <textarea class="r-recipients">${esc((r.recipients||[]).join('\n'))}</textarea></div>
      <div class="field full"><label>Email subject (placeholders: {date} {month} {year} {report_label}${sched?' {schedule_label} {generated_at} {instance_id}':''})</label>
        <input class="r-subject" value="${esc(r.email_subject||'')}"></div>
      <div class="field full"><label>Email body</label>
        <textarea class="r-body">${esc(r.email_body||'')}</textarea></div>
    </div>`;
  wrap.appendChild(el);
}
function addReport(scheduled){
  if(document.getElementById('reportsList').querySelector('.hint'))
    document.getElementById('reportsList').innerHTML='';
  const base={id:'',label:'',report_def_id:'',format:'xlsx',enabled:true,send_as_pdf:false,recipients:[]};
  if(scheduled){base.scheduled=true; base.report_name_match=''; base.check_window_minutes=90; base.schedule_label='';}
  reportCard(base);
}

function collect(){
  const c=JSON.parse(JSON.stringify(CFG));
  c.dashboard=Object.assign({}, c.dashboard, {
    url:get('d_url'), username:get('d_username'), password:get('d_password'),
    verify_ssl:isChk('d_verify'), timeout_seconds:num(get('d_timeout'),60),
    timezone:get('d_timezone'), date_format:get('d_dateformat'), csv_separator:get('d_csvsep')});
  c.smtp=Object.assign({}, c.smtp, {
    host:get('s_host'), port:num(get('s_port'),587), use_tls:isChk('s_tls'),
    username:get('s_username'), password:get('s_password'),
    from_address:get('s_from'), from_name:get('s_fromname')});

  const groups={};
  document.querySelectorAll('#groupsList .group').forEach(g=>{
    const nm=g.querySelector('.g-name').value.trim(); if(!nm) return;
    const emails=[...g.querySelectorAll('.taglist input')].map(i=>i.value.trim()).filter(Boolean);
    groups[nm]=emails;
  });
  c.recipient_groups=groups;

  const reports=[];
  document.querySelectorAll('#reportsList .report').forEach(r=>{
    const sched=r.dataset.scheduled==='true';
    const obj={
      id:r.querySelector('.r-id').value.trim(),
      label:r.querySelector('.r-label').value,
      report_def_id:r.querySelector('.r-defid').value.trim(),
      format:r.querySelector('.r-format').value,
      enabled:r.querySelector('.r-enabled').checked,
      send_as_pdf:r.querySelector('.r-send-pdf').checked,
      recipients:r.querySelector('.r-recipients').value.split('\n').map(x=>x.trim()).filter(Boolean),
    };
    if(sched){
      obj.scheduled=true;
      obj.schedule_label=r.querySelector('.r-schedlabel').value;
      obj.report_name_match=r.querySelector('.r-namematch').value.trim();
      obj.check_window_minutes=num(r.querySelector('.r-window').value,90);
    }
    const subj=r.querySelector('.r-subject').value; if(subj) obj.email_subject=subj;
    const body=r.querySelector('.r-body').value; if(body) obj.email_body=body;
    if(obj.id) reports.push(obj);
  });
  c.reports=reports;

  c.storage=Object.assign({}, c.storage, {output_dir:get('st_dir'), keep_days:num(get('st_keep'),30)});
  c.logging=Object.assign({}, c.logging, {log_file:get('lg_file'), level:document.getElementById('lg_level').value});
  return c;
}

async function saveAll(){
  const c=collect();
  const r=await fetch('/api/config',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify(c)});
  const j=await r.json();
  if(j.ok){CFG=c; toast('Saved → '+j.config_path,'ok'); reload();}
  else toast('Save failed: '+(j.error||'unknown'),'err');
}

let evtSource=null;
async function refreshRunList(){
  const r=await fetch('/api/reports'); const j=await r.json();
  const wrap=document.getElementById('runList'); wrap.innerHTML='';
  if(!j.reports.length){wrap.innerHTML='<p class="hint">No on-demand reports configured. Add one in the Reports tab and save.</p>';return;}
  j.reports.forEach(rp=>{
    const el=document.createElement('div'); el.className='run-item';
    el.innerHTML=`<div class="meta"><div class="lbl">${esc(rp.label)}
        <span class="pill ${rp.enabled?'':'off'}">${rp.enabled?rp.format:'disabled'}</span></div>
      <div class="sub">${esc(rp.id)}</div></div>
      ${rp.send_as_pdf?'<span class="pill" style="color:var(--accent);border-color:var(--accent);font-size:10px">→ PDF</span>':''}
      <button class="btn sm" ${rp.enabled?'':'disabled'} onclick="runReport('${esc(rp.id)}',false)">▶ Run</button>`;
    wrap.appendChild(el);
  });
}
function clearConsole(){document.getElementById('console').innerHTML='Idle.';}
function appendLine(line){
  const c=document.getElementById('console');
  let cls='';
  if(/\[ERROR\]|ERROR|✗|Traceback/.test(line)) cls='e';
  else if(/\[WARNING\]|WARN|⚠/.test(line)) cls='w';
  else if(/✓|succeeded|Done\./.test(line)) cls='ok';
  else if(line.startsWith('$ ')) cls='cmd';
  const span=document.createElement('span'); if(cls) span.className=cls;
  span.textContent=line+'\n'; c.appendChild(span); c.scrollTop=c.scrollHeight;
}
function runReport(id, all){
  if(evtSource){evtSource.close(); evtSource=null;}
  const c=document.getElementById('console'); c.innerHTML='';
  const st=document.getElementById('runStatus'); st.textContent='running…'; st.className='badge example';
  const q=new URLSearchParams();
  if(all) q.set('all','1'); else q.set('id',id);
  if(isChk('opt_dry')) q.set('dry_run','1');
  if(isChk('opt_verbose')) q.set('verbose','1');
  evtSource=new EventSource('/api/run?'+q.toString());
  evtSource.onmessage=(e)=>{
    if(e.data.startsWith('__DONE__:')){
      const rc=e.data.split(':')[1];
      st.textContent=rc==='0'?'completed ✓':'exit '+rc; st.className='badge '+(rc==='0'?'live':'example');
      evtSource.close(); evtSource=null; return;
    }
    appendLine(e.data);
  };
  evtSource.onerror=()=>{ if(evtSource){st.textContent='stream error'; st.className='badge example'; evtSource.close(); evtSource=null;} };
}

function num(v,dflt){const n=parseInt(v,10); return isNaN(n)?dflt:n;}
function esc(s){return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
  .replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

reload();
</script>
</body>
</html>"""


def main():
    global CONFIG_PATH, AUTH_USER, AUTH_PASS
    ap = argparse.ArgumentParser(description="Wazuh reporting — local config & run GUI")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address. Use 0.0.0.0 to reach it from outside the VM.")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--config", default=str(LIVE_CONFIG),
                    help="Path to live config (default: <repo>/config/reports.conf.yaml)")
    ap.add_argument("--auth", metavar="USER:PASS",
                    help="Enable HTTP Basic Auth (or set WAZUH_GUI_AUTH env var). "
                         "Strongly recommended when --host is not 127.0.0.1.")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    CONFIG_PATH = Path(args.config).resolve()

    auth = args.auth or os.environ.get("WAZUH_GUI_AUTH")
    if auth:
        if ":" not in auth:
            sys.exit("--auth must be in the form USER:PASS")
        AUTH_USER, AUTH_PASS = auth.split(":", 1)

    exposed = args.host not in ("127.0.0.1", "localhost")

    print("Wazuh Reporting GUI")
    print(f"  project root : {PROJECT_ROOT}")
    print(f"  config file  : {CONFIG_PATH}"
          f"{'  (will be created on first save)' if not CONFIG_PATH.exists() else ''}")
    print(f"  runner       : {RUNNER}{'  [NOT FOUND]' if not RUNNER.exists() else ''}")
    print(f"  bind         : {args.host}:{args.port}")
    print(f"  basic auth   : {'ON (user: ' + AUTH_USER + ')' if AUTH_USER else 'OFF'}")
    if exposed and not AUTH_USER:
        print("\n  WARNING: bound to a network interface with NO authentication.")
        print("    This page exposes dashboard & SMTP passwords. Add --auth USER:PASS")
        print("    or restrict access with a firewall / reverse proxy.")
    if exposed:
        print(f"\n  From outside the VM, open  http://<VM-IP>:{args.port}")
    else:
        print(f"\n  Open  http://{args.host}:{args.port}  in your browser.")
    print("  Ctrl+C to stop.\n")

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)


if __name__ == "__main__":
    main()
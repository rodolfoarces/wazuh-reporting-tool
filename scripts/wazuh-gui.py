#!/usr/bin/env python3
"""
wazuh-gui.py
============
Read-only run GUI for the Wazuh reporting tool.

Exposes only the "Run reports" section. It reads the existing YAML
configuration file but never modifies it. Use wazuh_gui2.py for full
configuration management.

Place this file in the repo's scripts/ directory and run:

    pip3 install flask pyyaml
    python3 scripts/wazuh-gui.py

Then open http://127.0.0.1:5001 in your browser.

Options:
    --host 127.0.0.1       Bind address (use 0.0.0.0 to reach from outside a VM)
    --port 5001            Port (default: 5001, avoids conflict with wazuh_gui2.py)
    --config PATH          Config file (default: <repo>/config/reports.conf.yaml)
    --auth USER:PASS       Enable HTTP Basic Auth (or set WAZUH_RUN_GUI_AUTH env var)
    --auth-file PATH       File containing USER:PASS on its first line
    --ssl-cert PATH        PEM certificate file to enable HTTPS (or set WAZUH_RUN_GUI_SSL_CERT)
    --ssl-key  PATH        PEM private key file to enable HTTPS (or set WAZUH_RUN_GUI_SSL_KEY)

Both --ssl-cert and --ssl-key must be provided together to activate HTTPS.

SECURITY NOTE: this UI can trigger report generation which contacts external
systems. Set --auth and consider HTTPS when binding to 0.0.0.0.
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
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

SCRIPT_DIR     = Path(__file__).resolve().parent
PROJECT_ROOT   = SCRIPT_DIR.parent
CONFIG_DIR     = PROJECT_ROOT / "config"
LIVE_CONFIG    = CONFIG_DIR / "reports.conf.yaml"
EXAMPLE_CONFIG = CONFIG_DIR / "reports.conf.example.yaml"
RUNNER         = SCRIPT_DIR / "wazuh_report_runner.py"
LOGS_DIR       = PROJECT_ROOT / "logs"

# Log file written to LOGS_DIR - change this variable to redirect the server log.
LOG_FILE_NAME = "wazuh-run-gui.log"

# Overridden by --config at startup.
CONFIG_PATH = LIVE_CONFIG

# Set to True by --debug.
DEBUG = False

# Auth credentials - set at startup.
AUTH_USER = None
AUTH_PASS = None

app = Flask(__name__)


# -- Logging -------------------------------------------------------------------

def _setup_logging(debug: bool) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if debug else logging.INFO
    fmt   = "%(asctime)s  %(levelname)-8s  %(message)s"
    logging.basicConfig(
        level=level,
        format=fmt,
        handlers=[
            logging.FileHandler(LOGS_DIR / LOG_FILE_NAME, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


# -- HTTP Basic Auth -----------------------------------------------------------

@app.before_request
def _require_auth():
    if AUTH_USER is None:
        return None
    import hmac
    a = request.authorization
    ok = (a and a.username is not None and a.password is not None
          and hmac.compare_digest(a.username, AUTH_USER)
          and hmac.compare_digest(a.password, AUTH_PASS))
    if not ok:
        return Response("Authentication required.", 401,
                        {"WWW-Authenticate": 'Basic realm="Wazuh Reporting - Run"'})
    return None


# -- Config helpers (read-only) ------------------------------------------------

def load_config():
    path = CONFIG_PATH if CONFIG_PATH.exists() else EXAMPLE_CONFIG
    if not path.exists():
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def on_demand_reports(cfg):
    out = []
    for r in cfg.get("reports", []) or []:
        if r.get("scheduled", False):
            continue
        out.append({
            "id":          r.get("id", ""),
            "label":       r.get("label", r.get("id", "")),
            "enabled":     r.get("enabled", True),
            "format":      r.get("format", "xlsx"),
            "send_as_pdf": r.get("send_as_pdf", False),
        })
    return out


# -- Routes --------------------------------------------------------------------

@app.get("/api/reports")
def api_reports():
    cfg = load_config()
    return jsonify({"reports": on_demand_reports(cfg)})


@app.get("/api/run")
def api_run():
    report_id = request.args.get("id", "")
    run_all   = request.args.get("all") == "1"
    dry_run   = request.args.get("dry_run") == "1"
    verbose   = request.args.get("verbose") == "1"

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

    label = "ALL" if run_all else report_id
    logging.info("Run requested: %s  dry_run=%s  verbose=%s", label, dry_run, verbose)

    def generate():
        yield _sse(("$ " + " ".join(cmd) if DEBUG else "Starting report execution...") + "\n\n")
        try:
            proc = subprocess.Popen(
                cmd, cwd=str(PROJECT_ROOT),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
        except Exception as exc:  # noqa: BLE001
            logging.error("Failed to launch runner: %s", exc)
            yield _sse(f"ERROR launching runner: {exc}\n")
            yield _sse("__DONE__:1")
            return
        for line in iter(proc.stdout.readline, ""):
            yield _sse(line.rstrip("\n"))
        proc.stdout.close()
        rc = proc.wait()
        logging.info("Runner finished: %s  rc=%d", label, rc)
        yield _sse(f"\n--- runner exited with code {rc} ---")
        yield _sse(f"__DONE__:{rc}")

    return Response(generate(), mimetype="text/event-stream")


def _sse(text):
    return "".join(f"data: {ln}\n" for ln in text.split("\n")) + "\n"


@app.get("/")
def index():
    return render_template_string(PAGE)


# -- Page HTML -----------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Wazuh Reporting - Run</title>
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
         padding:14px 22px;display:flex;align-items:center;gap:14px;
         position:sticky;top:0;z-index:10}
  header h1{font-size:17px;margin:0;font-weight:600}
  .badge{font-size:11px;padding:2px 8px;border-radius:999px;border:1px solid var(--line)}
  .badge.live{color:var(--ok);border-color:var(--ok)}
  .badge.example{color:var(--warn);border-color:var(--warn)}
  main{padding:22px 28px;max-width:920px;margin:0 auto}
  h2{font-size:15px;margin:0 0 4px;font-weight:600}
  .hint{color:var(--muted);font-size:12px;margin:0 0 18px}
  button.btn{background:var(--accent);color:#fff;border:none;padding:9px 16px;
        border-radius:6px;cursor:pointer;font-size:13px;font-weight:500}
  button.btn:hover{background:var(--accent2)}
  button.btn.ghost{background:transparent;border:1px solid var(--line);color:var(--txt)}
  button.btn.ghost:hover{border-color:var(--accent)}
  button.btn.sm{padding:5px 10px;font-size:12px}
  button.btn:disabled{opacity:.4;cursor:not-allowed}
  .toolbar{display:flex;gap:10px;align-items:center;margin-bottom:16px;flex-wrap:wrap}
  .row-check{display:flex;align-items:center;gap:8px}
  .row-check input{width:auto}
  .run-list{display:flex;flex-direction:column;gap:8px;margin-bottom:16px}
  .run-item{display:flex;align-items:center;gap:12px;background:var(--panel2);
        border:1px solid var(--line);border-radius:6px;padding:10px 14px}
  .run-item .meta{flex:1}
  .run-item .meta .lbl{font-weight:500}
  .run-item .meta .sub{color:var(--muted);font-size:12px;font-family:ui-monospace,monospace}
  .pill{font-size:10px;padding:1px 7px;border-radius:999px;border:1px solid var(--line);
        color:var(--muted)}
  .pill.off{color:var(--err);border-color:var(--err)}
  .console{background:#05080b;border:1px solid var(--line);border-radius:var(--radius);
        padding:14px;font-family:ui-monospace,monospace;font-size:12px;white-space:pre-wrap;
        height:400px;overflow:auto;color:#c5d1dc}
  .console .e{color:var(--err)} .console .w{color:var(--warn)}
  .console .ok{color:var(--ok)} .console .cmd{color:var(--accent)}
  code{background:var(--panel2);padding:1px 5px;border-radius:4px;font-size:12px}
</style>
</head>
<body>
<header>
  <h1>Wazuh Reporting - Run</h1>
  <span id="statusBadge" class="badge">loading...</span>
</header>

<main>
  <h2>Run reports on demand</h2>
  <p class="hint">Runs <code>wazuh_report_runner.py</code> against the saved configuration.
    Only enabled, non-scheduled reports appear here.</p>

  <div class="toolbar">
    <button class="btn" onclick="runReport('', true)">Run ALL enabled</button>
    <label class="row-check"><input type="checkbox" id="opt_dry">
      <span style="color:var(--txt)">Dry-run (no API call, no email)</span></label>
    <label class="row-check"><input type="checkbox" id="opt_verbose">
      <span style="color:var(--txt)">Verbose</span></label>
  </div>

  <div id="runList" class="run-list"></div>

  <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
    <strong style="font-size:13px">Output</strong>
    <button class="btn ghost sm" onclick="clearConsole()">Clear</button>
    <span id="runStatus" class="badge"></span>
  </div>
  <div id="console" class="console">Idle. Select a report above to run it.</div>
</main>

<script>
let evtSource = null;

async function loadReports(){
  let j;
  try { const r = await fetch('/api/reports'); j = await r.json(); }
  catch(e){ setBadge('error','example'); return; }

  const wrap = document.getElementById('runList');
  wrap.innerHTML = '';

  if(!j.reports || !j.reports.length){
    setBadge('no reports','example');
    wrap.innerHTML='<p style="color:var(--muted);font-size:12px">No on-demand reports found in the configuration.</p>';
    return;
  }
  setBadge(j.reports.length+' report'+(j.reports.length===1?'':'s'),'live');

  j.reports.forEach(rp=>{
    const el=document.createElement('div'); el.className='run-item';
    el.innerHTML=`
      <div class="meta">
        <div class="lbl">${esc(rp.label)}
          <span class="pill ${rp.enabled?'':'off'}">${rp.enabled?rp.format:'disabled'}</span>
        </div>
        <div class="sub">${esc(rp.id)}</div>
      </div>
      ${rp.send_as_pdf?'<span class="pill" style="color:var(--accent);border-color:var(--accent);font-size:10px">PDF</span>':''}
      <button class="btn sm" ${rp.enabled?'':'disabled'}
        onclick="runReport('${esc(rp.id)}',false)">Run</button>`;
    wrap.appendChild(el);
  });
}

function setBadge(text, kind){
  const b=document.getElementById('statusBadge');
  b.textContent=text; b.className='badge '+(kind||'');
}

function clearConsole(){ document.getElementById('console').innerHTML='Idle.'; }

function appendLine(line){
  const c=document.getElementById('console');
  let cls='';
  if(/\[ERROR\]|ERROR|FAILED|Traceback/.test(line)) cls='e';
  else if(/\[WARNING\]|WARN/.test(line))            cls='w';
  else if(/succeeded|Done\./.test(line))            cls='ok';
  else if(line.startsWith('$ '))               cls='cmd';
  const span=document.createElement('span'); if(cls) span.className=cls;
  span.textContent=line+'\n'; c.appendChild(span); c.scrollTop=c.scrollHeight;
}

function runReport(id, all){
  if(evtSource){ evtSource.close(); evtSource=null; }
  document.getElementById('console').innerHTML='';
  const st=document.getElementById('runStatus');
  st.textContent='running...'; st.className='badge example';

  const q=new URLSearchParams();
  if(all) q.set('all','1'); else q.set('id',id);
  if(document.getElementById('opt_dry').checked)     q.set('dry_run','1');
  if(document.getElementById('opt_verbose').checked) q.set('verbose','1');

  evtSource=new EventSource('/api/run?'+q.toString());
  evtSource.onmessage=e=>{
    if(e.data.startsWith('__DONE__:')){
      const rc=e.data.split(':')[1];
      st.textContent=rc==='0'?'completed':'exit '+rc;
      st.className='badge '+(rc==='0'?'live':'example');
      evtSource.close(); evtSource=null; return;
    }
    appendLine(e.data);
  };
  evtSource.onerror=()=>{
    if(evtSource){ st.textContent='stream error'; st.className='badge example';
      evtSource.close(); evtSource=null; }
  };
}

function esc(s){
  return String(s??'').replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

loadReports();
</script>
</body>
</html>"""


# -- Entry point ---------------------------------------------------------------

def main():
    global CONFIG_PATH, AUTH_USER, AUTH_PASS, DEBUG
    ap = argparse.ArgumentParser(description="Wazuh reporting - run-only GUI")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Bind address. Use 0.0.0.0 to reach from outside the VM.")
    ap.add_argument("--port", type=int, default=5001,
                    help="Port (default: 5001).")
    ap.add_argument("--config", default=str(LIVE_CONFIG),
                    help="Path to the config file (default: <repo>/config/reports.conf.yaml)")
    ap.add_argument("--auth", metavar="USER:PASS",
                    help="Enable HTTP Basic Auth (or set WAZUH_RUN_GUI_AUTH env var).")
    ap.add_argument("--auth-file", metavar="PATH",
                    help="File containing USER:PASS on its first line.")
    ap.add_argument("--ssl-cert", metavar="PATH",
                    help="PEM certificate file to enable HTTPS (or set WAZUH_RUN_GUI_SSL_CERT).")
    ap.add_argument("--ssl-key", metavar="PATH",
                    help="PEM private key file to enable HTTPS (or set WAZUH_RUN_GUI_SSL_KEY).")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    CONFIG_PATH = Path(args.config).resolve()
    DEBUG = args.debug

    _setup_logging(DEBUG)

    # Credential resolution order: --auth-file < env var < --auth (highest priority).
    auth = args.auth or os.environ.get("WAZUH_RUN_GUI_AUTH")
    if not auth and getattr(args, "auth_file", None):
        try:
            first_line = Path(args.auth_file).read_text(encoding="utf-8").splitlines()[0].strip()
            auth = first_line
        except Exception as exc:
            sys.exit(f"Cannot read --auth-file: {exc}")
    if auth:
        if ":" not in auth:
            sys.exit("Auth credentials must be in the form USER:PASS")
        AUTH_USER, AUTH_PASS = auth.split(":", 1)

    ssl_cert = getattr(args, "ssl_cert", None) or os.environ.get("WAZUH_RUN_GUI_SSL_CERT")
    ssl_key  = getattr(args, "ssl_key",  None) or os.environ.get("WAZUH_RUN_GUI_SSL_KEY")
    if bool(ssl_cert) != bool(ssl_key):
        sys.exit("Both --ssl-cert and --ssl-key must be provided together to enable HTTPS.")
    ssl_context = (ssl_cert, ssl_key) if ssl_cert else None
    scheme = "https" if ssl_context else "http"

    exposed = args.host not in ("127.0.0.1", "localhost")

    logging.info("Wazuh Reporting Run GUI starting")
    logging.info("  config : %s", CONFIG_PATH)
    logging.info("  runner : %s%s", RUNNER, "  [NOT FOUND]" if not RUNNER.exists() else "")
    logging.info("  bind   : %s:%d", args.host, args.port)
    logging.info("  auth   : %s", f"ON (user: {AUTH_USER})" if AUTH_USER else "OFF")
    logging.info("  ssl    : %s", f"ON (cert: {ssl_cert})" if ssl_context else "OFF")

    print("Wazuh Reporting Run GUI")
    print(f"  config file  : {CONFIG_PATH}"
          f"{'  (not found - check path)' if not CONFIG_PATH.exists() else ''}")
    print(f"  runner       : {RUNNER}{'  [NOT FOUND]' if not RUNNER.exists() else ''}")
    print(f"  bind         : {args.host}:{args.port}")
    print(f"  basic auth   : {'ON (user: ' + AUTH_USER + ')' if AUTH_USER else 'OFF'}")
    print(f"  SSL/HTTPS    : {'ON (cert: ' + ssl_cert + ')' if ssl_context else 'OFF'}")
    print(f"  log file     : {LOGS_DIR / LOG_FILE_NAME}")
    if exposed and not AUTH_USER:
        print("\n  WARNING: bound to a network interface with NO authentication.")
        print("    Running reports contacts external systems. Add --auth USER:PASS")
        print("    or restrict access with a firewall / reverse proxy.")
    if exposed:
        print(f"\n  From outside the VM, open  {scheme}://<VM-IP>:{args.port}")
    else:
        print(f"\n  Open  {scheme}://{args.host}:{args.port}  in your browser.")
    print("  Ctrl+C to stop.\n")

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True,
            ssl_context=ssl_context)


if __name__ == "__main__":
    main()

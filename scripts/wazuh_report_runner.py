#!/usr/bin/env python3
"""
wazuh_report_runner.py
======================
On-demand report executor for Wazuh / OpenSearch Dashboards.

Reads all configuration (connection, SMTP, recipients, report definitions)
from the YAML config file. No report logic lives here — add or change reports
by editing config/reports.conf.yaml only.

Authentication
--------------
Cookie-based session via auth.py. One POST /auth/login call produces a
security_authentication cookie; the session object carries it for all
subsequent API calls.

API flow (on-demand)
--------------------
A single synchronous POST generates and returns the report immediately:

  POST /api/reporting/generateReport/<report_def_id>
       ?timezone=...&dateFormat=...&csvSeparator=...&allowLeadingWildcards=true
  Body: empty
  → { "data": "data:<mime>;base64,<content>", "filename": "<name>" }

There is no polling step. The connection blocks until generation completes
and the full file is returned inline as a base64 data-URI.

Usage
-----
  python3 scripts/wazuh_report_runner.py --report critical_alerts_daily
  python3 scripts/wazuh_report_runner.py --report critical_alerts_daily failed_logins_weekly
  python3 scripts/wazuh_report_runner.py --all
  python3 scripts/wazuh_report_runner.py --all --filter compliance
  python3 scripts/wazuh_report_runner.py --all --config /etc/wazuh-reports/reports.conf.yaml
  python3 scripts/wazuh_report_runner.py --all --dry-run

Environment variable overrides:
  WAZUH_DASH_PASS   Dashboard password
  WAZUH_SMTP_PASS   SMTP password
"""

from __future__ import annotations

import argparse
import logging
import os
import smtplib
import sys
from datetime import date, datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests
import urllib3
import yaml

from auth import generate_report, get_dashboard_session
from pdf_converter import convert_to_pdf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH_DEFAULT = Path(__file__).resolve().parent.parent / "config" / "reports.conf.yaml"


# ── Config ────────────────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = yaml.safe_load(f)
    if os.environ.get("WAZUH_DASH_PASS"):
        cfg["dashboard"]["password"] = os.environ["WAZUH_DASH_PASS"]
    if os.environ.get("WAZUH_SMTP_PASS"):
        cfg["smtp"]["password"] = os.environ["WAZUH_SMTP_PASS"]
    return cfg


def resolve_recipients(report: dict, recipient_groups: dict) -> list[str]:
    """Expand group names and raw addresses into a flat, deduplicated list."""
    emails = []
    for entry in report.get("recipients", []):
        if entry in recipient_groups:
            emails.extend(recipient_groups[entry])
        elif "@" in entry:
            emails.append(entry)
        else:
            logging.warning(
                f"Unknown recipient entry '{entry}' in report '{report['id']}' — skipping."
            )
    seen: set = set()
    return [e for e in emails if not (e in seen or seen.add(e))]


# ── Email ─────────────────────────────────────────────────────────────────────

def render_template(template: str, report: dict, extra: dict | None = None) -> str:
    now = datetime.now()
    ctx = {
        "date":         date.today().isoformat(),
        "timestamp":    now.strftime("%Y-%m-%d %H:%M:%S"),
        "month":        now.strftime("%B"),
        "year":         now.year,
        "report_label": report.get("label", report["id"]),
    }
    if extra:
        ctx.update(extra)
    return template.format(**ctx)


def send_email(
    smtp_cfg: dict,
    recipients: list[str],
    subject: str,
    body: str,
    attachment_path: Path,
    attachment_name: str | None = None,
    dry_run: bool = False,
) -> None:
    attach_name = attachment_name or attachment_path.name
    msg = MIMEMultipart()
    msg["From"] = f"{smtp_cfg.get('from_name', 'Wazuh Reports')} <{smtp_cfg['from_address']}>"
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with open(attachment_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{attach_name}"')
    msg.attach(part)

    if dry_run:
        logging.info(f"  [DRY-RUN] Would send '{subject}' → {recipients}")
        return

    with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"]) as server:
        if smtp_cfg.get("use_tls", True):
            server.starttls()
        server.login(smtp_cfg["username"], smtp_cfg["password"])
        server.sendmail(smtp_cfg["from_address"], recipients, msg.as_string())
    logging.info(f"  ✓ Email sent: '{subject}' → {recipients}")


# ── Core runner ───────────────────────────────────────────────────────────────

def run_report(
    report: dict,
    cfg: dict,
    session: requests.Session,
    dry_run: bool = False,
) -> bool:
    """Execute a single on-demand report: POST generate → save → email."""
    rid = report["id"]
    output_dir = Path(cfg.get("storage", {}).get("output_dir", "logs/downloads"))

    logging.info(f"[{rid}] ── Starting: {report['label']}")

    recipients = resolve_recipients(report, cfg.get("recipient_groups", {}))
    if not recipients:
        logging.warning(f"[{rid}] No recipients resolved — skipping.")
        return False

    now = datetime.now()
    local_filename = f"{rid}_{now.strftime('%Y%m%d_%H%M%S')}.{report.get('format', 'xlsx')}"
    output_path = output_dir / local_filename

    try:
        if not dry_run:
            fmt = report.get("format", "xlsx")
            logging.info(f"[{rid}] Generating ({fmt}): {report['report_def_id']}")
            api_filename = generate_report(
                session, cfg["dashboard"], report["report_def_id"],
                output_path, report_format=fmt
            )
            logging.info(f"[{rid}] ✓ Saved → {output_path}  ({api_filename})")

            # Optional: convert XLSX/CSV to PDF before emailing
            if report.get("send_as_pdf") and fmt in ("xlsx", "csv"):
                pdf_path = output_path.with_suffix(".pdf")
                convert_to_pdf(
                    input_path=output_path,
                    output_path=pdf_path,
                    title=report.get("label", rid),
                    subtitle=cfg.get("dashboard", {}).get("url", ""),
                    report_date=now.strftime("%Y-%m-%d %H:%M:%S"),
                )
                output_path = pdf_path
                api_filename = pdf_path.name
                logging.info(f"[{rid}] ✓ Converted to PDF → {pdf_path.name}")
        else:
            api_filename = f"{rid}_dry-run.xlsx"
            output_path = Path("/tmp/dry-run-placeholder.xlsx")
            output_path.touch()
            logging.info(f"[{rid}] [DRY-RUN] Skipping API call.")

        subject = render_template(
            report.get("email_subject", "Wazuh Report: {report_label} — {date}"), report
        )
        body = render_template(
            report.get("email_body",
                "Wazuh report '{report_label}' attached.\n\nGenerated: {timestamp}\n"),
            report,
        )
        logging.info(f"[{rid}] Sending to {len(recipients)} recipient(s)...")
        send_email(cfg["smtp"], recipients, subject, body, output_path,
                   attachment_name=api_filename, dry_run=dry_run)

        logging.info(f"[{rid}] ✓ Done.")
        return True

    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response else "?"
        body   = exc.response.text[:200] if exc.response else str(exc)
        logging.error(f"[{rid}] HTTP {status}: {body}")
        if status == 404:
            logging.error(
                f"[{rid}] 404 suggests the report_def_id is wrong or the report "
                f"definition was deleted.\n"
                f"  Configured ID : {report['report_def_id']}\n"
                f"  To find the correct ID: Wazuh Dashboard → Reporting → "
                f"Report Definitions → Edit → copy ID from URL"
            )
    except Exception as exc:
        logging.error(f"[{rid}] Unexpected error: {exc}", exc_info=True)
    return False


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wazuh On-Demand Report Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", default=str(CONFIG_PATH_DEFAULT), metavar="PATH")
    parser.add_argument("--report", nargs="+", metavar="ID")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--filter", metavar="KEYWORD")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    cfg = load_config(args.config)
    log_cfg = cfg.get("logging", {})
    log_file = Path(log_cfg.get("log_file", "logs/report-runner.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Force UTF-8 on both handlers so Unicode log characters (✓ ✗ ── ⚠ →)
    # don't crash on Windows consoles that default to cp1252.
    _stream_handler = logging.StreamHandler(sys.stdout)
    _stream_handler.stream = open(sys.stdout.fileno(), mode="w",
                                  encoding="utf-8", buffering=1,
                                  closefd=False)
    _file_handler = logging.FileHandler(log_file, encoding="utf-8")
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else getattr(logging, log_cfg.get("level", "INFO")),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[_stream_handler, _file_handler],
    )

    eligible = [r for r in cfg.get("reports", [])
                if r.get("enabled", True) and not r.get("scheduled", False)]

    if args.report:
        wanted = set(args.report)
        targets = [r for r in eligible if r["id"] in wanted]
        missing = wanted - {r["id"] for r in targets}
        if missing:
            logging.warning(f"Report ID(s) not found or not on-demand eligible: {missing}")
    elif args.all:
        targets = eligible
        if args.filter:
            targets = [r for r in targets if args.filter.lower() in r["id"].lower()]
        logging.info(f"Running {len(targets)} report(s) (filter: '{args.filter or 'none'}').")
    else:
        parser.print_help()
        sys.exit(0)

    if not targets:
        logging.error("No matching reports found.")
        sys.exit(1)

    session = get_dashboard_session(cfg["dashboard"]) if not args.dry_run else requests.Session()

    results = {r["id"]: run_report(r, cfg, session, dry_run=args.dry_run) for r in targets}

    ok   = [rid for rid, ok in results.items() if ok]
    fail = [rid for rid, ok in results.items() if not ok]
    logging.info(f"\n{'=' * 60}")
    logging.info(f"Run complete — {len(ok)} succeeded, {len(fail)} failed")
    for rid in ok:   logging.info(f"  ✓ {rid}")
    for rid in fail: logging.error(f"  ✗ {rid}")
    sys.exit(0 if not fail else 1)


if __name__ == "__main__":
    main()

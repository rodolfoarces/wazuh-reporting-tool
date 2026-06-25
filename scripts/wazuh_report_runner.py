#!/usr/bin/env python3
"""
wazuh_report_runner.py
======================
On-demand report executor for Wazuh / OpenSearch Dashboards.

Reads all configuration (connection, SMTP, recipients, report definitions)
from the YAML config file. No report logic lives here — add or change reports
by editing config/reports.conf.yaml only.

Usage
-----
  # Run a single report by ID
  python3 scripts/wazuh_report_runner.py --report critical_alerts_daily

  # Run several reports in one pass
  python3 scripts/wazuh_report_runner.py --report critical_alerts_daily failed_logins_weekly

  # Run ALL enabled, non-scheduled reports
  python3 scripts/wazuh_report_runner.py --all

  # Run all enabled reports whose ID contains a keyword
  python3 scripts/wazuh_report_runner.py --all --filter compliance

  # Use a non-default config path
  python3 scripts/wazuh_report_runner.py --all --config /etc/wazuh-reports/reports.conf.yaml

  # Dry-run: log what would happen without calling any API or sending email
  python3 scripts/wazuh_report_runner.py --all --dry-run

Environment variable overrides (take precedence over the config file):
  WAZUH_DASH_PASS   Dashboard password
  WAZUH_SMTP_PASS   SMTP password
"""

import argparse
import logging
import os
import smtplib
import sys
import time
from datetime import date, datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Default config path: <project_root>/config/reports.conf.yaml
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
            logging.warning(f"Unknown recipient entry '{entry}' in report '{report['id']}' — skipping.")
    seen: set = set()
    return [e for e in emails if not (e in seen or seen.add(e))]


# ── OpenSearch Dashboards Reporting API ───────────────────────────────────────

def trigger_report(dashboard_cfg: dict, report_def_id: str) -> str:
    """POST to generate a report job; returns the job_id string."""
    url = f"{dashboard_cfg['url']}/api/reporting/generateReport"
    resp = requests.post(
        url,
        json={"report_definition_id": report_def_id},
        auth=(dashboard_cfg["username"], dashboard_cfg["password"]),
        headers={"osd-xsrf": "true"},
        verify=dashboard_cfg.get("verify_ssl", False),
        timeout=dashboard_cfg.get("timeout_seconds", 30),
    )
    resp.raise_for_status()
    body = resp.json()
    job_id = body.get("job_id") or body.get("data", {}).get("_id")
    if not job_id:
        raise ValueError(f"No job_id in response: {resp.text}")
    return job_id


def wait_for_report(dashboard_cfg: dict, job_id: str) -> bool:
    """Poll until the report job reaches a terminal state. Returns True on success."""
    url = f"{dashboard_cfg['url']}/api/reporting/jobs/status/{job_id}"
    interval = dashboard_cfg.get("poll_interval_seconds", 5)
    max_attempts = dashboard_cfg.get("poll_max_attempts", 24)

    for attempt in range(1, max_attempts + 1):
        time.sleep(interval)
        resp = requests.get(
            url,
            auth=(dashboard_cfg["username"], dashboard_cfg["password"]),
            verify=dashboard_cfg.get("verify_ssl", False),
            timeout=dashboard_cfg.get("timeout_seconds", 30),
        )
        resp.raise_for_status()
        body = resp.json()
        status = body.get("job_status") or body.get("data", {}).get("status")
        logging.debug(f"  Poll {attempt}/{max_attempts}: job {job_id} → {status}")

        if status == "completed":
            return True
        if status in ("failed", "error"):
            logging.error(f"  Job {job_id} ended with status: {status}")
            return False

    logging.error(f"  Job {job_id} did not complete after {max_attempts} polls.")
    return False


def download_report(dashboard_cfg: dict, job_id: str, output_path: Path) -> None:
    """Stream the finished report to disk."""
    url = f"{dashboard_cfg['url']}/api/reporting/jobs/download/{job_id}"
    resp = requests.get(
        url,
        auth=(dashboard_cfg["username"], dashboard_cfg["password"]),
        verify=dashboard_cfg.get("verify_ssl", False),
        timeout=dashboard_cfg.get("timeout_seconds", 30),
        stream=True,
    )
    resp.raise_for_status()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)


# ── Email ─────────────────────────────────────────────────────────────────────

def render_template(template: str, report: dict, extra: dict | None = None) -> str:
    """Fill date/time/report placeholders in a subject or body template."""
    now = datetime.now()
    ctx = {
        "date": date.today().isoformat(),
        "timestamp": now.strftime("%Y-%m-%d %H:%M:%S"),
        "month": now.strftime("%B"),
        "year": now.year,
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
    dry_run: bool = False,
) -> None:
    msg = MIMEMultipart()
    msg["From"] = f"{smtp_cfg.get('from_name', 'Wazuh Reports')} <{smtp_cfg['from_address']}>"
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with open(attachment_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{attachment_path.name}"')
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

def run_report(report: dict, cfg: dict, dry_run: bool = False) -> bool:
    """Execute a single on-demand report: trigger → poll → download → email."""
    rid = report["id"]
    dashboard_cfg = cfg["dashboard"]
    smtp_cfg = cfg["smtp"]
    output_dir = Path(cfg.get("storage", {}).get("output_dir", "logs/downloads"))

    logging.info(f"[{rid}] ── Starting: {report['label']}")

    recipients = resolve_recipients(report, cfg.get("recipient_groups", {}))
    if not recipients:
        logging.warning(f"[{rid}] No recipients resolved — skipping.")
        return False

    now = datetime.now()
    filename = f"{rid}_{now.strftime('%Y%m%d_%H%M%S')}.{report.get('format', 'xlsx')}"
    output_path = output_dir / filename

    try:
        # 1. Trigger
        if not dry_run:
            logging.info(f"[{rid}] Triggering report definition: {report['report_def_id']}")
            job_id = trigger_report(dashboard_cfg, report["report_def_id"])
            logging.info(f"[{rid}] Job ID: {job_id}")
        else:
            job_id = "dry-run-job-000"
            logging.info(f"[{rid}] [DRY-RUN] Skipping API trigger.")

        # 2. Poll
        if not dry_run:
            logging.info(f"[{rid}] Waiting for job to complete...")
            if not wait_for_report(dashboard_cfg, job_id):
                logging.error(f"[{rid}] Report generation failed — aborting.")
                return False

        # 3. Download
        if not dry_run:
            logging.info(f"[{rid}] Downloading → {output_path}")
            download_report(dashboard_cfg, job_id, output_path)
        else:
            output_path = Path("/tmp/dry-run-placeholder.xlsx")
            output_path.touch()

        # 4. Email
        subject = render_template(
            report.get("email_subject", "Wazuh Report: {report_label} — {date}"), report
        )
        body = render_template(
            report.get("email_body", "Wazuh report '{report_label}' attached.\n\nGenerated: {timestamp}\n"),
            report,
        )
        logging.info(f"[{rid}] Sending to {len(recipients)} recipient(s)…")
        send_email(smtp_cfg, recipients, subject, body, output_path, dry_run=dry_run)

        logging.info(f"[{rid}] ✓ Done.")
        return True

    except requests.HTTPError as exc:
        logging.error(f"[{rid}] HTTP error: {exc} — {exc.response.text if exc.response else 'N/A'}")
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
    parser.add_argument("--config", default=str(CONFIG_PATH_DEFAULT), metavar="PATH",
                        help="Path to reports.conf.yaml (default: config/reports.conf.yaml)")
    parser.add_argument("--report", nargs="+", metavar="ID",
                        help="Run one or more specific report IDs")
    parser.add_argument("--all", action="store_true",
                        help="Run all enabled, non-scheduled reports")
    parser.add_argument("--filter", metavar="KEYWORD",
                        help="Limit --all to report IDs containing KEYWORD")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate without API calls or emails")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable DEBUG logging")
    args = parser.parse_args()

    cfg = load_config(args.config)
    log_cfg = cfg.get("logging", {})
    log_file = Path(log_cfg.get("log_file", "logs/report-runner.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else getattr(logging, log_cfg.get("level", "INFO")),
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file),
        ],
    )

    # Only on-demand (non-scheduled), enabled reports
    eligible = [r for r in cfg.get("reports", [])
                if r.get("enabled", True) and not r.get("scheduled", False)]

    if args.report:
        wanted = set(args.report)
        targets = [r for r in eligible if r["id"] in wanted]
        missing = wanted - {r["id"] for r in targets}
        if missing:
            logging.warning(f"Report ID(s) not found or not eligible for on-demand: {missing}")
    elif args.all:
        targets = eligible
        if args.filter:
            targets = [r for r in targets if args.filter.lower() in r["id"].lower()]
        logging.info(f"Running {len(targets)} report(s) (filter: '{args.filter or 'none'}').")
    else:
        parser.print_help()
        sys.exit(0)

    if not targets:
        logging.error("No matching reports found. Check --report IDs or --filter value.")
        sys.exit(1)

    results: dict[str, bool] = {}
    for report in targets:
        results[report["id"]] = run_report(report, cfg, dry_run=args.dry_run)

    ok = [rid for rid, success in results.items() if success]
    fail = [rid for rid, success in results.items() if not success]
    logging.info(f"\n{'='*60}")
    logging.info(f"Run complete — {len(ok)} succeeded, {len(fail)} failed")
    for rid in ok:
        logging.info(f"  ✓ {rid}")
    for rid in fail:
        logging.error(f"  ✗ {rid}")

    sys.exit(0 if not fail else 1)


if __name__ == "__main__":
    main()

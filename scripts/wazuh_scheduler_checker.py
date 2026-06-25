#!/usr/bin/env python3
"""
wazuh_scheduler_checker.py
==========================
Validates that Indexer-managed scheduled reports have been generated,
then downloads and emails them to their configured recipients.

This script does NOT trigger report generation. It assumes the OpenSearch
Dashboards Report Scheduler has already run and checks whether the resulting
job completed within the expected time window.

Run it via cron approximately 15 minutes after each scheduled report's
configured generation time to give the Indexer time to finish.

Authentication
--------------
Uses cookie-based session authentication via auth.py, matching the exact
flow the Wazuh Dashboard browser client uses:

  1. POST /auth/login  →  receives security_authentication session cookie
  2. All Reporting API calls (job list, download) use that session cookie

The session is established once and reused for all checks in a single run.

Usage
-----
  # Check all enabled scheduled reports
  python3 scripts/wazuh_scheduler_checker.py --all

  # Check a specific scheduled report by ID
  python3 scripts/wazuh_scheduler_checker.py --report scheduled_daily_overview

  # Dry-run: validate and log without downloading or sending email
  python3 scripts/wazuh_scheduler_checker.py --all --dry-run

  # Custom config path
  python3 scripts/wazuh_scheduler_checker.py --all --config /etc/wazuh-reports/reports.conf.yaml

Cron example — daily report scheduled at 06:00, checker runs at 06:15:
  15 6 * * * cd /opt/wazuh-reports && python3 scripts/wazuh_scheduler_checker.py --report scheduled_daily_overview >> logs/cron.log 2>&1

Environment variable overrides:
  WAZUH_DASH_PASS   Dashboard password
  WAZUH_SMTP_PASS   SMTP password
"""

import argparse
import logging
import os
import smtplib
import sys
from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests
import urllib3
import yaml

from auth import get_dashboard_session

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


# ── OpenSearch Dashboards Reporting API — job list ────────────────────────────

def list_recent_jobs(
    session: requests.Session,
    dashboard_cfg: dict,
    report_def_id: str,
    since: datetime,
) -> list[dict]:
    """
    Retrieve up to 50 recent jobs from the Dashboards reporting API and return
    those matching report_def_id that completed after `since`, newest first.

    API endpoint: GET /api/reporting/jobs/list?size=50
    Response shape:
      {"data": [{"_id": "...", "_source": {"report_definition_id": "...",
                                           "status": "completed",
                                           "last_updated_time": <epoch_ms>}}]}
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    url = f"{base_url}/api/reporting/jobs/list"

    resp = session.get(
        url,
        params={"size": 50},
        timeout=dashboard_cfg.get("timeout_seconds", 30),
    )
    resp.raise_for_status()

    matching = []
    for job in resp.json().get("data", []):
        src = job.get("_source", {})

        # Field name varies slightly between OpenSearch Dashboards versions
        job_def_id = (
            src.get("report_definition_id")
            or src.get("report_params", {}).get("report_definition_id")
        )
        if job_def_id != report_def_id:
            continue
        if src.get("status") != "completed":
            continue

        # Parse completion timestamp (ms epoch int or ISO string)
        raw_ts = src.get("last_updated_time") or src.get("last_updated")
        if raw_ts is None:
            continue
        if isinstance(raw_ts, (int, float)):
            completed_at = datetime.fromtimestamp(raw_ts / 1000, tz=timezone.utc)
        else:
            try:
                completed_at = datetime.fromisoformat(str(raw_ts).replace("Z", "+00:00"))
            except ValueError:
                logging.warning(
                    f"  Cannot parse timestamp '{raw_ts}' for job {job.get('_id')} — skipping."
                )
                continue

        if completed_at >= since:
            matching.append({
                "job_id":       job["_id"],
                "completed_at": completed_at,
                "status":       src.get("status"),
            })

    matching.sort(key=lambda j: j["completed_at"], reverse=True)
    return matching


def download_job(
    session: requests.Session,
    dashboard_cfg: dict,
    job_id: str,
    output_path: Path,
) -> None:
    base_url = dashboard_cfg["url"].rstrip("/")
    url = f"{base_url}/api/reporting/jobs/download/{job_id}"

    resp = session.get(
        url,
        timeout=dashboard_cfg.get("timeout_seconds", 30),
        stream=True,
    )
    resp.raise_for_status()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        for chunk in resp.iter_content(chunk_size=8192):
            f.write(chunk)


# ── Email ─────────────────────────────────────────────────────────────────────

def render_template(template: str, report: dict, job: dict) -> str:
    now = datetime.now()
    ctx = {
        "date":           now.date().isoformat(),
        "timestamp":      now.strftime("%Y-%m-%d %H:%M:%S"),
        "completed_at":   job["completed_at"].strftime("%Y-%m-%d %H:%M:%S UTC"),
        "month":          now.strftime("%B"),
        "year":           now.year,
        "report_label":   report.get("label", report["id"]),
        "schedule_label": report.get("schedule_label", "scheduled"),
        "job_id":         job["job_id"],
    }
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


def send_missing_alert(
    smtp_cfg: dict,
    recipients: list[str],
    report: dict,
    window_minutes: int,
    dry_run: bool,
) -> None:
    """Notify recipients that a scheduled report was NOT found within the window."""
    now = datetime.now()
    subject = f"⚠ Wazuh Report MISSING: {report['label']} — {now.date().isoformat()}"
    body = (
        f"WARNING: The scheduled Wazuh report was not found.\n\n"
        f"Report  : {report['label']} ({report['id']})\n"
        f"Schedule: {report.get('schedule_label', 'unknown')}\n"
        f"Window  : last {window_minutes} minutes\n"
        f"Checked : {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"Possible causes:\n"
        f"  • The OpenSearch Dashboards Report Scheduler did not run\n"
        f"  • The report job is still generating (consider increasing check_window_minutes)\n"
        f"  • The report_def_id in reports.conf.yaml does not match the Dashboards definition\n"
        f"  • The Wazuh Dashboard service is unavailable\n\n"
        f"Check: Wazuh Dashboard → Reporting → Job Queue\n\n"
        f"— Wazuh Report System"
    )

    if dry_run:
        logging.info(f"  [DRY-RUN] Would send missing-report alert → {recipients}")
        return

    msg = MIMEMultipart()
    msg["From"] = f"{smtp_cfg.get('from_name', 'Wazuh Reports')} <{smtp_cfg['from_address']}>"
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"]) as server:
        if smtp_cfg.get("use_tls", True):
            server.starttls()
        server.login(smtp_cfg["username"], smtp_cfg["password"])
        server.sendmail(smtp_cfg["from_address"], recipients, msg.as_string())
    logging.warning(f"  ⚠ Missing-report alert sent → {recipients}")


# ── Core checker ──────────────────────────────────────────────────────────────

OUTCOME_DELIVERED    = "delivered"
OUTCOME_ALREADY_SENT = "already_sent"
OUTCOME_NOT_FOUND    = "not_found"
OUTCOME_ERROR        = "error"


def check_scheduled_report(
    report: dict,
    cfg: dict,
    session: requests.Session,
    dry_run: bool = False,
) -> str:
    """
    Validate and deliver one scheduled report.

    Flow:
      1. Query job list for report_def_id within check_window_minutes
      2. Job found + not yet sent → download → email → write marker file
      3. Job found + marker exists → skip (idempotent)
      4. No job found → send missing-report alert to recipients

    Returns one of: "delivered" | "already_sent" | "not_found" | "error"
    """
    rid = report["id"]
    dashboard_cfg = cfg["dashboard"]
    smtp_cfg = cfg["smtp"]
    output_dir = Path(cfg.get("storage", {}).get("output_dir", "logs/downloads"))
    window_minutes = report.get("check_window_minutes", 90)
    since = datetime.now(tz=timezone.utc) - timedelta(minutes=window_minutes)

    logging.info(f"[{rid}] ── Checking: {report['label']}")
    logging.info(
        f"[{rid}] Window: last {window_minutes} min "
        f"(since {since.strftime('%Y-%m-%d %H:%M:%S UTC')})"
    )

    recipients = resolve_recipients(report, cfg.get("recipient_groups", {}))
    if not recipients:
        logging.warning(f"[{rid}] No recipients resolved — skipping.")
        return OUTCOME_ERROR

    try:
        if dry_run:
            logging.info(f"[{rid}] [DRY-RUN] Simulating 1 completed job found.")
            jobs = [{
                "job_id":       "dry-run-job-000",
                "completed_at": datetime.now(tz=timezone.utc),
                "status":       "completed",
            }]
        else:
            jobs = list_recent_jobs(session, dashboard_cfg, report["report_def_id"], since)

        # ── Not found ────────────────────────────────────────────────────────
        if not jobs:
            logging.warning(
                f"[{rid}] ⚠ No completed job found in the last {window_minutes} minutes."
            )
            send_missing_alert(smtp_cfg, recipients, report, window_minutes, dry_run)
            return OUTCOME_NOT_FOUND

        # Use the most recently completed job
        job = jobs[0]
        logging.info(
            f"[{rid}] ✓ Found job {job['job_id']} "
            f"(completed {job['completed_at'].strftime('%Y-%m-%d %H:%M:%S UTC')})"
        )
        if len(jobs) > 1:
            logging.info(
                f"[{rid}]   {len(jobs) - 1} additional job(s) in window — using most recent."
            )

        # ── Idempotency check ────────────────────────────────────────────────
        marker = output_dir / f".sent_{rid}_{job['job_id']}"
        if marker.exists() and not dry_run:
            logging.info(f"[{rid}] Already delivered (marker exists). Skipping.")
            return OUTCOME_ALREADY_SENT

        # ── Download ─────────────────────────────────────────────────────────
        now = datetime.now()
        filename = f"{rid}_{now.strftime('%Y%m%d_%H%M%S')}.{report.get('format', 'xlsx')}"
        output_path = output_dir / filename

        if not dry_run:
            logging.info(f"[{rid}] Downloading → {output_path}")
            download_job(session, dashboard_cfg, job["job_id"], output_path)
        else:
            output_path = Path("/tmp/dry-run-placeholder.xlsx")
            output_path.touch()

        # ── Email ─────────────────────────────────────────────────────────────
        subject = render_template(
            report.get("email_subject", "Wazuh Scheduled Report: {report_label} — {date}"),
            report, job,
        )
        body = render_template(
            report.get(
                "email_body",
                "Scheduled Wazuh report '{report_label}' attached.\n\n"
                "Schedule  : {schedule_label}\n"
                "Completed : {completed_at}\n"
                "Job ID    : {job_id}\n\n"
                "— Wazuh Report System\n",
            ),
            report, job,
        )
        logging.info(f"[{rid}] Sending to {len(recipients)} recipient(s)...")
        send_email(smtp_cfg, recipients, subject, body, output_path, dry_run=dry_run)

        # ── Write delivery marker ─────────────────────────────────────────────
        if not dry_run:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()

        logging.info(f"[{rid}] ✓ Done.")
        return OUTCOME_DELIVERED

    except requests.HTTPError as exc:
        logging.error(
            f"[{rid}] HTTP error: {exc} — {exc.response.text if exc.response else 'N/A'}"
        )
    except Exception as exc:
        logging.error(f"[{rid}] Unexpected error: {exc}", exc_info=True)
    return OUTCOME_ERROR


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wazuh Scheduled Report Checker & Delivery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--config", default=str(CONFIG_PATH_DEFAULT), metavar="PATH",
        help="Path to reports.conf.yaml (default: config/reports.conf.yaml)",
    )
    parser.add_argument("--report", nargs="+", metavar="ID",
                        help="Check one or more specific scheduled report IDs")
    parser.add_argument("--all", action="store_true",
                        help="Check all enabled scheduled reports")
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

    scheduled = [
        r for r in cfg.get("reports", [])
        if r.get("enabled", True) and r.get("scheduled", False)
    ]

    if args.report:
        wanted = set(args.report)
        targets = [r for r in scheduled if r["id"] in wanted]
        missing = wanted - {r["id"] for r in targets}
        if missing:
            logging.warning(f"Report ID(s) not found or not scheduled: {missing}")
    elif args.all:
        targets = scheduled
        logging.info(f"Checking {len(targets)} scheduled report(s).")
    else:
        parser.print_help()
        sys.exit(0)

    if not targets:
        logging.error("No matching scheduled reports found.")
        sys.exit(1)

    # Authenticate once; reuse the session for all checks in this run
    if not args.dry_run:
        logging.info("Establishing Dashboard session...")
        session = get_dashboard_session(cfg["dashboard"])
    else:
        session = requests.Session()  # unused in dry-run but keeps signature consistent

    results: dict[str, list] = {
        OUTCOME_DELIVERED:    [],
        OUTCOME_ALREADY_SENT: [],
        OUTCOME_NOT_FOUND:    [],
        OUTCOME_ERROR:        [],
    }
    for report in targets:
        outcome = check_scheduled_report(report, cfg, session, dry_run=args.dry_run)
        results[outcome].append(report["id"])

    logging.info(f"\n{'=' * 60}")
    logging.info("Scheduler check complete")
    logging.info(f"  ✓ Delivered   : {results[OUTCOME_DELIVERED] or 'none'}")
    logging.info(f"  ↩ Already sent: {results[OUTCOME_ALREADY_SENT] or 'none'}")
    logging.info(f"  ⚠ Not found   : {results[OUTCOME_NOT_FOUND] or 'none'}")
    logging.info(f"  ✗ Errors      : {results[OUTCOME_ERROR] or 'none'}")

    if results[OUTCOME_NOT_FOUND] or results[OUTCOME_ERROR]:
        sys.exit(1)


if __name__ == "__main__":
    main()

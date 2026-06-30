#!/usr/bin/env python3
"""
wazuh_scheduler_checker.py
==========================
Validates that Indexer-scheduled reports have been generated, then downloads
and emails them to the configured recipients.

How it works
------------
This script does NOT generate reports. It queries the Wazuh Dashboard job
queue for reports that were already produced by the OpenSearch Dashboards
Report Scheduler, then downloads and emails them.

API flow:
  1. GET  /api/reporting/reports
         -> list of all report instances (on-demand and scheduled)

  2. Filter by:
       * report_name matches the configured report_name_match value
       * trigger_type == "Schedule"   (excludes on-demand instances)
       * time_created within check_window_minutes of now

  3. GET  /api/reporting/generateReport/<instance_id>?timezone=...
         -> { "data": "...;base64,...", "filename": "..." }
         (same endpoint as on-demand generation, but GET + instance _id)

  4. Decode base64, save file, email to recipients, write idempotency marker.

If no matching instance is found within the window, a failure alert is sent
to the same recipients so the absence is noticed immediately.

Idempotency
-----------
A marker file (.sent_<report_id>_<instance_id>) is written after each
successful delivery. The checker skips any instance whose marker already
exists, preventing duplicate emails if it runs more than once in a window.
Use --force to override and re-send.

Usage
-----
  python3 scripts/wazuh_scheduler_checker.py --all
  python3 scripts/wazuh_scheduler_checker.py --report scheduled_daily_overview
  python3 scripts/wazuh_scheduler_checker.py --report scheduled_daily_overview --force
  python3 scripts/wazuh_scheduler_checker.py --all --dry-run
  python3 scripts/wazuh_scheduler_checker.py --all --config /etc/wazuh-reports/reports.conf.yaml

Cron example -- scheduled report at 06:00, checker runs at 06:15:
  15 6 * * * cd /opt/wazuh-reports && \
             python3 scripts/wazuh_scheduler_checker.py \
             --report scheduled_daily_overview >> logs/cron.log 2>&1

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
from datetime import datetime, timedelta, timezone
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests
import urllib3
import yaml

from auth import download_report_instance, get_dashboard_session, list_reports
from pdf_converter import convert_to_pdf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH_DEFAULT = Path(__file__).resolve().parent.parent / "config" / "reports.conf.yaml"

OUTCOME_DELIVERED    = "delivered"
OUTCOME_ALREADY_SENT = "already_sent"
OUTCOME_NOT_FOUND    = "not_found"
OUTCOME_FAILED       = "failed"
OUTCOME_ERROR        = "error"


# -- Config --------------------------------------------------------------------

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
                f"Unknown recipient entry '{entry}' in report '{report['id']}' -- skipping."
            )
    seen: set = set()
    return [e for e in emails if not (e in seen or seen.add(e))]


# -- Job queue filtering -------------------------------------------------------

def find_scheduled_instances(
    all_reports: list[dict],
    report_name_match: str,
    window_minutes: int,
) -> list[dict]:
    """
    Filter the full report list down to scheduled instances that match the
    configured report name and were created within check_window_minutes.

    Matching logic:
      * _source.report_definition.report_params.report_name == report_name_match
      * _source.report_definition.trigger.trigger_type == "Schedule"
      * _source.time_created (epoch ms) >= now - window_minutes

    Returns matches sorted newest first. Callers use index [0] for the most
    recent instance within the window.
    """
    since_ms = (
        datetime.now(tz=timezone.utc) - timedelta(minutes=window_minutes)
    ).timestamp() * 1000  # epoch ms

    matches = []
    for entry in all_reports:
        src = entry.get("_source", {})
        rdef = src.get("report_definition", {})
        rparams = rdef.get("report_params", {})
        trigger = rdef.get("trigger", {})

        name  = rparams.get("report_name", "")
        ttype = trigger.get("trigger_type", "")
        tc    = src.get("time_created", 0)

        if name != report_name_match:
            continue
        if ttype != "Schedule":
            continue
        if tc < since_ms:
            continue

        created_at = datetime.fromtimestamp(tc / 1000, tz=timezone.utc)
        matches.append({
            "instance_id": entry["_id"],
            "created_at":  created_at,
            "report_name": name,
            "trigger_type": ttype,
        })

    matches.sort(key=lambda m: m["created_at"], reverse=True)
    return matches


# -- Email ---------------------------------------------------------------------

def render_template(template: str, report: dict, instance: dict | None = None) -> str:
    now = datetime.now()
    ctx = {
        "date":           now.date().isoformat(),
        "timestamp":      now.strftime("%Y-%m-%d %H:%M:%S"),
        "month":          now.strftime("%B"),
        "year":           now.year,
        "report_label":   report.get("label", report["id"]),
        "schedule_label": report.get("schedule_label", "scheduled"),
        "generated_at":   (
            instance["created_at"].strftime("%Y-%m-%d %H:%M:%S UTC")
            if instance else now.strftime("%Y-%m-%d %H:%M:%S")
        ),
        "instance_id": instance["instance_id"] if instance else "N/A",
    }
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
        logging.info(f"  [DRY-RUN] Would send '{subject}' -> {recipients}")
        return

    with smtplib.SMTP(smtp_cfg["host"], smtp_cfg["port"]) as server:
        if smtp_cfg.get("use_tls", True):
            server.starttls()
        server.login(smtp_cfg["username"], smtp_cfg["password"])
        server.sendmail(smtp_cfg["from_address"], recipients, msg.as_string())
    logging.info(f"  [ok] Email sent: '{subject}' -> {recipients}")


def send_not_found_alert(
    smtp_cfg: dict,
    recipients: list[str],
    report: dict,
    window_minutes: int,
    dry_run: bool,
) -> None:
    """Alert recipients that no scheduled instance was found in the window."""
    now = datetime.now()
    subject = f"[!] Wazuh Scheduled Report NOT FOUND: {report['label']} -- {now.date().isoformat()}"
    body = (
        f"WARNING: No scheduled report instance was found in the job queue.\n\n"
        f"Report       : {report['label']} ({report['id']})\n"
        f"Report name  : {report.get('report_name_match', '(not set)')}\n"
        f"Schedule     : {report.get('schedule_label', 'unknown')}\n"
        f"Search window: last {window_minutes} minutes\n"
        f"Checked at   : {now.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"Possible causes:\n"
        f"  * The OpenSearch Dashboards Report Scheduler did not run\n"
        f"  * The report_name_match value does not match the Dashboard definition name\n"
        f"    (must match exactly: Wazuh Dashboard -> Reporting -> Report Definitions -> Name)\n"
        f"  * check_window_minutes is too short -- the report may have completed\n"
        f"    outside the search window; consider increasing it\n"
        f"  * The Wazuh Dashboard service is unavailable\n\n"
        f"Check: Wazuh Dashboard -> Reporting -> Reports (job queue)\n\n"
        f"-- Wazuh Report System"
    )

    if dry_run:
        logging.info(f"  [DRY-RUN] Would send not-found alert -> {recipients}")
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
    logging.warning(f"  [!] Not-found alert sent -> {recipients}")


# -- Core checker --------------------------------------------------------------

def check_scheduled_report(
    report: dict,
    cfg: dict,
    all_report_instances: list[dict],
    session: requests.Session,
    force: bool = False,
    dry_run: bool = False,
) -> str:
    """
    Validate and deliver one scheduled report.

    The full report list (all_report_instances) is fetched once by the caller
    and passed in here to avoid one API call per report.

    Flow:
      1. Filter all_report_instances for this report's name + "Schedule"
         trigger + within check_window_minutes
      2. No match -> send not-found alert -> return "not_found"
      3. Match found -> check idempotency marker
      4. Marker exists -> skip (return "already_sent") unless --force
      5. Download via GET /api/reporting/generateReport/<instance_id>
      6. Email -> write marker -> return "delivered"
    """
    rid = report["id"]
    smtp_cfg = cfg["smtp"]
    output_dir = Path(cfg.get("storage", {}).get("output_dir", "logs/downloads"))
    window_minutes = report.get("check_window_minutes", 90)
    report_name_match = report.get("report_name_match", "")

    logging.info(f"[{rid}] -- Checking: {report['label']} ({report.get('schedule_label', '')})")
    logging.info(f"[{rid}] Searching for name='{report_name_match}' "
                 f"trigger=Schedule within last {window_minutes} min")

    recipients = resolve_recipients(report, cfg.get("recipient_groups", {}))
    if not recipients:
        logging.warning(f"[{rid}] No recipients resolved -- skipping.")
        return OUTCOME_ERROR

    try:
        if dry_run:
            logging.info(f"[{rid}] [DRY-RUN] Simulating 1 matching scheduled instance.")
            instances = [{
                "instance_id": "dry-run-instance-000",
                "created_at":  datetime.now(tz=timezone.utc),
                "report_name": report_name_match,
                "trigger_type": "Schedule",
            }]
        else:
            instances = find_scheduled_instances(
                all_report_instances, report_name_match, window_minutes
            )

        # -- Not found --------------------------------------------------------
        if not instances:
            logging.warning(
                f"[{rid}] [!] No scheduled instance found in the last {window_minutes} min."
            )
            send_not_found_alert(smtp_cfg, recipients, report, window_minutes, dry_run)
            return OUTCOME_NOT_FOUND

        # Use the most recently created instance in the window
        instance = instances[0]
        logging.info(
            f"[{rid}] [ok] Found instance {instance['instance_id']} "
            f"(created {instance['created_at'].strftime('%Y-%m-%d %H:%M:%S UTC')})"
        )
        if len(instances) > 1:
            logging.info(
                f"[{rid}]   {len(instances) - 1} additional instance(s) in window -- using newest."
            )

        # -- Idempotency -------------------------------------------------------
        marker = output_dir / f".sent_{rid}_{instance['instance_id']}"
        if marker.exists() and not force and not dry_run:
            logging.info(
                f"[{rid}] Already delivered (marker: {marker.name}). Use --force to re-send."
            )
            return OUTCOME_ALREADY_SENT

        # -- Download ----------------------------------------------------------
        now = datetime.now()
        local_filename = f"{rid}_{now.strftime('%Y%m%d_%H%M%S')}.{report.get('format', 'xlsx')}"
        output_path = output_dir / local_filename

        if not dry_run:
            fmt = report.get("format", "xlsx")
            logging.info(f"[{rid}] Downloading instance {instance['instance_id']} -> {output_path} ({fmt})")
            api_filename = download_report_instance(
                session, cfg["dashboard"], instance["instance_id"],
                output_path, report_format=fmt
            )
            logging.info(f"[{rid}] [ok] Saved ({api_filename})")

            # Optional: convert XLSX/CSV to PDF before emailing
            if report.get("send_as_pdf") and fmt in ("xlsx", "csv"):
                pdf_path = output_path.with_suffix(".pdf")
                convert_to_pdf(
                    input_path=output_path,
                    output_path=pdf_path,
                    title=report.get("label", rid),
                    subtitle=report.get("schedule_label", ""),
                    report_date=now.strftime("%Y-%m-%d %H:%M:%S"),
                )
                output_path = pdf_path
                api_filename = pdf_path.name
                logging.info(f"[{rid}] [ok] Converted to PDF -> {pdf_path.name}")
        else:
            api_filename = f"{rid}_dry-run.xlsx"
            output_path = Path("/tmp/dry-run-placeholder.xlsx")
            output_path.touch()

        # -- Email -------------------------------------------------------------
        subject = render_template(
            report.get("email_subject", "Wazuh Scheduled Report: {report_label} -- {date}"),
            report, instance,
        )
        body = render_template(
            report.get(
                "email_body",
                "Scheduled Wazuh report '{report_label}' attached.\n\n"
                "Schedule     : {schedule_label}\n"
                "Generated at : {generated_at}\n"
                "Instance ID  : {instance_id}\n\n"
                "-- Wazuh Report System\n",
            ),
            report, instance,
        )
        logging.info(f"[{rid}] Sending to {len(recipients)} recipient(s)...")
        send_email(smtp_cfg, recipients, subject, body, output_path,
                   attachment_name=api_filename, dry_run=dry_run)

        # -- Marker ------------------------------------------------------------
        if not dry_run:
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()
            logging.debug(f"[{rid}] Marker written: {marker.name}")

        logging.info(f"[{rid}] [ok] Done.")
        return OUTCOME_DELIVERED

    except requests.HTTPError as exc:
        err = f"HTTP {exc.response.status_code if exc.response else '?'}: " \
              f"{exc.response.text[:200] if exc.response else exc}"
        logging.error(f"[{rid}] {err}")
        return OUTCOME_FAILED

    except Exception as exc:
        logging.error(f"[{rid}] Unexpected error: {exc}", exc_info=True)
        return OUTCOME_ERROR


# -- CLI -----------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Wazuh Scheduled Report Checker & Delivery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--config", default=str(CONFIG_PATH_DEFAULT), metavar="PATH")
    parser.add_argument("--report", nargs="+", metavar="ID",
                        help="Check specific scheduled report ID(s)")
    parser.add_argument("--all", action="store_true",
                        help="Check all enabled scheduled reports")
    parser.add_argument("--force", action="store_true",
                        help="Re-download and re-send even if a marker exists")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate without API calls or emails")
    parser.add_argument("--verbose", action="store_true",
                        help="Enable DEBUG logging")
    args = parser.parse_args()

    cfg = load_config(args.config)
    log_cfg = cfg.get("logging", {})
    log_file = Path(log_cfg.get("log_file", "logs/report-runner.log"))
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Force UTF-8 on both handlers so Unicode log characters ([ok] [x] -- [!] ->)
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

    scheduled = [r for r in cfg.get("reports", [])
                 if r.get("enabled", True) and r.get("scheduled", False)]

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

    # Validate that all scheduled reports have report_name_match configured
    missing_match = [r["id"] for r in targets if not r.get("report_name_match")]
    if missing_match:
        logging.error(
            f"The following scheduled reports are missing 'report_name_match' in config: "
            f"{missing_match}\n"
            f"  This must match the exact Report Definition name in the Wazuh Dashboard."
        )
        sys.exit(1)

    session = get_dashboard_session(cfg["dashboard"]) if not args.dry_run else requests.Session()

    # Fetch the job queue once -- reused for all report checks
    if not args.dry_run:
        logging.info("Fetching report job queue (GET /api/reporting/reports)...")
        all_instances = list_reports(session, cfg["dashboard"])
        logging.info(f"  {len(all_instances)} total report instance(s) in queue.")
    else:
        all_instances = []

    results: dict[str, list] = {
        OUTCOME_DELIVERED:    [],
        OUTCOME_ALREADY_SENT: [],
        OUTCOME_NOT_FOUND:    [],
        OUTCOME_FAILED:       [],
        OUTCOME_ERROR:        [],
    }
    for report in targets:
        outcome = check_scheduled_report(
            report, cfg, all_instances, session,
            force=args.force, dry_run=args.dry_run,
        )
        results[outcome].append(report["id"])

    logging.info(f"\n{'=' * 60}")
    logging.info("Scheduler check complete")
    logging.info(f"  [ok] Delivered   : {results[OUTCOME_DELIVERED] or 'none'}")
    logging.info(f"  <- Already sent: {results[OUTCOME_ALREADY_SENT] or 'none'}")
    logging.info(f"  [!] Not found   : {results[OUTCOME_NOT_FOUND] or 'none'}")
    logging.info(f"  [x] Failed      : {results[OUTCOME_FAILED] or 'none'}")
    logging.info(f"  [x] Errors      : {results[OUTCOME_ERROR] or 'none'}")

    if results[OUTCOME_NOT_FOUND] or results[OUTCOME_FAILED] or results[OUTCOME_ERROR]:
        sys.exit(1)


if __name__ == "__main__":
    main()

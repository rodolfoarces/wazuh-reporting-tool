#!/usr/bin/env python3
"""
auth.py
=======
Handles Wazuh Dashboard session authentication and provides the core
API functions shared by both runner scripts.

Authentication flow
-------------------
The Wazuh Dashboard Reporting API uses cookie-based session authentication.
Basic Auth (Authorization: Basic ...) works for direct OpenSearch REST calls
but is rejected by the Dashboards application layer that fronts the Reporting
endpoints. The correct flow mirrors what the browser does:

  POST /auth/login  { username, password }
  → Set-Cookie: security_authentication=Fe26.2**...
  → All subsequent requests carry that cookie via the Session object.

API endpoint map (from observed browser traffic)
-------------------------------------------------
  Generate (on-demand):
    POST /api/reporting/generateReport/<report_def_id>
         ?timezone=...&dateFormat=...&csvSeparator=...&allowLeadingWildcards=true
    Body: empty
    Returns: { "data": "data:<mime>;base64,<content>", "filename": "<name>" }

  List existing reports (job queue):
    GET  /api/reporting/reports
    Returns: { "data": [ { "_id": "...", "_source": { ... } } ] }
    Each _source contains report metadata including:
      report_definition.report_params.report_name  — matches the definition name
      report_definition.trigger.trigger_type        — "On demand" | "Schedule"
      time_created                                  — epoch ms when generated

  Re-execute a report instance by its _id (the 'download' flow):
    GET  /api/reporting/generateReport/<instance_id>
         ?timezone=...&dateFormat=...&csvSeparator=...&allowLeadingWildcards=true
    Returns: same shape as generate — { "data": "...;base64,...", "filename": "..." }

IMPORTANT — the API does NOT store file artifacts. Every GET re-executes the
report query using the saved parameters (time range, saved search, format)
from that instance record. Evidence from observed traffic: the response
filename contains a fresh timestamp and new UUID suffix on every call, and the
xlsx internal metadata differs between calls. The job queue is therefore a list
of report parameter snapshots, not a list of downloadable stored files.

The report_def_id (used for POST generation) and the instance _id (used for
GET re-execution) are different identifiers sharing the same endpoint path but
different HTTP methods.
"""

import base64
import logging
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Session authentication ─────────────────────────────────────────────────────

def get_dashboard_session(dashboard_cfg: dict) -> requests.Session:
    """
    Authenticate against OpenSearch Dashboards and return a Session with the
    security_authentication cookie set and ready for all Reporting API calls.

    Raises:
        requests.HTTPError  if the login endpoint returns a non-2xx status
        RuntimeError        if the expected cookie is absent after a successful login
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    session = requests.Session()
    session.verify = dashboard_cfg.get("verify_ssl", False)

    login_url = f"{base_url}/auth/login"
    headers = {
        "Content-Type": "application/json",
        "osd-xsrf": "osd-fetch",
    }
    payload = {
        "username": dashboard_cfg["username"],
        "password": dashboard_cfg["password"],
    }

    logging.debug(f"Authenticating at {login_url}")
    resp = session.post(
        login_url,
        json=payload,
        headers=headers,
        timeout=dashboard_cfg.get("timeout_seconds", 60),
    )
    resp.raise_for_status()

    if "security_authentication" not in session.cookies:
        raise RuntimeError(
            f"Login returned HTTP {resp.status_code} but the "
            f"security_authentication cookie was not set. "
            f"Response: {resp.text[:300]}"
        )

    logging.info("Dashboard session established (security_authentication cookie received).")
    return session


# ── Shared query-string parameters ────────────────────────────────────────────

def build_report_params(dashboard_cfg: dict) -> dict:
    """
    Return the query-string parameters sent on every generateReport request
    (both POST generation and GET download), matching the browser's values.

    Observed in browser traffic:
      ?timezone=America%2FAsuncion
      &dateFormat=MMM%20D%2C%20YYYY%20%40%20HH%3Amm%3Ass.SSS
      &csvSeparator=%2C
      &allowLeadingWildcards=true
    """
    return {
        "timezone":              dashboard_cfg.get("timezone", "UTC"),
        "dateFormat":            dashboard_cfg.get("date_format", "MMM D, YYYY @ HH:mm:ss.SSS"),
        "csvSeparator":          dashboard_cfg.get("csv_separator", ","),
        "allowLeadingWildcards": "true",
    }


# ── Shared file decode/write helper ───────────────────────────────────────────

def decode_and_save(response_body: dict, output_path: Path) -> str:
    """
    Decode the base64 data-URI from a generateReport response and write
    the file to disk.

    Response shape (both POST generate and GET download):
      { "data": "data:<mime>;base64,<content>", "filename": "<name>" }

    Returns the original filename provided by the API.

    Raises:
        ValueError       if 'data' or 'filename' fields are missing or malformed
        binascii.Error   if the base64 payload cannot be decoded
    """
    data_uri = response_body.get("data")
    filename  = response_body.get("filename")

    if not data_uri or not filename:
        raise ValueError(
            f"Unexpected response shape — 'data' or 'filename' missing. "
            f"Keys received: {list(response_body.keys())}"
        )
    if "," not in data_uri:
        raise ValueError(
            f"data-URI missing comma separator: {data_uri[:80]}..."
        )

    b64_payload = data_uri.split(",", 1)[1]
    file_bytes = base64.b64decode(b64_payload)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(file_bytes)

    logging.debug(f"  Written {len(file_bytes):,} bytes → {output_path}")
    return filename


# ── On-demand report generation (POST) ────────────────────────────────────────

def generate_report(
    session: requests.Session,
    dashboard_cfg: dict,
    report_def_id: str,
    output_path: Path,
) -> str:
    """
    Generate a report on-demand via a single synchronous POST and save to disk.

    POST /api/reporting/generateReport/<report_def_id>?timezone=...
    Body: empty
    → 200 OK  { "data": "...;base64,...", "filename": "..." }

    Returns the API-provided filename.
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    url = f"{base_url}/api/reporting/generateReport/{report_def_id}"

    resp = session.post(
        url,
        params=build_report_params(dashboard_cfg),
        headers={"osd-xsrf": "osd-fetch", "Content-Type": "application/json"},
        timeout=dashboard_cfg.get("timeout_seconds", 60),
    )
    resp.raise_for_status()
    return decode_and_save(resp.json(), output_path)


# ── Report instance list (job queue) ──────────────────────────────────────────

def list_reports(
    session: requests.Session,
    dashboard_cfg: dict,
) -> list[dict]:
    """
    Retrieve all report instances from the job queue.

    GET /api/reporting/reports
    → 200 OK  { "data": [ { "_id": "...", "_source": { ... } } ] }

    Each entry represents one completed report generation event.
    The list includes both on-demand and scheduled reports.
    Returns the raw list of { "_id", "_source" } dicts, newest entries last
    (the API returns them in insertion order; callers sort as needed).
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    url = f"{base_url}/api/reporting/reports"

    resp = session.get(
        url,
        headers={"osd-xsrf": "osd-fetch"},
        timeout=dashboard_cfg.get("timeout_seconds", 60),
    )
    resp.raise_for_status()
    return resp.json().get("data", [])


# ── Re-execute a report instance by _id (the "download" flow, GET) ──────────

def download_report_instance(
    session: requests.Session,
    dashboard_cfg: dict,
    instance_id: str,
    output_path: Path,
) -> str:
    """
    Re-execute a report using the saved parameters of an existing instance _id.

    Despite the name "download", the API does not serve a stored file — it
    re-runs the report query using the time range, saved search, and format
    captured in that instance record, and returns a freshly generated file.
    Confirmed by observed traffic: every GET returns a new filename timestamp
    and new UUID suffix, with differing xlsx internal metadata.

    GET /api/reporting/generateReport/<instance_id>?timezone=...
    → 200 OK  { "data": "...;base64,...", "filename": "<name>_<new_ts>_<uuid>" }

    Same endpoint path as POST generation but uses GET + instance _id
    (not the report_def_id). Returns the API-provided filename.
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    url = f"{base_url}/api/reporting/generateReport/{instance_id}"

    resp = session.get(
        url,
        params=build_report_params(dashboard_cfg),
        headers={"osd-xsrf": "osd-fetch"},
        timeout=dashboard_cfg.get("timeout_seconds", 60),
    )
    resp.raise_for_status()
    return decode_and_save(resp.json(), output_path)

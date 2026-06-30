#!/usr/bin/env python3
"""
auth.py
=======
Handles Wazuh Dashboard session authentication and provides all Reporting
API functions shared by both runner scripts.

Authentication flow
-------------------
The Wazuh Dashboard Reporting API uses cookie-based session authentication.
Basic Auth is rejected by the Dashboards application layer. The correct flow:

  POST /auth/login  { username, password }
  -> Set-Cookie: security_authentication=Fe26.2**...
  -> All subsequent requests carry that cookie via the Session object.

API endpoint map (confirmed from observed browser traffic)
----------------------------------------------------------

  Generate on-demand (CSV/XLSX --synchronous):
    POST /api/reporting/generateReport/<report_def_id>
         ?timezone=...&dateFormat=...&csvSeparator=...&allowLeadingWildcards=true
    Body: empty
    -> 200 OK  { "data": "data:<mime>;base64,<content>", "filename": "<name>" }
    The connection blocks until generation is complete. No polling needed.

  Generate on-demand (PDF from dashboard/visualization --asynchronous):
    POST /api/reporting/generateReport/<report_def_id>  (same endpoint)
    -> 200 OK  { "data": "", "filename": "<name>.pdf",
                "reportId": "<id>", "queryUrl": "<dashboard_url>" }
    data is intentionally EMPTY on the POST response. The server-side
    headless Chromium browser loads queryUrl, renders it, and stores the
    result against reportId. Poll with GET until data is non-empty.

  Poll / download PDF by reportId:
    GET  /api/reporting/generateReport/<reportId>
         ?timezone=...&dateFormat=...&csvSeparator=...&allowLeadingWildcards=true
    -> 200 OK  { "data": "", ... }               <- still rendering
    -> 200 OK  { "data": "...;base64,...", ... }  <- ready, same shape as CSV/XLSX

  List existing report instances (job queue):
    GET  /api/reporting/reports
    -> 200 OK  { "data": [ { "_id": "...", "_source": { ... } } ] }
    Includes both on-demand and scheduled instances.
    Key fields per entry:
      _source.report_definition.report_params.report_name  --definition name
      _source.report_definition.trigger.trigger_type       --"On demand"|"Schedule"
      _source.report_definition.core_params.report_format  --"csv"|"xlsx"|"pdf"
      _source.time_created                                  --epoch ms

  Re-execute an existing report instance by _id:
    GET  /api/reporting/generateReport/<instance_id>  (same endpoint as PDF poll)
    For CSV/XLSX: returns inline content immediately (synchronous).
    For PDF: may return empty data if still rendering; poll until non-empty.
    NOTE: the API re-executes the query --it does not serve a stored file.

How to detect PDF vs CSV/XLSX
------------------------------
Check the POST response: if "reportId" is present and "data" is empty,
the report is PDF/async. Route to generate_report_pdf() instead of
generate_report_sync(). Both converge on decode_and_save() once data
is non-empty.
"""

from __future__ import annotations

import base64
import logging
import time
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# -- Session authentication -----------------------------------------------------

def get_dashboard_session(dashboard_cfg: dict) -> requests.Session:
    """
    Authenticate against OpenSearch Dashboards and return a Session with the
    security_authentication cookie set and ready for all Reporting API calls.

    Raises:
        requests.HTTPError  if the login endpoint returns a non-2xx status
        RuntimeError        if the expected cookie is absent after login
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    session = requests.Session()
    session.verify = dashboard_cfg.get("verify_ssl", False)

    resp = session.post(
        f"{base_url}/auth/login",
        json={"username": dashboard_cfg["username"],
              "password": dashboard_cfg["password"]},
        headers={"Content-Type": "application/json", "osd-xsrf": "osd-fetch"},
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


# -- Shared query-string parameters --------------------------------------------

def build_report_params(dashboard_cfg: dict) -> str:
    """
    Return pre-encoded query-string parameters for every generateReport request.

    Uses urllib.parse.urlencode with quote_via=quote (not quote_plus) to
    produce %20 for spaces instead of +, matching the exact encoding the
    browser sends:
      ?timezone=America%2FAsuncion
      &dateFormat=MMM%20D%2C%20YYYY%20%40%20HH%3Amm%3Ass.SSS
      &csvSeparator=%2C
      &allowLeadingWildcards=true

    Returns a pre-encoded string. Pass as params=None and append manually,
    or use requests' params= with a dict --but to guarantee %20 encoding,
    build the URL string directly using this output.
    """
    from urllib.parse import urlencode, quote
    params = {
        "timezone":              dashboard_cfg.get("timezone", "UTC"),
        "dateFormat":            dashboard_cfg.get("date_format", "MMM D, YYYY @ HH:mm:ss.SSS"),
        "csvSeparator":          dashboard_cfg.get("csv_separator", ","),
        "allowLeadingWildcards": "true",
    }
    return urlencode(params, quote_via=quote)


def _report_url(base_url: str, report_id: str, dashboard_cfg: dict) -> str:
    """Build the full generateReport URL with correctly encoded query string."""
    return f"{base_url}/api/reporting/generateReport/{report_id}?{build_report_params(dashboard_cfg)}"


# -- Shared file decode/write helper -------------------------------------------

def decode_and_save(response_body: dict, output_path: Path) -> str:
    """
    Decode the base64 data-URI from a generateReport response and write
    the file to disk.

    Response shape:
      { "data": "data:<mime>;base64,<content>", "filename": "<name>" }

    Returns the original filename provided by the API.

    Raises:
        ValueError      if 'data' is empty/missing or 'filename' is missing
        binascii.Error  if the base64 payload cannot be decoded
    """
    data_uri = response_body.get("data")
    filename  = response_body.get("filename")

    if not data_uri or not filename:
        raise ValueError(
            f"Response 'data' is empty or 'filename' is missing.\n"
            f"  data value   : {str(data_uri)[:120]}\n"
            f"  filename     : {filename}\n"
            f"  all keys     : {list(response_body.keys())}\n"
            f"  reportId     : {response_body.get('reportId')}\n"
            f"  queryUrl     : {str(response_body.get('queryUrl', ''))[:80]}"
        )
    if "," not in data_uri:
        raise ValueError(f"data-URI missing comma separator: {data_uri[:80]}...")

    file_bytes = base64.b64decode(data_uri.split(",", 1)[1])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(file_bytes)

    logging.debug(f"  Written {len(file_bytes):,} bytes -> {output_path}")
    return filename


# -- On-demand generation --CSV/XLSX (synchronous POST) ------------------------

def generate_report_sync(
    session: requests.Session,
    dashboard_cfg: dict,
    report_def_id: str,
    output_path: Path,
) -> str:
    """
    Generate a CSV or XLSX report via a single synchronous POST.

    The connection blocks until the report is complete and the full file
    is returned inline as a base64 data-URI. No polling needed.

    POST /api/reporting/generateReport/<report_def_id>?...
    -> { "data": "data:<mime>;base64,<content>", "filename": "..." }

    Returns the API-provided filename.
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    url = _report_url(base_url, report_def_id, dashboard_cfg)

    resp = session.post(
        url,
        headers={"osd-xsrf": "osd-fetch", "Content-Type": "application/json"},
        timeout=dashboard_cfg.get("timeout_seconds", 60),
    )
    resp.raise_for_status()
    return decode_and_save(resp.json(), output_path)


# -- On-demand generation --PDF (asynchronous POST + poll) ---------------------

def generate_report_pdf(
    session: requests.Session,
    dashboard_cfg: dict,
    report_def_id: str,
    output_path: Path,
) -> str:
    """
    Generate a PDF report from a dashboard or visualization.

    PDF reports use an asynchronous headless Chromium render pipeline:

      Step 1 --POST to trigger:
        POST /api/reporting/generateReport/<report_def_id>?...
        -> { "data": "",                    <- intentionally empty
            "filename": "<name>.pdf",
            "reportId": "<poll_id>",
            "queryUrl": "<dashboard_url>"  <- Chromium loads this URL
          }

      Step 2 --Poll GET until data is non-empty:
        GET /api/reporting/generateReport/<reportId>?...
        -> { "data": "", ... }               <- still rendering
        -> { "data": "...;base64,...", ... } <- complete

    Poll interval and max attempts are read from dashboard_cfg:
      pdf_poll_interval_seconds  (default: 3)
      pdf_poll_max_attempts      (default: 40, i.e. up to ~2 min)

    Returns the API-provided filename.
    Raises TimeoutError if the report does not complete within the poll limit.
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    url = _report_url(base_url, report_def_id, dashboard_cfg)

    # Step 1: trigger
    resp = session.post(
        url,
        headers={"osd-xsrf": "osd-fetch", "Content-Type": "application/json"},
        timeout=dashboard_cfg.get("timeout_seconds", 60),
    )
    resp.raise_for_status()
    body = resp.json()

    report_id  = body.get("reportId")
    filename   = body.get("filename", f"{report_def_id}.pdf")
    query_url  = body.get("queryUrl", "")

    if not report_id:
        # data was already inline (unexpected for PDF, but handle gracefully)
        logging.debug("  PDF POST returned data inline --no polling needed.")
        return decode_and_save(body, output_path)

    logging.info(
        f"  PDF render triggered --reportId: {report_id}\n"
        f"  Chromium loading: {query_url[:120]}"
    )

    # Step 2: poll
    interval    = dashboard_cfg.get("pdf_poll_interval_seconds", 3)
    max_attempts = dashboard_cfg.get("pdf_poll_max_attempts", 40)
    poll_url    = _report_url(base_url, report_id, dashboard_cfg)

    for attempt in range(1, max_attempts + 1):
        time.sleep(interval)
        poll_resp = session.get(
            poll_url,
            headers={"osd-xsrf": "osd-fetch"},
            timeout=dashboard_cfg.get("timeout_seconds", 60),
        )
        poll_resp.raise_for_status()
        poll_body = poll_resp.json()

        data_uri = poll_body.get("data", "")
        logging.debug(
            f"  PDF poll {attempt}/{max_attempts}: "
            f"data={'<content>' if data_uri else 'empty'}"
        )

        if data_uri:
            logging.info(f"  PDF render complete after {attempt} poll(s).")
            # Use the filename from the poll response if available,
            # fall back to the filename from the trigger response.
            poll_body.setdefault("filename", filename)
            return decode_and_save(poll_body, output_path)

    raise TimeoutError(
        f"PDF report did not complete after {max_attempts} polls "
        f"({max_attempts * interval}s). reportId: {report_id}\n"
        f"Check the Wazuh Dashboard -> Reporting -> Reports for status."
    )


# -- Unified generate dispatcher -----------------------------------------------

def generate_report(
    session: requests.Session,
    dashboard_cfg: dict,
    report_def_id: str,
    output_path: Path,
    report_format: str = "xlsx",
) -> str:
    """
    Dispatch to the correct generation function based on report_format.

    CSV/XLSX -> generate_report_sync()  (single POST, inline response)
    PDF      -> generate_report_pdf()   (POST trigger + GET poll loop)

    The report_format should be taken from the config entry's 'format' field.
    Returns the API-provided filename.
    """
    if report_format.lower() == "pdf":
        return generate_report_pdf(session, dashboard_cfg, report_def_id, output_path)
    return generate_report_sync(session, dashboard_cfg, report_def_id, output_path)


# -- Report instance list (job queue) ------------------------------------------

def list_reports(
    session: requests.Session,
    dashboard_cfg: dict,
) -> list[dict]:
    """
    Retrieve all report instances from the job queue.

    GET /api/reporting/reports
    -> { "data": [ { "_id": "...", "_source": { ... } } ] }

    Returns the raw list. Includes on-demand and scheduled instances for
    all formats (CSV, XLSX, PDF).
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    resp = session.get(
        f"{base_url}/api/reporting/reports",
        headers={"osd-xsrf": "osd-fetch"},
        timeout=dashboard_cfg.get("timeout_seconds", 60),
    )
    resp.raise_for_status()
    return resp.json().get("data", [])


# -- Re-execute / download an existing report instance -------------------------

def download_report_instance(
    session: requests.Session,
    dashboard_cfg: dict,
    instance_id: str,
    output_path: Path,
    report_format: str = "xlsx",
) -> str:
    """
    Re-execute a report using the saved parameters of an existing instance _id.

    For CSV/XLSX: the GET returns inline content immediately.
    For PDF:      the GET may return empty data while Chromium re-renders;
                  poll until data is non-empty using the same reportId loop.

    GET /api/reporting/generateReport/<instance_id>?...
    -> { "data": "...;base64,...", "filename": "..." }   <- CSV/XLSX (immediate)
    -> { "data": "", "reportId": "...", ... }             <- PDF (poll needed)

    NOTE: the API re-executes the report query --it does not serve stored files.
    Returns the API-provided filename.
    """
    base_url = dashboard_cfg["url"].rstrip("/")
    url = _report_url(base_url, instance_id, dashboard_cfg)

    resp = session.get(
        url,
        headers={"osd-xsrf": "osd-fetch"},
        timeout=dashboard_cfg.get("timeout_seconds", 60),
    )
    resp.raise_for_status()
    body = resp.json()

    # If data is already present, decode and return immediately
    if body.get("data"):
        return decode_and_save(body, output_path)

    # PDF: data is empty --poll using the reportId returned in this response
    if report_format.lower() == "pdf":
        report_id = body.get("reportId")
        if not report_id:
            raise ValueError(
                f"PDF download: data is empty and no reportId in response. "
                f"Keys: {list(body.keys())}"
            )
        logging.info(f"  PDF re-execution triggered --polling reportId: {report_id}")

        interval     = dashboard_cfg.get("pdf_poll_interval_seconds", 3)
        max_attempts = dashboard_cfg.get("pdf_poll_max_attempts", 40)
        poll_url     = _report_url(base_url, report_id, dashboard_cfg)
        filename     = body.get("filename", f"{instance_id}.pdf")

        for attempt in range(1, max_attempts + 1):
            time.sleep(interval)
            poll_resp = session.get(
                poll_url,
                headers={"osd-xsrf": "osd-fetch"},
                timeout=dashboard_cfg.get("timeout_seconds", 60),
            )
            poll_resp.raise_for_status()
            poll_body = poll_resp.json()
            data_uri = poll_body.get("data", "")
            logging.debug(f"  PDF poll {attempt}/{max_attempts}: "
                          f"data={'<content>' if data_uri else 'empty'}")
            if data_uri:
                poll_body.setdefault("filename", filename)
                return decode_and_save(poll_body, output_path)

        raise TimeoutError(
            f"PDF re-execution did not complete after {max_attempts} polls "
            f"({max_attempts * interval}s). reportId: {report_id}"
        )

    raise ValueError(
        f"Empty data in response for non-PDF format '{report_format}'. "
        f"Keys: {list(body.keys())}"
    )

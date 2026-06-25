#!/usr/bin/env python3
"""
auth.py
=======
Handles Wazuh Dashboard session authentication.

The Wazuh Dashboard Reporting API (/api/reporting/generateReport/<id>) is
served by the OpenSearch Dashboards application layer, which validates a
session cookie (security_authentication) — not an HTTP Basic Auth header.

This module replicates the exact authentication flow the browser uses:

  Step 1 — POST /auth/login with username + password
            → OpenSearch Dashboards issues Set-Cookie: security_authentication
  Step 2 — All subsequent Reporting API calls carry that cookie automatically
            via the returned requests.Session object.

Why Basic Auth fails here:
  auth=(user, pass) sends an Authorization: Basic ... header, which is valid
  for direct OpenSearch REST calls but is rejected by the Dashboards
  application layer. The Reporting, job status, and download endpoints all
  sit behind Dashboards and require the session cookie instead.

The session object is created once per script run and reused for all API
calls, keeping the token valid throughout and avoiding repeated logins.
"""

import logging

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
        timeout=dashboard_cfg.get("timeout_seconds", 30),
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


def build_report_params(dashboard_cfg: dict) -> dict:
    """
    Return the query-string parameters that must accompany every
    /api/reporting/generateReport/<id> request, matching the values
    the browser sends automatically.

    These are observed directly from the Wazuh Dashboard browser request:
      POST /api/reporting/generateReport/<id>
           ?timezone=America%2FAsuncion
           &dateFormat=MMM%20D%2C%20YYYY%20%40%20HH%3Amm%3Ass.SSS
           &csvSeparator=%2C
           &allowLeadingWildcards=true
    """
    return {
        "timezone":           dashboard_cfg.get("timezone", "UTC"),
        "dateFormat":         dashboard_cfg.get("date_format", "MMM D, YYYY @ HH:mm:ss.SSS"),
        "csvSeparator":       dashboard_cfg.get("csv_separator", ","),
        "allowLeadingWildcards": "true",
    }

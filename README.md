# wazuh-reports

Automated report delivery for **Wazuh / OpenSearch Dashboards**.

Generates or validates reports from the Wazuh Indexer Reporting API, then
emails them to configured recipients. All report definitions, schedules, and
recipient lists live in one YAML config file -- no code changes needed to add
or modify reports.

---

## Project structure

```
wazuh-reports/
  config/
    reports.conf.example.yaml     # Template -- copy to reports.conf.yaml and edit
  scripts/
    auth.py                        # Session auth + all Reporting API calls
    wazuh_report_runner.py         # On-demand: POST generate -> save -> email
    wazuh_scheduler_checker.py     # Scheduled: GET job queue -> re-execute -> email
  logs/                              # Runtime logs and report files (git-ignored)
    .gitkeep
  .gitignore
  requirements.txt
  README.md
```

> **`config/reports.conf.yaml` is git-ignored.** Only the example file is
> version-controlled. Credentials never touch the repository.

---

## Quick start

```bash
# 1. Enter the project directory
cd ~/Projects/Wazuh/wazuh-reports

# 2. Install Python dependencies (includes fpdf2 and openpyxl for PDF conversion)
pip3 install -r requirements.txt

# 3. Create your live config from the example
cp config/reports.conf.example.yaml config/reports.conf.yaml

# 4. Edit with your real values (dashboard URL, credentials, report IDs)
nano config/reports.conf.yaml

# 5. Verify everything without sending anything
python3 scripts/wazuh_report_runner.py --all --dry-run
python3 scripts/wazuh_scheduler_checker.py --all --dry-run

# 6. Run for real
python3 scripts/wazuh_report_runner.py --report critical_alerts_daily
```

> **After any `git pull`:** diff the example against your live config to
> catch new required fields or changed placeholder names before running:
> ```bash
> diff config/reports.conf.example.yaml config/reports.conf.yaml
> ```

---

## How the Reporting API works

Understanding the three API operations helps configure reports correctly.

### Operation 1 -- Generate on-demand (POST)

Triggers a new report and returns the file immediately in the same response.
The connection blocks until generation is complete -- there is no polling step.

```
POST /api/reporting/generateReport/<report_def_id>
     ?timezone=America/Asuncion&dateFormat=...&csvSeparator=,&allowLeadingWildcards=true
Body: empty
-> 200 OK
  {
    "data": "data:application/vnd.openxmlformats...;base64,<content>",
    "filename": "Wazuh - Agent list_2026-06-25T19:15:44.524Z_439ca4c0.xlsx"
  }
```

The `report_def_id` is taken from the Report Definition edit URL in the Dashboard.

### Operation 2 -- List the job queue (GET)

Returns all report instances ever generated (both on-demand and scheduled).
Each entry contains the original report parameters and the time it was created.

```
GET /api/reporting/reports
-> 200 OK
  { "data": [
      {
        "_id": "A4xaAJ8BYNS2laJ4HcnD",
        "_source": {
          "time_created": 1782330933698,
          "report_definition": {
            "report_params": {
              "report_name": "Wazuh - Agent list",   <- used by report_name_match
              ...
            },
            "trigger": {
              "trigger_type": "On demand"             <- or "Schedule"
            }
          }
        }
      },
      ...
  ]}
```

> **Important:** `_source.report_definition.report_params.report_name` is the
> value that `report_name_match` in your config must match exactly. It is the
> **Report Definition name as entered in the Dashboard UI**, not the `id` or
> `label` fields in your config file.

### Operation 3 -- Re-execute a queued instance (GET)

Re-runs the report using the saved parameters (time range, saved search,
format) of an existing job queue entry and returns a fresh file.

```
GET /api/reporting/generateReport/<instance_id>
    ?timezone=...&dateFormat=...&csvSeparator=,&allowLeadingWildcards=true
-> 200 OK
  { "data": "...;base64,<content>", "filename": "..._<new_timestamp>_<new_uuid>.xlsx" }
```

> **Note:** The API does not serve stored files. Every GET re-executes the
> query and returns a freshly generated file -- confirmed by fresh timestamps
> and new UUIDs in the filename on every call. The job queue is a list of
> **report parameter snapshots**, not stored file artifacts.

---

## Finding your Report Definition ID (`report_def_id`)

Used by the on-demand runner (POST generation).

1. Open **Wazuh Dashboard -> Reporting -> Report Definitions**
2. Click **Edit** on the report
3. Copy the ID from the browser URL:

```
https://wazuh.corp.example.com/app/reporting/edit/report_definition/a1b2c3d4-e5f6-7890-abcd-ef1234567890
                                                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                                      this is your report_def_id
```

---

## Finding your Report Name Match (`report_name_match`)

Used by the scheduler checker to locate the right entry in the job queue.
This **must match exactly** the `report_name` field stored in the job queue,
which corresponds to the **Report Definition name as entered in the Dashboard UI**.

### Method 1 -- Check the Dashboard UI

1. Open **Wazuh Dashboard -> Reporting -> Report Definitions**
2. The **Name** column value is exactly what goes in `report_name_match`

### Method 2 -- Query the job queue directly

Run this one-liner to list all report names and their trigger types:

```bash
curl -sk -X GET "https://10.0.0.3/api/reporting/reports" \
  -H "osd-xsrf: osd-fetch" \
  -H "Content-Type: application/json" \
  --cookie "security_authentication=<your_cookie>" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin).get('data', [])
for r in data:
    src = r['_source']
    rp  = src.get('report_definition', {}).get('report_params', {})
    trg = src.get('report_definition', {}).get('trigger', {})
    print(f\"_id          : {r['_id']}\")
    print(f\"  report_name  : {rp.get('report_name')}\")
    print(f\"  trigger_type : {trg.get('trigger_type')}\")
    print(f\"  time_created : {src.get('time_created')}\")
    print()
"
```

The value under `report_name` for your scheduled report is exactly what goes
in `report_name_match`. For example:

```
_id          : KoyUAJ8BYNS2laJ49cmD
  report_name  : Wazuh - FIM Daily Overview     <- use this exact string
  trigger_type : Schedule
  time_created : 1782330933698
```

---

## Configuration (`config/reports.conf.yaml`)

### Dashboard connection

```yaml
dashboard:
  url: "https://wazuh.corp.example.com:443"
  username: "admin"
  password: "Sup3rS3cret!"    # or set WAZUH_DASH_PASS env var
  verify_ssl: false            # set true with a valid certificate
  timeout_seconds: 60          # generation is synchronous -- allow enough time
  timezone: "America/Asuncion" # IANA tz name, e.g. America/New_York, UTC
  date_format: "MMM D, YYYY @ HH:mm:ss.SSS"
  csv_separator: ","
```

### SMTP

```yaml
smtp:
  host: "smtp.corp.example.com"
  port: 587
  use_tls: true
  username: "wazuh-reports@corp.example.com"
  password: "Sm7pP@ssw0rd"    # or set WAZUH_SMTP_PASS env var
  from_address: "wazuh-reports@corp.example.com"
  from_name: "Wazuh Report System"
```

**Gmail:** use an [App Password](https://support.google.com/accounts/answer/185833) (16 chars), host `smtp.gmail.com`, port `587`.  
**Office 365:** host `smtp.office365.com`, port `587`.

### Recipient groups

```yaml
recipient_groups:
  soc_team:
    - "alice.smith@corp.example.com"
    - "bob.jones@corp.example.com"
  soc_managers:
    - "carol.white@corp.example.com"
    - "david.lee@corp.example.com"
```

### On-demand report definition

Handled by `wazuh_report_runner.py`. The runner ignores entries with
`scheduled: true`.

```yaml
reports:
  - id: "critical_alerts_daily"
    label: "Critical Alerts -- Daily Summary"
    report_def_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"  # from Report Definition edit URL
    format: "xlsx"                # xlsx or csv
    enabled: true
    recipients:
      - soc_team                  # recipient group name
      - soc_managers
      - "extra@partner.example.com"  # raw address also accepted
    email_subject: "Wazuh Critical Alerts -- {date}"
    email_body: |
      Daily Critical Alerts report attached.

      Report date : {date}
      Generated at: {timestamp}

      -- Wazuh Report System
```

**On-demand email placeholders:**

| Placeholder | Value |
|---|---|
| `{date}` | Today's date, e.g. `2026-06-25` |
| `{timestamp}` | Generation datetime, e.g. `2026-06-25 19:15:44` |
| `{month}` | Month name, e.g. `June` |
| `{year}` | Year, e.g. `2026` |
| `{report_label}` | The `label` field from this config entry |

### Scheduled report definition

Handled by `wazuh_scheduler_checker.py`. The checker ignores entries without
`scheduled: true`. Requires two additional fields not present on on-demand
reports: `report_name_match` and `check_window_minutes`.

```yaml
  - id: "scheduled_fim_daily_overview"
    label: "Scheduled -- Daily FIM Security Overview"
    report_def_id: "KoyUAJ8BYNS2laJ49cmD"   # from Report Definition edit URL
                                              # (used if checker falls back to generation)
    format: "xlsx"
    enabled: true
    scheduled: true
    schedule_label: "Daily at 18:00"

    # report_name_match -- REQUIRED for scheduled reports
    # Must match _source.report_definition.report_params.report_name in the job queue,
    # which is the exact Report Definition name entered in the Dashboard UI.
    # To find it: Wazuh Dashboard -> Reporting -> Report Definitions -> Name column
    # Or query the job queue -- see README "Finding your Report Name Match" section.
    report_name_match: "Wazuh - FIM Daily Overview"

    # check_window_minutes -- how far back to search the job queue for a completed
    # scheduled instance. Set to at least 15 min longer than expected generation time.
    # Example: scheduled at 18:00, checker cron runs at 18:15 -> window of 30 min is enough.
    check_window_minutes: 90

    recipients:
      - soc_team
    email_subject: "Wazuh FIM Daily Overview (Scheduled) -- {date}"
    email_body: |
      Scheduled Daily FIM Security Overview attached.

      Schedule     : {schedule_label}
      Generated at : {generated_at}
      Instance ID  : {instance_id}

      -- Wazuh Report System
```

**Scheduled email placeholders:**

| Placeholder | Value |
|---|---|
| `{date}` | Today's date |
| `{timestamp}` | Current datetime when checker ran |
| `{generated_at}` | When the matched job queue instance was created |
| `{instance_id}` | The job queue `_id` of the matched instance |
| `{month}` | Month name |
| `{year}` | Year |
| `{report_label}` | The `label` field from this config entry |
| `{schedule_label}` | The `schedule_label` field from this config entry |

> **Common mistake:** using `{completed_at}` or `{job_id}` in the email body
> these are not valid placeholders. Use `{generated_at}` and `{instance_id}`.

---

## Scripts

### `wazuh_report_runner.py` -- on-demand

POSTs to the generate endpoint, receives the file inline (synchronous), saves
it, and emails it. One API call per report.

```bash
# Single report
python3 scripts/wazuh_report_runner.py --report critical_alerts_daily

# Multiple reports in one pass
python3 scripts/wazuh_report_runner.py --report critical_alerts_daily failed_logins_weekly

# All enabled on-demand reports
python3 scripts/wazuh_report_runner.py --all

# Filter by keyword in report ID
python3 scripts/wazuh_report_runner.py --all --filter compliance

# Dry-run (no API calls, no email)
python3 scripts/wazuh_report_runner.py --all --dry-run

# Verbose debug output
python3 scripts/wazuh_report_runner.py --report critical_alerts_daily --verbose
```

### `wazuh_scheduler_checker.py` -- scheduled report delivery

Queries the job queue once, then for each scheduled report finds the most
recent matching instance within the configured window and re-executes it to
download and email the file.

```bash
# Check all scheduled reports
python3 scripts/wazuh_scheduler_checker.py --all

# Check a specific scheduled report
python3 scripts/wazuh_scheduler_checker.py --report scheduled_fim_daily_overview

# Re-send even if already delivered today
python3 scripts/wazuh_scheduler_checker.py --report scheduled_fim_daily_overview --force

# Dry-run (no API calls, no email)
python3 scripts/wazuh_scheduler_checker.py --all --dry-run

# Verbose debug output
python3 scripts/wazuh_scheduler_checker.py --all --verbose
```

#### How the checker works

```
OpenSearch Dashboards Scheduler
  +- runs Report Definition at scheduled time (e.g. 18:00)
  +- writes instance to job queue (_id + original parameters)
        |
        |  ~15 minutes later (cron)
        v
wazuh_scheduler_checker.py
  1. GET /api/reporting/reports  ->  fetch full job queue (one call for all reports)
  2. For each scheduled report in config:
       Filter by: report_name  == report_name_match  (exact match)
                  trigger_type == "Schedule"
                  time_created >= now - check_window_minutes

       +-- Instance found? -------------------------------------------------+
       |  YES -> marker file exists? (.sent_<id>_<instance_id>)              |
       |         NO  -> GET /api/reporting/generateReport/<instance_id>      |
       |               -> decode base64 -> save -> email -> write marker     |
       |         YES -> skip (already delivered) -- use --force to resend    |
       |                                                                      |
       |  NO  -> send [!] not-found alert email to recipients                |
       +----------------------------------------------------------------------+
```

> **Startup validation:** the checker will refuse to run if any enabled
> scheduled report in config is missing `report_name_match`. This prevents
> silent failures where the wrong report (or no report) gets matched.

---

## Admin Web UI (`wazuh_gui2.py`)

A browser-based configuration editor and report runner. Provides full access to
edit the YAML configuration file and run on-demand reports, all from a single page.

### Install

```bash
pip3 install flask pyyaml
# or install everything at once:
pip3 install -r requirements.txt
```

### Start

```bash
python3 scripts/wazuh_gui2.py
```

Then open `http://127.0.0.1:5000` in your browser.

### Options

| Option | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address. Use `0.0.0.0` to reach from outside the VM |
| `--port` | `5000` | Listening port |
| `--config PATH` | `config/reports.conf.yaml` | Path to the YAML config file |
| `--auth USER:PASS` | -- | Enable HTTP Basic Auth (or set `WAZUH_GUI_AUTH`) |
| `--ssl-cert PATH` | -- | PEM certificate file to enable HTTPS (or set `WAZUH_GUI_SSL_CERT`) |
| `--ssl-key PATH` | -- | PEM private key file to enable HTTPS (or set `WAZUH_GUI_SSL_KEY`) |
| `--debug` | off | Show full command lines and config file paths in the UI |

Both `--ssl-cert` and `--ssl-key` must be provided together.

### Examples

```bash
# Local only, no auth (default)
python3 scripts/wazuh_gui2.py

# Custom port
python3 scripts/wazuh_gui2.py --port 8080

# Expose to the network with authentication
python3 scripts/wazuh_gui2.py --host 0.0.0.0 --auth admin:Sup3rS3cret!

# HTTPS only (local)
python3 scripts/wazuh_gui2.py \
    --ssl-cert /etc/ssl/certs/gui.crt \
    --ssl-key  /etc/ssl/private/gui.key

# Expose with HTTPS and auth
python3 scripts/wazuh_gui2.py \
    --host 0.0.0.0 \
    --auth admin:Sup3rS3cret! \
    --ssl-cert /etc/ssl/certs/gui.crt \
    --ssl-key  /etc/ssl/private/gui.key

# Pass credentials via environment variable instead of the command line
export WAZUH_GUI_AUTH="admin:Sup3rS3cret!"
python3 scripts/wazuh_gui2.py --host 0.0.0.0

# Debug mode -- reveals config file paths and full runner commands in the UI
python3 scripts/wazuh_gui2.py --debug
```

### UI sections

| Tab | What it configures |
|---|---|
| **Connection** | Dashboard URL, credentials, SSL, timeout, timezone, CSV separator |
| **SMTP / Email** | Mail server host, port, TLS, sender identity |
| **Recipient groups** | Named address lists referenced by report definitions |
| **Reports** | Add, edit, or remove on-demand and scheduled report definitions |
| **Storage / Logging** | Output directory, file retention period, log level |
| **>Run reports** | Trigger any on-demand report and watch live streamed output |

> **Save before running.** Click **Save config** after any change -- the runner
> always reads from the saved YAML file.

---

## Run-only Web UI (`wazuh-gui.py`)

A read-only interface for running reports on demand. It reads the existing YAML
configuration but never modifies it. Intended for operators who need to trigger
reports but should not have access to configuration or credentials.

- Default port `5001` to avoid conflict with the admin UI
- Uses its own separate credentials, independent of `wazuh_gui2.py`
- Writes a server log to `logs/wazuh-run-gui.log`

### Start

```bash
python3 scripts/wazuh-gui.py
```

Then open `http://127.0.0.1:5001` in your browser.

### Options

| Option | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `5001` | Listening port |
| `--config PATH` | `config/reports.conf.yaml` | Path to the YAML config file |
| `--auth USER:PASS` | -- | Enable HTTP Basic Auth (or set `WAZUH_RUN_GUI_AUTH`) |
| `--auth-file PATH` | -- | File containing `USER:PASS` on its first line |
| `--ssl-cert PATH` | -- | PEM certificate file to enable HTTPS (or set `WAZUH_RUN_GUI_SSL_CERT`) |
| `--ssl-key PATH` | -- | PEM private key file to enable HTTPS (or set `WAZUH_RUN_GUI_SSL_KEY`) |
| `--debug` | off | Show full runner command lines in the UI; set log level to DEBUG |

### Credential precedence

When multiple sources are present, `--auth` wins over the environment variable,
which wins over `--auth-file`:

```
--auth USER:PASS  >  WAZUH_RUN_GUI_AUTH  >  --auth-file PATH
```

### Examples

```bash
# Local only, no auth (default)
python3 scripts/wazuh-gui.py

# With authentication
python3 scripts/wazuh-gui.py --auth operator:RunP@ss!

# Credentials stored in a protected file instead of on the command line
echo "operator:RunP@ss!" > /etc/wazuh-run-gui.auth
chmod 600 /etc/wazuh-run-gui.auth
python3 scripts/wazuh-gui.py --auth-file /etc/wazuh-run-gui.auth

# Expose to the network with auth
python3 scripts/wazuh-gui.py --host 0.0.0.0 --auth operator:RunP@ss!

# Expose with HTTPS and auth
python3 scripts/wazuh-gui.py \
    --host 0.0.0.0 \
    --auth operator:RunP@ss! \
    --ssl-cert /etc/ssl/certs/gui.crt \
    --ssl-key  /etc/ssl/private/gui.key

# Different config file
python3 scripts/wazuh-gui.py --config /opt/wazuh/reports.conf.yaml

# Debug mode -- shows full runner command in the UI and writes DEBUG-level log entries
python3 scripts/wazuh-gui.py --debug

# Run both UIs at the same time with separate credentials
python3 scripts/wazuh_gui2.py --auth admin:AdminPass! &
python3 scripts/wazuh-gui.py  --auth operator:RunP@ss! &
```

### Server log

Activity is written to `logs/wazuh-run-gui.log` alongside the existing log files.
The file name is set by the `LOG_FILE_NAME` variable at the top of the script -- edit
it there to redirect the log without changing the CLI. Each entry records:

- Server startup parameters (config path, bind address, auth state, SSL state)
- Every run request (report ID or ALL, dry-run flag, verbose flag)
- Runner exit codes
- Any errors encountered launching the runner process

---

## PDF conversion from XLSX / CSV

When `send_as_pdf: true` is set on a report definition, the script downloads
the XLSX or CSV from the Indexer as usual, then converts it to a formatted PDF
using **fpdf2** before attaching it to the email. The original XLSX/CSV is kept
in `logs/downloads/` for reference.

This is the recommended approach for delivering visualization-style data
reports via email when the native PDF generation from the Wazuh Dashboard
is not accessible via the API.

### Install the dependency

```bash
pip install fpdf2 openpyxl
# or install all dependencies at once:
pip install -r requirements.txt
```

Both `fpdf2` and `openpyxl` are pure Python -- no system-level dependencies
required. Works on Windows and Linux without any extra setup.

### Enable per report

```yaml
  - id: "critical_alerts_daily"
    label: "Critical Alerts -- Daily Summary"
    report_def_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    format: "xlsx"           # downloaded format from the Indexer
    send_as_pdf: true        # convert to PDF before emailing
    recipients:
      - soc_team
```

`send_as_pdf` has no effect when `format` is already `"pdf"`.

### PDF output characteristics

The generated PDF is landscape A4 with:
- Wazuh-branded header (dark blue) with report title, subtitle, and date
- Auto-sized columns distributed across the full page width
- Alternating row shading for readability
- Long cell values truncated with ellipsis to fit the column
- Page number and timestamp footer on every page
- Column headers repeated on each new page

### Standalone conversion (testing)

```bash
# Convert a file directly without running a full report
python3 scripts/pdf_converter.py logs/downloads/my_report.xlsx output.pdf \
    --title "Critical Alerts" \
    --subtitle "Daily at 07:00" \
    --date "2026-06-29 07:00:00"
```

## Cron setup

```bash
crontab -e
```

```cron
# -- On-demand reports ----------------------------------------------------------

# Critical alerts every day at 07:00
0 7 * * *   cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_report_runner.py --report critical_alerts_daily \
            >> logs/cron.log 2>&1

# Weekly failed logins -- every Monday at 07:30
30 7 * * 1  cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_report_runner.py --report failed_logins_weekly \
            >> logs/cron.log 2>&1

# Monthly PCI-DSS -- 1st of each month at 08:00
0 8 1 * *   cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_report_runner.py --report compliance_pci_monthly \
            >> logs/cron.log 2>&1

# -- Scheduled report validation ------------------------------------------------
# Run ~15 min AFTER the time configured in the Wazuh Dashboard scheduler.

# FIM daily overview -- Dashboard scheduler runs at 18:00, checker at 18:15
15 18 * * * cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_scheduler_checker.py \
            --report scheduled_fim_daily_overview \
            >> logs/cron.log 2>&1

# Daily security overview -- Dashboard scheduler at 06:00, checker at 06:15
15 6 * * *  cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_scheduler_checker.py \
            --report scheduled_daily_overview \
            >> logs/cron.log 2>&1
```

---

## Adding a new on-demand report -- checklist

1. **Create** the Report Definition in Wazuh Dashboard -> Reporting -> Report Definitions
2. **Copy** the `report_def_id` from the edit URL
3. **Add** an entry under `reports:` in `config/reports.conf.yaml` with `scheduled: false` (or omit the field)
4. **Reference** an existing recipient group or add a new one
5. **Test** with `--dry-run`, then run for real
6. **Add** a cron entry if it should run on a schedule

## Adding a new scheduled report -- checklist

1. **Create** the Report Definition in Wazuh Dashboard -> Reporting -> Report Definitions, with a **Schedule** trigger
2. **Copy** the `report_def_id` from the edit URL
3. **Find** the `report_name_match` value using one of the methods in the [Finding your Report Name Match](#finding-your-report-name-match-report_name_match) section
4. **Add** an entry under `reports:` with `scheduled: true`, `report_name_match`, and `check_window_minutes`
5. **Test** with `--dry-run` after the scheduler has run at least once
6. **Add** a cron entry timed ~15 min after the Dashboard scheduler runs

---

## Using environment variables instead of plaintext passwords

```bash
# Add to ~/.bashrc or /etc/environment
export WAZUH_DASH_PASS="Sup3rS3cret!"
export WAZUH_SMTP_PASS="Sm7pP@ssw0rd"
```

Or prefix the cron command directly (less ideal -- visible in process list):

```cron
15 18 * * * WAZUH_DASH_PASS=secret WAZUH_SMTP_PASS=secret \
            python3 ~/Projects/Wazuh/wazuh-reports/scripts/wazuh_scheduler_checker.py --all
```

---

## Troubleshooting

| Symptom | Check |
|---|---|
| `missing 'report_name_match'` error on startup | Add `report_name_match` to every `scheduled: true` entry in config -- see [Finding your Report Name Match](#finding-your-report-name-match-report_name_match) |
| `report_name_match` configured but no instance found | Value must match `_source.report_definition.report_params.report_name` exactly -- use the job queue curl command to verify the exact string |
| `KeyError` on `{completed_at}` or `{job_id}` in email body | Wrong placeholders -- use `{generated_at}` and `{instance_id}` for scheduled reports |
| HTTP 401 on any API call | Wrong credentials; check `WAZUH_DASH_PASS` env var; session cookie may have expired |
| `security_authentication cookie was not set` | Login endpoint returned 200 but no cookie -- check Dashboard URL and that the `/auth/login` endpoint is reachable |
| SSL warnings in logs | Expected with self-signed certs when `verify_ssl: false` -- set `true` with a valid cert in production |
| Email fails to send | Verify SMTP host, port, credentials; check that port 587 outbound is allowed by firewall |
| `check_window_minutes` too short -- no instance found | Increase the window; also confirm the Dashboard scheduler actually ran (check Dashboard -> Reporting -> Reports) |
| Same report emailed twice | Marker files (`.sent_<id>_<instance_id>`) in `logs/downloads/` prevent duplicates -- verify write permissions on that directory |
| `Unknown recipient entry` warning | Entry in `recipients:` doesn't match any key in `recipient_groups:` and isn't a valid email address |

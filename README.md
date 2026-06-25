# wazuh-reports

Automated report delivery for **Wazuh / OpenSearch Dashboards**.

Generates or validates reports, then emails them to configured recipients.
All report definitions, schedules, and recipient lists live in one YAML config
file — no code changes needed to add or modify reports.

---

## Project structure

```
wazuh-reports/
├── config/
│   └── reports.conf.example.yaml   # Template — copy to reports.conf.yaml and edit
├── scripts/
│   ├── wazuh_report_runner.py      # On-demand: trigger → poll → download → email
│   └── wazuh_scheduler_checker.py  # Scheduled: validate Indexer job → download → email
├── logs/                           # Runtime logs and downloaded reports (git-ignored)
│   └── .gitkeep
├── .gitignore
├── requirements.txt
└── README.md
```

> **`config/reports.conf.yaml` is git-ignored.** Only the example file is version-controlled.
> Credentials never touch the repository.

---

## Quick start

```bash
# 1. Clone or place the project
cd ./wazuh-reports

# 2. Install Python dependencies
pip3 install -r requirements.txt

# 3. Create your config from the example
cp config/reports.conf.example.yaml config/reports.conf.yaml

# 4. Edit with your real values (see Configuration section below)
nano config/reports.conf.yaml

# 5. Verify without sending anything
python3 scripts/wazuh_report_runner.py --all --dry-run
python3 scripts/wazuh_scheduler_checker.py --all --dry-run

# 6. Run for real
python3 scripts/wazuh_report_runner.py --report critical_alerts_daily
```

---

## Finding your Report Definition IDs

1. Open **Wazuh Dashboard → Reporting → Report Definitions**
2. Click **Edit** on any report
3. Copy the ID from the browser URL:

```
https://wazuh.corp.example.com/app/reporting/edit/report_definition/a1b2c3d4-e5f6-7890-abcd-ef1234567890
                                                                      ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                                      paste this into report_def_id
```

---

## Configuration (`config/reports.conf.yaml`)

### Dashboard connection

```yaml
dashboard:
  url: "https://wazuh.corp.example.com:443"
  username: "admin"
  password: "Sup3rS3cret!"    # or use WAZUH_DASH_PASS env var
  verify_ssl: false            # set true with a valid certificate
  timeout_seconds: 30
  poll_interval_seconds: 5
  poll_max_attempts: 24        # 24 × 5 s = 2 min max wait
```

### SMTP

```yaml
smtp:
  host: "smtp.corp.example.com"
  port: 587
  use_tls: true
  username: "wazuh-reports@corp.example.com"
  password: "Sm7pP@ssw0rd"    # or use WAZUH_SMTP_PASS env var
  from_address: "wazuh-reports@corp.example.com"
  from_name: "Wazuh Report System"
```

**Gmail example:**
```yaml
smtp:
  host: "smtp.gmail.com"
  port: 587
  use_tls: true
  username: "wazuh-alerts@gmail.com"
  password: "abcd efgh ijkl mnop"    # 16-char App Password (not your login password)
  from_address: "wazuh-alerts@gmail.com"
```

**Office 365 example:**
```yaml
smtp:
  host: "smtp.office365.com"
  port: 587
  use_tls: true
  username: "wazuh-reports@corp.onmicrosoft.com"
  password: "M!cr0s0ftP@ss"
  from_address: "wazuh-reports@corp.onmicrosoft.com"
```

### Recipient groups

Define named groups once, reference them in any number of reports:

```yaml
recipient_groups:

  soc_team:
    - "alice.smith@corp.example.com"
    - "bob.jones@corp.example.com"

  soc_managers:
    - "carol.white@corp.example.com"   # SOC Manager
    - "david.lee@corp.example.com"     # CISO

  compliance:
    - "compliance@corp.example.com"
    - "external-auditor@auditfirm.example.com"
```

### On-demand report definition

```yaml
reports:
  - id: "critical_alerts_daily"
    label: "Critical Alerts — Daily Summary"
    report_def_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    format: "xlsx"
    enabled: true
    recipients:
      - soc_team                            # group name
      - soc_managers                        # group name
      - "extra-recipient@partner.example.com"  # raw address also works
    email_subject: "Wazuh Critical Alerts — {date}"
    email_body: |
      Daily Critical Alerts report attached.

      Report date : {date}
      Generated at: {timestamp}

      — Wazuh Report System
```

**Available placeholders:** `{date}` `{timestamp}` `{month}` `{year}` `{report_label}`

### Scheduled report definition

Add `scheduled: true` plus two extra fields. The checker script handles these;
the runner script ignores them.

```yaml
  - id: "scheduled_daily_overview"
    label: "Scheduled — Daily Security Overview"
    report_def_id: "e5f6a7b8-c9d0-1234-efab-345678901234"
    format: "xlsx"
    enabled: true
    scheduled: true
    schedule_label: "Daily at 06:00"
    check_window_minutes: 90      # look back 90 min from when the checker runs
    recipients:
      - all_security
    email_subject: "Wazuh Daily Overview (Scheduled) — {date}"
    email_body: |
      Scheduled Daily Security Overview attached.

      Completed : {completed_at}
      Job ID    : {job_id}

      — Wazuh Report System
```

**Additional placeholders for scheduled reports:** `{completed_at}` `{job_id}` `{schedule_label}`

---

## Scripts

### `wazuh_report_runner.py` — on-demand

Triggers a report job via the API, waits for it to finish, downloads it,
and emails it to the configured recipients.

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

### `wazuh_scheduler_checker.py` — scheduled report validation

Does **not** trigger generation. Queries the Dashboards job list for a recently
completed job matching the configured `report_def_id`, then downloads and emails
it. If no job is found within the window, it sends a **missing-report alert**
to the same recipients.

Idempotent — a marker file prevents the same job being emailed twice even if
the checker runs multiple times.

```bash
# Check all scheduled reports
python3 scripts/wazuh_scheduler_checker.py --all

# Check one specific scheduled report
python3 scripts/wazuh_scheduler_checker.py --report scheduled_daily_overview

# Dry-run
python3 scripts/wazuh_scheduler_checker.py --all --dry-run
```

#### How it decides whether a report is "found"

```
OpenSearch Dashboards Scheduler
  └─ generates job at scheduled time (e.g. 06:00)
        │
        │  ~15 minutes later
        ▼
wazuh_scheduler_checker.py
  1. GET /api/reporting/jobs/list
  2. Filter: report_def_id matches AND status = "completed"
             AND completed_at >= (now - check_window_minutes)
  3a. Job found + not yet sent
        → download → email → write marker file (.sent_<id>_<job_id>)
  3b. Job found + marker exists
        → skip (already delivered)
  3c. No job found
        → send ⚠ missing-report alert email to recipients
```

---

## Cron setup

```bash
crontab -e
```

```cron
# ── On-demand reports ─────────────────────────────────────────────────────────

# Critical alerts every day at 07:00
0 7 * * *   cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_report_runner.py --report critical_alerts_daily \
            >> logs/cron.log 2>&1

# Weekly failed logins — every Monday at 07:30
30 7 * * 1  cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_report_runner.py --report failed_logins_weekly \
            >> logs/cron.log 2>&1

# Monthly PCI-DSS — 1st of each month at 08:00
0 8 1 * *   cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_report_runner.py --report compliance_pci_monthly \
            >> logs/cron.log 2>&1

# ── Scheduled report validation ───────────────────────────────────────────────
# Run ~15 min after the Indexer's own scheduled generation time.

# Daily overview — Indexer runs at 06:00, check at 06:15
15 6 * * *  cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_scheduler_checker.py --report scheduled_daily_overview \
            >> logs/cron.log 2>&1

# Weekly threat — Indexer runs Monday 07:00, check at 07:15
15 7 * * 1  cd ~/Projects/Wazuh/wazuh-reports && \
            python3 scripts/wazuh_scheduler_checker.py --report scheduled_weekly_threat \
            >> logs/cron.log 2>&1
```

---

## Using environment variables instead of plaintext passwords

```bash
# Add to ~/.bashrc, /etc/environment, or a secrets manager integration
export WAZUH_DASH_PASS="Sup3rS3cret!"
export WAZUH_SMTP_PASS="Sm7pP@ssw0rd"
```

Or inline in cron (less ideal, visible in process list):

```cron
15 6 * * * WAZUH_DASH_PASS=secret WAZUH_SMTP_PASS=secret \
           python3 ~/Projects/Wazuh/wazuh-reports/scripts/wazuh_scheduler_checker.py --all
```

---

## Adding a new report — checklist

1. **Create the Report Definition** in Wazuh Dashboard → Reporting → Report Definitions
2. **Copy the ID** from the edit URL
3. **Add an entry** to `config/reports.conf.yaml` under `reports:`
4. **Reference or create** a recipient group (or use raw email addresses)
5. **Test** with `--dry-run`, then run for real

No script changes required.

---

## Troubleshooting

| Symptom | Check |
|---|---|
| `No job_id in response` | Verify `report_def_id` matches the Dashboards edit URL |
| HTTP 401 errors | Wrong credentials; check `WAZUH_DASH_PASS` env var override |
| SSL warnings in logs | Expected with self-signed certs when `verify_ssl: false`; suppress by setting `true` with a valid cert |
| Email fails to send | Confirm SMTP host, port, credentials; check firewall allows port 587 outbound |
| Scheduled report `not_found` every run | Increase `check_window_minutes`; verify the Dashboards scheduler is enabled; check the Dashboards job queue manually |
| Same report emailed twice | Marker files (`.sent_*`) in `logs/downloads/` prevent duplicates — check directory permissions |
| `Unknown recipient entry` warning | Entry in `recipients:` doesn't match any key in `recipient_groups:` and isn't an email address |

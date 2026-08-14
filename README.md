# Assurance Finding Lifecycle & SLA Management Platform

A production-ready security assurance platform for the Security Assurance team:

- **Ingest** vulnerability scan reports (VA Scans, CIS Benchmarks, Configuration Reviews) from JSON/XML files (Nessus `.nessus`, OpenVAS, custom JSON exports).
- **Correlate** findings by `CVE + PluginID + Asset + Port` — re-scanning an asset refreshes `last_seen` instead of creating duplicates; closed findings that reappear are re-opened and flagged.
- **Enforce dynamic SLA** — remediation deadlines come from a severity × asset-classification matrix (DB-backed, admin-editable), anchored to the original first-detection date.
- **Track lifecycle** — `Open → In Progress → Pending Verification → Pending Retest → Closed` (+ `Risk Accepted`), with strict transition validation and a retest workflow that preserves finding age.
- **Manage risk exceptions** — link a `risk_id` (e.g. `RSK-2025-0142`) to put a finding "Under Exception" and pause its breach clock.
- **Alert** via a simulated webhook/email outbox when Critical findings are created, statuses change, reappear, or SLA breaches.
- **Analyze** on an 8-screen dark operations dashboard with Chart.js analytics, search, filters, and severity sorting.

## Tech Stack

| Layer     | Technology                                          |
| --------- | --------------------------------------------------- |
| Backend   | Python 3.10+ · FastAPI (auto Swagger at `/docs`)     |
| Database  | SQLite via SQLAlchemy 2.x ORM (zero config)          |
| Frontend  | HTML5 + TailwindCSS (CDN) + Chart.js (CDN) + vanilla JS |
| Parsers   | Built-in JSON/XML engines for Nessus/OpenVAS/CIS     |

## Quickstart (Windows / macOS / Linux)

```bash
cd assurance_platform

# 1. Create a virtual environment
python -m venv .venv
.venv\Scripts\activate          # Windows PowerShell
# source .venv/bin/activate     # macOS / Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the API
uvicorn app.main:app --reload --port 8000
```

Open:

- **Dashboard:** http://127.0.0.1:8000
- **Swagger/OpenAPI docs:** http://127.0.0.1:8000/docs
- **Health check:** http://127.0.0.1:8000/api/v1/health

On first boot the platform seeds `sample_data/mock_scan.json` (13 unique
findings, including a duplicate that demonstrates correlation/dedup), builds
the asset registry with auto-classification, and loads the 16-rule SLA matrix.

## Test Ingestion Right Away

```bash
curl -s -F "file=@sample_data/mock_scan.json" http://127.0.0.1:8000/api/v1/upload
```

Expected response (first run): `created: 13, updated: 1, total: 14` — the
duplicate Log4Shell entry on `web-prod-01.corp.local` is refreshed, not duplicated.

## Correlation & Deduplication

- Each finding gets a `correlation_signature = CVE + PluginID + Asset + Port`.
- When neither CVE nor plugin ID is present, the normalized title fills the
  plugin slot (keeps CIS baseline re-scans correlating).
- On upload every signature is matched against the registry:
  - **Match** → `last_seen` refreshed, `severity` drift updated; no duplicate row.
  - **Closed / Risk Accepted finding re-detected** → status reverts to `Open`,
    `reappeared=True`, `reappeared_count` incremented, `last_reappeared_at` set,
    and a `reappeared` alert fires.
  - **Pending Retest finding still present** → `retest_failed()`, stays open,
    `retest_failed_count` incremented. `original_created_at` is NEVER reset.
  - **Pending Retest finding absent from a scan covering its asset** →
    `retest_passed()`, finding closed, `retest_passed_at` recorded.

## SLA Policy (Dynamic Matrix)

SLA days are stored per `severity × asset_classification` in the
`sla_configurations` table (admin-editable in the Administration screen, or
`PATCH /api/v1/sla/config`). Defaults:

| Severity \ Classification | Critical | High | Medium | Low |
| ------------------------- | -------- | ---- | ------ | --- |
| **Critical**              | 7        | 10   | 14     | 14  |
| **High**                  | 14       | 14   | 21     | 21  |
| **Medium**                | 30       | 30   | 45     | 45  |
| **Low**                   | 60       | 60   | 90     | 120 |

- Assets are auto-classified from hostname keywords (`dc/db/prod` → Critical,
  `web/app/gw` → High, `file/build/dev` → Medium, else Low); overridable on the
  Assets screen.
- `due_date = original_created_at + sla_days` — retests, reappearances and
  matrix edits shift the deadline but never reset finding age.
- Status is computed dynamically: `On Track` / `Approaching` / `Breached` /
  `Under Exception` / `Resolved`.
- A finding whose SLA is `Approaching`/`Breached` **and** whose last scan is
  stale (no `last_seen` in the last 7 days) is moved to `Pending Retest` by
  `refresh_sla_for` (runs on every upload/status change/`sla/refresh`).
- Changing a matrix cell via the admin UI triggers `recompute_all_slas()`.

## Retest & Validation Workflow

1. Finding enters `Pending Retest` automatically when its SLA is at risk and
   the scan data is stale.
2. Analyst rescans the asset and uploads the new report:
   - signature still present → `retest_failed` (status back to `Open`, age kept);
   - signature absent on a covered asset → `retest_passed` (`Closed`).
3. Manual `Pending Verification` status is also supported for out-of-band
   evidence; the Retest & Validation screen shows the pending queue and the
   retest history.

## Risk Exceptions

- `PATCH /api/v1/findings/{id}/exception` with `{risk_id, reason, granted_by}`
  puts the finding "Under Exception" — the breach flag is cleared while active.
- `DELETE /api/v1/findings/{id}/exception` lifts it and immediately re-evaluates
  the SLA state (breach returns if still past due).
- The Exceptions screen lists active exceptions with the linked risk ticket.

## API Reference

| Method | Endpoint                         | Description |
| ------ | -------------------------------- | ----------- |
| GET    | `/`                              | Dashboard UI (Jinja2 template) |
| POST   | `/api/v1/upload`                 | Ingest JSON/XML scan report (multipart `file`) |
| GET    | `/api/v1/findings`               | Paginated findings — `search`, `status`, `severity`, `source`, `reappeared`, `sort`, `page`, `page_size` |
| GET    | `/api/v1/findings/{id}`          | Fetch one finding |
| PATCH  | `/api/v1/findings/{id}`          | Enrich (owner/notes/title) and/or transition `{"status": "In Progress"}` |
| POST   | `/api/v1/findings/{id}/exception`| Link a risk exception `{risk_id, reason, granted_by}` |
| DELETE | `/api/v1/findings/{id}/exception`| Lift the risk exception |
| GET    | `/api/v1/stats`                  | Dashboard aggregates (severity, status, SLA compliance) |
| GET    | `/api/v1/assets`                 | Asset registry with classification and finding counts |
| POST   | `/api/v1/assets`                 | Register/classify an asset |
| PATCH  | `/api/v1/assets/{id}`            | Update classification/owner (recomputes SLAs) |
| GET    | `/api/v1/sla/config`             | Current SLA matrix |
| PATCH  | `/api/v1/sla/config`             | Bulk-update matrix cells `{updates: [{severity, asset_classification, sla_days}]}` |
| POST   | `/api/v1/sla/refresh`            | Re-evaluate SLA flags + pending-retest moves |
| POST   | `/api/v1/sla/recompute`          | Recompute all due dates from the matrix (anchored to `original_created_at`) |
| GET    | `/api/v1/retests`                | Pending retest queue + retest history |
| POST   | `/api/v1/retests/evaluate`       | Force re-evaluation of the queue |
| GET    | `/api/v1/exceptions`             | Active risk exceptions |
| GET    | `/api/v1/reports`                | Executive summary (close time, aging, uploads, reappearances) |
| GET    | `/api/v1/uploads`                | Scan upload history with per-upload correlation counters |
| GET    | `/api/v1/notifications`          | Simulated webhook/email outbox feed |
| POST   | `/api/v1/notifications/test`     | Manually dispatch a test alert |
| GET    | `/api/v1/health`                 | Liveness probe |

Try every endpoint interactively in Swagger at `/docs`.

## Supported Scan Formats

- **Nessus v2 XML** (`.nessus`): `ReportHost`/`ReportItem` with `plugin_name`,
  `pluginID`, `severity` (0–4), `cvss_base_score`, `<cve>`, `port`.
- **OpenVAS / Greenbone XML**: `result` elements with `name`, `host`, `threat`,
  `severity` (0–10), nested `nvt` with `cve`/`cvss_base`.
- **JSON**: flat lists, `{"findings": [...]}`, `{"hosts": [...]}` — key-tolerant
  (`title`/`name`/`plugin_name`, `host`/`asset`/`ip`, `plugin_id`/`pluginid`).
- Severity strings are normalized (`Critical`/`HIGH`/`4`/`9.8` → canonical levels).

## UI Screens

Dashboard · Findings (with REAPPEARED tags) · SLA Tracking · Retest & Validation ·
Exceptions · Assets · Reports · Administration (SLA matrix editor).

## Project Structure

```
assurance_platform/
├── app/
│   ├── __init__.py          # package metadata
│   ├── main.py              # FastAPI app, routes, correlation engine, seeding
│   ├── database.py          # SQLAlchemy engine + session
│   ├── models.py            # Finding, Asset, SLAConfiguration, ScanUpload, Notification
│   ├── schemas.py           # Pydantic v2 API schemas
│   ├── parsers.py           # JSON/XML scan report parsing + correlation signatures
│   ├── sla_engine.py        # SLA matrix, retest/lifecycle rules, alert dispatch
│   └── templates/
│       └── index.html       # 8-screen dark operations dashboard (Tailwind + Chart.js)
├── sample_data/
│   └── mock_scan.json       # sample Nessus-style report for testing
├── data/                    # created at runtime (SQLite DB lives here)
├── requirements.txt
└── README.md
```

## Simulated Alerting

Alerts are persisted in the `notifications` table and rendered in the
dashboard; they are also logged to stdout as `[MOCK WEBHOOK]` / `[MOCK EMAIL]`.
To wire real integrations, replace `dispatch_notification()` in
`app/sla_engine.py` with an HTTP POST to your ticketing API or SMTP call —
the signature already carries event type, level, subject, message and context.

## Development Notes

- SQLite file lives at `data/assurance.db`. Delete it to reset the demo dataset.
- Dashboard requires internet access for the TailwindCSS and Chart.js CDNs.
- UI auto-refreshes every 60s (toggleable) and reflects SLA breaches live.
- `original_created_at` is immutable — it drives all SLA age calculations.

# Assurance Finding Lifecycle & SLA Management Platform

**Status**: ✓ Production Ready | **Assets**: 1,208 loaded | **Server**: http://localhost:8000

## Login Credentials
- **Username**: `Assurance Head`
- **Password**: `admin`

---

A full-stack platform for ingesting vulnerability scans, correlating findings across
scans (reappearance tracking), and enforcing firewall-style rule-based SLA policies —
built for Banque Misr.

## Tech stack

| Layer      | Technology                                                     |
|------------|----------------------------------------------------------------|
| Backend    | Python 3.10+, FastAPI, Uvicorn                                 |
| Database   | SQLite + SQLAlchemy ORM (`data/assurance.db`)                  |
| Parsing    | Pandas + OpenPyXL (.xlsx) / CSV                                |
| Auth/RBAC  | JWT (python-jose) + bcrypt with `admin` / `read_write` / `read_only` roles |
| Frontend   | Jinja2 + TailwindCSS (CDN) + Vanilla JS + Chart.js (CDN)       |

## Quick start

```bash
cd assurance_platform
python -m venv venv
# Windows: venv\Scripts\activate   |  macOS/Linux: source venv/bin/activate
pip install -r requirements.txt
python load_assets.py  # Load 1,208 assets from Asset_Inventory.xlsx
uvicorn app.main:app --reload --port 8000
```

Open http://localhost:8000 and login with:
- **Username**: `Assurance Head`
- **Password**: `admin`

The platform auto-loads assets on startup and is ready to receive VA and CIS scan uploads.

## VA Scan import format

The parser accepts the classic VA export columns (matches
`VA_C1_2026-03-16_R1_HQ-App-Servers-A.xlsx`):

| Column                            | Mapped to                  |
|-----------------------------------|----------------------------|
| `Plugin Name`                     | `plugin_name`              |
| `Severity`                        | `severity`                 |
| `IP Address`                      | `ip_address`               |
| `Protocol` / `Port`               | `protocol` / `port`        |
| `CVE`                             | `cve`                      |
| `First Discovered` / `Last Observed` | `first_discovered` / `last_observed` |
| `Description`                     | `description`              |
| `Steps to Remediate`              | `remediation_steps`        |
| `Plugin Output`                   | `plugin_output`            |
| `Vulnerability Priority Rating`   | `vpr_score`                |

Dates are parsed from Excel serials, timestamps or strings and are always
normalized to naive UTC, so offset-aware CSV values (e.g. `2026-03-16 07:45:12 +0000`
or an ISO `+03:00` suffix) never crash the SLA math.

If the scan export also carries asset columns, they are picked up automatically
and used to create or update the inventory: `Hostname`/`Asset Name`, `Asset Type`/`Type`,
`Scope`, `Environment`, `Site`, `Owner Team`, `Asset Code`, `Asset Status`.
Rows without asset info (and IPs not already in inventory) attach to the fallback
**Default Asset (AST-0000)** and a warning banner is shown.

Upload via **Findings → Upload Report** or **Audit Files → Upload Report**
(VA Scan or Asset Inventory).

To start a fully clean import, log in as `admin`, open **Audit Files → Danger Zone**
and delete all findings (or findings + assets). Users and SLA rules are kept.

## Correlation engine

* Assets are looked up by **IP address**. Unmapped IPs attach to the fallback
  **Default Asset (AST-0000)** and a warning banner is shown.
* Correlation key: `(IP Address + Plugin Name + Port + Protocol)`.
  * Open finding re-seen → only `last_observed` is refreshed.
  * Closed finding re-seen → reopened as `Open`, `is_reappeared=True`,
    `reappeared_count += 1`; `first_discovered` / SLA age is **preserved**.
  * New finding → created with `original_created_at = First Discovered`.
* A finding history + audit file record is created for every upload.

## SLA engine

Rules are evaluated **top-to-bottom, first match wins** (firewall style).
Match fields: `Source`, `Severity`, `Asset Scope`, `Asset Type`, `Environment`
(where `Any` matches anything). On match:

```
due_date = original_created_at + sla_days
SLA status = Under Exception   if active exception exists
           else SLA Exceeded   if now > due_date and status != Closed
           else Approaching    if elapsed / sla_days >= approaching_pct / 100
           else Within SLA
```

Closed findings are set to `sla_status = Closed`. Once the `retest_pct`
threshold is crossed, open findings are automatically flagged `retest_status = Pending`.
SLAs recalculate automatically on new upload, rule create/toggle/reorder, or via
**Settings → Recalculate**.

## Roles

| Capability             | admin | read_write | read_only |
|------------------------|:-----:|:----------:|:---------:|
| View dashboards/findings/reports | ✔ | ✔ | ✔ |
| Upload scans / inventory         | ✔ | ✔ | — |
| Assign owner / retest / close    | ✔ | ✔ | — |
| Link risk IDs, add exceptions    | ✔ | ✔ | — |
| SLA policy rules & reordering    | ✔ | — | — |
| User management                 | ✔ | — | — |

## Project layout

```
assurance_platform/
├── app/
│   ├── __init__.py
│   ├── main.py            # FastAPI app, UI routes, APIs, ingestion
│   ├── database.py        # SQLAlchemy engine & session
│   ├── models.py          # User, Asset, Finding, SLARule, ExceptionRecord, AuditFile…
│   ├── schemas.py         # Pydantic schemas
│   ├── auth.py            # bcrypt + JWT + RBAC dependencies
│   ├── parsers.py         # VA-scan & inventory Excel/CSV parsing
│   ├── sla_engine.py      # first-match-wins rule engine & SLA calculator
│   └── templates/         # base, login, dashboard, findings, sla_tracking,
│                          # assets, settings, retests, exceptions, audit, reports
├── sample_data/
│   └── seed_data.py       # seeds admin, default SLA rules, sample assets/findings
├── data/                  # assurance.db (created at runtime)
├── requirements.txt
└── README.md
```

## Security notes

* JWT is stored in an HttpOnly cookie; bcrypt hashes passwords.
* Change `ASSURANCE_SECRET_KEY` via environment in production.
* `read_only` users cannot mutate data; all mutation routes enforce RBAC.

## Tests

`smoke_test.py` runs an end-to-end suite (auth/RBAC, dashboard APIs, correlation,
reappearance logic, SLA engine, uploads, exports) and `page_render_test.py`
verifies every page renders for each role. Both use FastAPI's TestClient:

```bash
.\venv\Scripts\python.exe smoke_test.py        # 40 assertions
.\venv\Scripts\python.exe page_render_test.py  # 10 page renders
```
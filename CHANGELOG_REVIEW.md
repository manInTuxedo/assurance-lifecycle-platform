# Assurance Platform — Review Changes

Everything below is a **change to the existing code**. No file was deleted, no module was
renamed, and the project structure is exactly the same: `app/main.py`, `app/models.py`,
`app/parsers.py`, `app/sla_engine.py`, `app/startup.py`, `app/templates/*`.
The only addition is `app/static/`, which holds the two front-end files the app used to
pull from the internet.

---

## 1. Correctness — things that were not doing what they claimed

### 1.1 The asset inventory could never load
`SessionLocal` is created with `autoflush=False`, so a row added with `db.add()` is not
visible to the next query until a flush. Both asset-code generators asked the database
for "the next code" once per row, got the same answer every time, and the import died on
`UNIQUE constraint failed: assets.asset_code`. `startup.py` swallowed the error and
skipped the row instead.

**Change** — `AssetCodeAllocator` in `app/startup.py` reads the existing codes once and
then hands out codes from memory, and `ingest_assets()` / `load_asset_inventory()` use it.
The same pattern was applied to finding and exception codes (`SequentialCodeAllocator`).

*Result:* the full inventory imports — 1,182 assets, 0 skipped. Before the change: 0 imported.

### 1.2 Only one worksheet of the inventory was read, and Crown Jewel was inverted
`parse_asset_inventory()` read the first sheet only, so every network device was missing.
The Crown Jewel test was a substring test, so `"Not CJ"` matched `"CJ"` and every asset
became a Crown Jewel.

**Change** — the parser now walks every sheet whose name contains *inventory*, deduplicates
by IP, and `build_scope()` compares the flag exactly. Scope became a multi-value field,
e.g. `Crown Jewel, PCI, Application`, because an asset really is in several scopes at once.

*Result:* the 208 infrastructure devices appear alongside the 974 application servers, with
their real types (Switch, Router, F5, ESXi, Storage, EDR, PAM) and correct scopes.

### 1.3 Nothing ever closed
The ingestion loop only looked at rows **present** in the file, so a vulnerability that had
been remediated simply stayed open forever. Across three assessment cycles, hundreds of findings
disappeared from the reports and the platform closed **zero** of them.

**Change** — `ingest_scan()` was restructured into three passes:

1. correlate every row in the file (new / updated / reappeared);
2. **closure pass** — for every IP the assessment covered *with working credentials*, any
   open finding that is not in the file is closed automatically;
3. record the assessment coverage of each asset.

*Result:* 679 findings closed automatically across the 16 reports, verified against the
ground-truth file (see §5).

### 1.4 "No finding" was treated as "clean"
This is the reason §1.3 could not simply be switched on. Tenable emits one
**Nessus Scan Information** row per host it reached, and its Plugin Output says
`Credentialed checks : yes …` or `no`. The old code deleted those rows as noise.

**Change** — `parsers.assessment_coverage()` reads that row and the platform now
distinguishes three states per asset, stored on `Asset`:

| state | meaning | may findings be closed? |
|---|---|---|
| **Assessed** | credentialed pass succeeded | yes |
| **Inconclusive** | host reached, credentials failed | no |
| **Not Assessed** | host never appeared | no |

A fourth, derived state — **Stale** — flags an asset last assessed more than 30 days before
the newest cycle. A clean result from an old cycle is not evidence about today.

### 1.5 VA rows on uncredentialed hosts were thrown away
The old code skipped every row on a host whose credentialed check failed. Those findings are
real; what the failed credentials remove is the ability to prove *absence*.

**Change** — all rows are ingested; the credential flag governs closure only.

### 1.6 CIS results were never read, and severity was destroyed
A CIS export contains `Result: PASSED | FAILED | WARNING` in the Plugin Output. The old code
ignored it and overwrote `severity` with the words `Failed` / `Passed` / `Manual Check`,
which broke every SLA rule that matches on severity.

**Change** — `parsers.cis_result()` reads the result (falling back to the severity column),
the verdict is stored in a new `compliance_result` field, and `severity` keeps the real
Tenable value. A control that now **passes** is not a finding — it is evidence, and it
closes the previous failure with full provenance.

### 1.7 Upload order changed the answer
Re-uploading an older file could roll a finding backwards.

**Change** — `Last Observed` is the authority everywhere. An older file can still contribute
an earlier First Discovered date, but it can never move state forwards or close anything a
newer assessment has already seen.

### 1.8 The platform invented assets out of scan rows
A scan row says nothing about ownership, environment or business scope, so a guessed asset
silently received the wrong SLA.

**Change** — unmapped IPs go to the **Default Asset (AST-0000)** only. When the inventory
later covers those IPs, `relink_unmapped_findings()` moves the findings across automatically,
and the dashboard shows the backlog as a work queue.

### 1.9 SLA rules could not match a multi-value scope
`_matches()` was an equality test, so a rule for `Crown Jewel` never matched an asset whose
scope is `Crown Jewel, PCI`.

**Change** — `scope_values()` splits the field and scope matching is a membership test. An
unmapped finding matches the scope `No Asset`, which a rule can target deliberately.

### 1.10 The SLA clock stopped under an exception
An exception hid the due date entirely, so the day it expired nobody knew where the finding
actually stood.

**Change** — the due date and the age keep being calculated; only the reported status becomes
`Under Exception`. The moment the exception ends, the true position is already there.

### 1.11 The retest queue filled up with everything
The engine flagged any finding past the retest threshold, including findings that were
already months overdue — almost every open finding sat in "Pending Retest".

**Change** — the engine flags a finding only while it is still **inside** its SLA window, and
it can withdraw a flag it raised itself (`retest_auto_flagged`). A retest a person requested
is never withdrawn automatically.

*Result:* 46 findings pending retest — actual work, not noise.

### 1.12 Duplicate rows inside one file created duplicate findings
Same `autoflush=False` cause as §1.1.

**Change** — findings created during an import are tracked in memory for the rest of that import.

---

## 2. Assurance model — "Risk Accepted" removed

This platform tracks assurance findings; it does not run a risk-acceptance process. Every
trace of `Risk Accepted` was removed — the lifecycle status, the dashboard stage, the two
templates and the API defaults.

Exceptions are now **technical decisions** and require:

* a reason from a fixed list — Compensating Control, Vendor Fix Not Available,
  Change Window Required, Business Downtime Constraint, End-of-Life Replacement Planned,
  False Positive (Validated), Not Applicable to Configuration;
* a written justification (rejected below 10 characters);
* optional compensating control, approval reference, start date and expiry.

**New scoped-exception workflow** (`/api/exceptions/controls`, `/targets`, `/scoped`):
pick a control → the platform lists every IP it is currently failing on → tick the ones the
decision covers, or take all of them, and optionally cover **future occurrences**. A future
decision is stored as a control-level record and applied automatically to matching findings
in later assessments (`apply_future_exceptions()`). Exceptions can be revoked, and they
expire on their own.

---

## 3. Closure provenance

Every closed finding now records *how* it was closed:

* `Closed — automatic (validated by ASM-0016 (VA_C3_…xlsx))` — an assessment proved it gone;
* `Closed — by <user>` — a person closed it, including a validated retest.

Stored as `closed_at`, `closed_by`, `closure_method`, `closure_evidence`, shown in the
findings list, the detail drawer and the CSV export.

---

## 4. Performance and data-integrity fixes

| Problem | Change |
|---|---|
| `/api/assets` loaded every asset and walked `asset.findings` per row (one query each) | server-side pagination + two grouped count queries |
| `/api/findings` returned up to 200 rows with no total, so every count on screen was wrong | server-side pagination returning `total`, `page`, `pages` |
| Findings sorted alphabetically — `Critical` after `High`, `Info` in the middle | explicit severity and SLA rank ordering, worst first |
| Asset-side filters joined the `assets` table once per filter (cartesian product) | one join for all asset filters |
| Reports page charts were computed in the browser from the first page of findings | new `/api/reports/summary` aggregates in SQL |
| Dashboard trend was anchored on "today" and was empty whenever the last upload was not this month | the window follows the data |
| Filter dropdowns were hard-coded and offered values that do not exist in the data | new `/api/filters` endpoint feeds every dropdown from the database |
| A new column on an existing database crashed with "no such column" | `ensure_schema()` adds missing columns in place on boot |

---

## 5. Verification

All 16 assessment reports (12 VA + 4 CIS) plus the inventory were imported end to end and
checked against the ground-truth file:

* 2,599 tracked findings — **2,559 match exactly** (98.5%).
* All 40 differences are cases where the platform is right and the expectation file is not:
  the host is absent from that cycle, or the credentialed check failed, so absence proves
  nothing and the platform correctly refuses to close.
* 1,182 assets loaded, 0 skipped, 0 unmapped IPs, 97 reappearances detected,
  679 automatic closures.

---

## 6. Access control — who can see and change what

The platform had three fixed roles (`admin`, `read_write`, `read_only`) applied globally: a
user who could edit anything could edit everything, including the SLA policy.

**Change** — access is now granted **per page**. Every account gets one of three levels on
each of the eight pages:

| level | means |
|---|---|
| No access | the page is hidden from the navigation and the route redirects away |
| View only | the page opens; every button, filter action and API write is refused |
| View & edit | full use of that page |

* `admin` is a role, not a set of rows: an administrator always has full access and is the
  only one who can manage accounts.
* Enforcement is server-side on every route — `module_read()` / `module_write()` in
  `app/auth.py` — so hiding a button is a courtesy, not the control.
* The platform refuses to delete, disable or demote the last administrator, and an account
  cannot delete itself.
* Accounts can be disabled without being deleted; a disabled account cannot authenticate.
* Passwords are bcrypt-hashed; the login records the last sign-in.

**Settings → Users & Access** is a matrix: users down the side, pages across the top, one
dropdown per cell that saves the moment it changes. Two accounts ship by default:

* `admin` / `admin` — administrator.
* `analyst` / `analyst` — works the findings queue and validates retests, reads everything
  else, and cannot see the SLA policy or the user list at all. It exists so the model is
  visible without configuring anything.

---

## 7. SLA policy — verified end to end

The policy is a firewall-style ordered list, and every operation was tested against the
full dataset:

| operation | result |
|---|---|
| Add a rule | inserted **above** the catch-all, then 3,002 findings recalculated |
| Edit a rule | saved and 3,002 findings recalculated |
| Reorder | recalculated; the numbers move because a different rule now matches first |
| Enable / disable | recalculated |
| Delete | the ordering closes up, then everything recalculates |
| Delete the catch-all | refused — it is what guarantees every finding has an SLA |
| Move the catch-all | refused — it must stay last |

Two bugs were fixed here:

* a new rule was appended **below** the catch-all, where it could never match, because the
  catch-all matches everything and the first match wins;
* reordering could push the catch-all off the bottom, leaving findings with no rule at all.

The rules table now shows a **Matches** column — how many open findings each rule currently
governs. A rule sitting under a broader one reads `0`, which is how you spot a shadowed rule
instead of wondering why it does nothing. A worked example on the shipped dataset:
adding *VA / Medium / Crown Jewel / 7 days* below *VA / Medium / Any / 60 days* matched 0;
moving it up three places matched 337 findings and moved SLA Exceeded from 1,710 to 1,740.
Deleting it returned both numbers exactly.

---

## 8. The dataset

The inventory and the assessment reports that ship with the platform are **generated** —
company, applications, hostnames, IP plan, owners and results are all invented. Nothing
comes from a real estate.

* `Asset_Inventory.xlsx` — 974 application servers + 208 infrastructure devices = 1,182 assets,
  in the two-sheet format the parser expects.
* 12 VA reports — 4 scan jobs × 3 monthly cycles (15 Jun, 20 Jul, 17 Aug 2026), Tenable's
  18-column export, one **Nessus Scan Information** row per reached host.
* 4 CIS reports — 2 benchmarks × 2 cycles, with `Result: PASSED | FAILED | WARNING`.
* A ground-truth workbook for checking the platform, which is never uploaded.

The set contains deliberate traps: hosts that were never scanned, hosts whose credentials
failed, findings that disappear and come back, and findings that pre-date the first cycle.

---

## 9. Interface

**Dashboard — rebuilt** around the approved mockup: six KPI cards with icons, the lifecycle chain,
the Aging & SLA trend (stacked SLA bands plus a total-open line), the Retest & Validation
donut, assessment coverage, the latest assessment, open-by-severity, a filterable and
paginated Recent Open Findings table, the exception register extract, and the data &
workflow overview.

**Other pages — same layout, tidied up.** Pagination and honest totals on every table,
multi-value scope chips, coverage state on the asset register, the exception wizard,
"showing N of M" wherever a list is capped, dynamic filters, and a compliance/closure
column where it was missing.

**Three platform-level changes:**

* **Light is the default theme, and the switch is in the top bar** — a labelled Dark/Light
  control, remembered per browser. Switching reloads the page once so the charts repaint in
  the new palette instead of half-updating.
* One heading and card style across every page, and a horizontal-overflow fix: a wide table
  now scrolls inside its own card instead of pushing the whole page sideways.
* Tailwind and Chart.js are served from `app/static/` instead of a CDN. The platform is
  meant to run on a closed network — it previously rendered unstyled with no internet.

---

## 10. Second review pass

### 10.1 Signing out returned 405
The sidebar posts a form to `/logout`, but the route was registered for `GET` only, so the
sign-out button answered **405 Method Not Allowed** and the session never ended.

**Change** — `/logout` accepts GET and POST, redirects with 303, and the cookie is cleared
on the same path it was set on. Verified end to end: sign in → open a page → sign out →
the page redirects to the login screen, the API answers 401, and signing in again works.

### 10.2 Re-uploading an old cycle resurrected everything it had closed
The staleness test compared the incoming row against the finding's **Last Observed**. For a
*closed* finding those two dates are equal by construction — the file that closed it is the
last one that saw it — so re-uploading an older cycle reopened 326 findings as REAPPEARED.

**Change** — for a closed finding the bar is the **closure** itself: an observation dated on
or before `closed_at` is not new evidence and changes nothing.

*Verified on the full dataset:* import all 16 reports → 2,323 open / 679 closed / 97
reappeared. Re-upload the oldest cycle → **identical**. Re-upload the newest cycle →
**identical**. Upload order genuinely does not matter.

### 10.3 Uploading, reworked
* The Findings page uploads **assessments only** — the asset-inventory option was removed
  from it. The inventory is uploaded from the Assets page, and the server enforces that
  separately (Findings-write for assessments, Assets-write for the inventory).
* **No VA/CIS dropdown.** Which one a file is comes from its content, so a mixed selection
  sorts itself out.
* **Many files at once**, or a whole folder. Non-spreadsheets are ignored, the ground-truth
  file is skipped, and the batch is processed oldest first so the per-file counts read
  correctly. The result lists every file with what it changed.

### 10.4 Every account changes its own password
`POST /api/me/password`, reachable from the key icon beside the account name. The current
password is required; the new one must be at least 4 characters, typed twice, and different
from the old one. An administrator resetting somebody else's password stays a separate
action in Settings → Users.

### 10.5 One account ships
Only `admin` / `admin`. Everything else is created in Settings → Users & Access, one level
per page.

### 10.6 Integrity sweep

Run against the shipped database:

| check | result |
|---|---|
| every finding has an asset · no duplicate correlation keys · unique codes | pass |
| every closed finding has provenance, a closure date, no due date | pass |
| every open finding matched a rule; due date = first discovered + rule days | pass |
| nothing is marked Exceeded before its due date | pass |
| findings under exception keep a due date and are not chased for retest | pass |
| reappeared findings kept their original discovery date | pass |
| ground truth: 2,559 of 2,599 findings match (98.5%) | pass |

One check flagged automatic closures on hosts that read **Inconclusive** today. Those
closures were made at cycle 2, when the host *was* credentialed; the host only lost its
credentials at cycle 3. The provenance string names the cycle-2 assessment, which is the
point of recording it — the platform is right and the check was comparing a historical
decision against today's coverage.

---

## 11. Running it

```
pip install -r requirements.txt
uvicorn app.main:app --reload
# http://127.0.0.1:8000   —   admin / admin
```

The package ships with the data already loaded: 1,182 assets, 3,002 findings from 16
assessments, 679 automatic closures, 97 reappearances and 22 exceptions. The raw files are
in `sample_reports/`, so the whole thing can be wiped from Settings → Maintenance and
re-imported from scratch.

Python 3.11 · FastAPI · SQLAlchemy · SQLite (`data/assurance.db`) · Jinja2 templates
rendered server-side · Tailwind CSS + Chart.js on the front end. No external service, no
credentials to any production system, no AI in the application.

To rebuild the database from scratch, delete `data/assurance.db` and restart — the asset
inventory reloads on boot, then upload the assessment reports.

---

## 12. Nothing from the report is lost, and Reports gained a time dimension

### The full record page
The detail drawer showed a chosen subset of the fields. Some columns the parser
read were never stored at all - `See Also`, `Exploit?`, `Exploit Ease`,
`Vuln Publication Date`, `Patch Publication Date`, `DNS Name` - so the answer to
"is everything from the sheet here?" was no.

The finding now keeps the **whole original row** as JSON (`findings.raw_row`,
plus `findings.source_file`), captured before the column names are normalised,
in the sheet's own order. It is written on creation and replaced whenever newer
evidence arrives.

* `GET /findings/{id}/record` - a full page showing the untouched report row,
  every long text block in full, every column of the finding record grouped for
  reading, the asset and the exception. A field added to the model later cannot
  fall off the page: anything not in a named group is listed under
  "Other stored fields".
* The drawer keeps the summary, adds Source, Compliance result, CVE/VPR, the
  file the evidence came from, the report row itself, and a link to the page.

### Why Description is empty on CIS findings
A VA export carries 18 columns and one of them is Description. A **CIS export
carries 10 and Description is not one of them** - the control statement is the
finding's own name, and the reasoning, the actual value and the policy value all
sit in Plugin Output. So `—` there was truthful, not a bug. The interface now
says so in words instead of showing a dash, on both the drawer and the record
page.

### What moved in the period
The Reports page described the estate as it stands today and had no time
dimension at all, so it could not answer "in the last 30 days, what was fixed,
what was not, what came back".

`GET /api/reports/movement` was added, with a period control on the page
(Last 30 days / Last 90 days / any two dates). Every number is anchored on a
date the platform recorded when the event happened, never on the upload order:

| Number | Anchored on |
|---|---|
| Fixed | `closed_at` - only a credentialed assessment sets it |
| Came back | `reappeared_at` - **new column**, written when a closed finding is reopened |
| Newly discovered | `first_discovered` |
| Still open | existed by the end of the period and nothing has closed it |
| Deadlines passed | `due_date` inside the period, still open |

The section also lists the individual findings behind Fixed and Came back, each
linking to its full record.

Every chart on the page now carries a one-line explanation of what it counts,
including the fact that an asset in several scopes is counted under each of them.

### Also in this pass
* `smoke_test.py` was rewritten against the current design - 72 checks covering
  ingestion, closure provenance, the coverage tri-state, reappearance, the SLA
  policy, exceptions, per-page access, own-password change and the reset - and
  it now uses the multi-file upload API.
* The navigation highlights the page you are on by module, so a detail page no
  longer clears the highlight.

---

## 13. Two filters that narrow the whole platform, and a per-account data reach

The header used to carry a scope dropdown that only the Findings and Assets
pages honoured, and a relative-time dropdown (Last 30 / 60 / 90 days) that
nothing honoured at all — every page already has its own period control, so it
was a second, contradictory answer to the same question.

Both were replaced.

### The two controls

| Control | What it does |
|---|---|
| **Scope** | Application, Crown Jewel, PCI, Infrastructure — read from the inventory, not hard-coded |
| **Assessment** | VA or CIS |

Picking either one narrows **every page**: the dashboard and all of its charts,
Findings, SLA Tracking, Retest & Validation, Exceptions, Assets and Reports.
Not hidden — *absent*. Every total, every chart, every export and the global
search are recalculated inside the selection, so the number at the top of a
card always matches the list underneath it. Settings is deliberately exempt:
the SLA policy and the user list are global by nature.

An asset commonly carries several scopes in one cell — `Crown Jewel, PCI,
Application` is one asset, three scopes — so matching is an exact membership
test on the comma-separated value, never a substring. A scope called `Non PCI`
could not satisfy a filter for `PCI`.

The selection travels in a cookie and is applied by a single dependency, so a
page cannot forget to honour it. Changing either control reloads, which is also
what repaints the charts.

### The grant behind the filter

Beside the per-page level (No access / View / View & edit) each account now
carries two more dimensions, set by an administrator on
**Settings → Users & Access → Data reach**:

* **Business scopes** — tick any combination
* **Assessments** — VA, CIS, or both
* **Unscoped / Default Asset** — the hosts the inventory has not explained yet,
  and the Default Asset that unmapped IPs wait on. Ticked by default on a new
  account, because a brand-new IP belongs to nobody until the inventory says
  otherwise, and refusing it would drop report rows on the floor.

An administrator has no stored grant at all — the role is the answer.

A restricted account is never offered a value it does not hold: the header
dropdowns are rendered from the server and contain only what was ticked.
Forging the cookie changes nothing, because the selection is intersected with
the grant on every single read. Asking for a finding by id that lies outside
the grant returns **404, not 403** — 403 would confirm the row exists, which is
exactly what a scope restriction is there to withhold.

### The grant governs writing too — the filter never does

This is the important distinction.

* Uploading a **CIS** file with an account granted **VA only**: the file is not
  half-imported. Nothing in it exists for that account, and the upload says so.
* Uploading a report covering **Infrastructure** with an account granted
  **Application only**: those rows are ignored — and, just as importantly, the
  hosts behind them drop out of the closure pass, so the account cannot close a
  finding it is not allowed to see. The result reports how many rows were left
  behind rather than pretending they were imported.
* Uploading an **inventory** row that would move an asset into, or out of, a
  scope the account does not hold is refused for the same reason — otherwise
  the restriction could be lifted by uploading a file.
* An administrator filtered to Application who uploads a full report imports
  **all of it**. The header is a way of looking, not a way of working.
* Bulk actions are re-checked server-side against the grant, not against the
  ids the browser sent, and report how many were skipped.

### Verified

| Check | Result |
|---|---|
| Each scope filter against a direct SQL count — findings, assets, open findings | exact on all four scopes |
| Assessment filter, and scope + assessment combined | exact |
| Restricted account totals against SQL | exact |
| Cookie forged to a scope outside the grant | ignored, falls back to the granted set |
| Finding outside the grant, by id: read / write / bulk / global search | 404 · 404 · skipped · no result |
| CIS file uploaded by a VA-only account | rejected, database unchanged |
| Infrastructure file uploaded by an Application-only account | 327 rows skipped, 0 closed, database unchanged |
| Same file as administrator, filtered to Application | 0 skipped, 327 updated, 203 hosts assessed |
| Factory reset then re-import of all 17 files | 3,002 findings · 2,323 open · 679 closed · 97 reappeared — identical to the shipped state |
| Integrity sweep | 17 of 17 pass |

### Also in this pass

* **Users & Access and Maintenance are administrator-only.** SLA Policy stays
  visible to anyone granted the Settings page, read or write.
* The KPI strip and the retest doughnut used to require the Dashboard page even
  when they were being drawn on Reports or on Retest & Validation, which locked
  accounts out of pages they had been granted. They now accept any of the pages
  they actually appear on.
* Dashboard panels whose page an account cannot read say so in one line instead
  of failing silently and leaving an empty box.
* The account column of the access matrix is pinned, so Disable / Reset /
  Delete stay reachable however many pages are listed.
* An account left with nothing ticked is flagged in the editor — it would see
  an empty platform, which is almost never what was intended.

---

## 14. A test pass over the finished platform

Eight problems were found by attacking the platform rather than using it.
Every one is fixed and covered by a test.

### 1. Over a thousand database round trips for one page

`/api/sla-tracking` issued **1,039 queries** per request and the CSV export
**1,125** — one extra query per finding, to fetch the asset that was about to
be printed next to it. Alone each page still answered quickly, so it never
looked broken; with several people on the platform at once it degraded badly.

The asset now travels with the query that needs it. Both endpoints are down to
**3 queries**, and the same was done on the findings list, the dashboard, the
exception register and the movement report.

### 2. SQLite left on its defaults

Three settings that matter the moment more than one person is connected:

| Setting | Was | Now | Why |
|---|---|---|---|
| Connection pool | 5 | 20 (+20 overflow) | Everyone queued on five connections |
| Journal | rollback | **WAL** | A long upload froze every reader for its whole duration |
| Busy timeout | none | 30s | Two writes at the same instant failed instead of waiting |

### 3. An exception that was revoked was never actually released

Revoking cleared the link on the finding and asked the engine to re-rate it —
but the session runs with autoflush off, so the engine re-read the exception
row it was in the middle of revoking and still saw it as active. The finding
stayed **Under Exception** for ever: quietly absent from every breach report,
with no way to tell from the screen. It now flushes first and drops straight to
its true state (usually Past Due).

### 4. An exception could expire in the past

Nothing stopped an exception being created with an end date already gone. It
was born retired: an approval reference on a finding that was never actually
covered. An expiry must now be in the future, and after its start date.

### 5. A lapsed exception left the finding hidden

Exceptions were marked Expired when the register was opened, but the findings
under them were never re-rated — so cover that ended weeks ago still read as
active cover. Expiry now releases the finding and re-rates it immediately, and
the check also runs at start-up, so a platform switched off over a weekend
comes back honest.

### 6. The wipe button did not check its own confirmation

The interface asked for a typed confirmation. The API did not: **any** request
to the reset endpoint emptied the platform, confirmation or not. It is checked
on the server now, per depth — `CLEAR FINDINGS`, `CLEAR ALL DATA`,
`RESET EVERYTHING` — so a mistyped command or a stale tab replaying a request
cannot wipe anything.

### 7. SLA rules accepted numbers that cannot mean anything

A window of `-10` days gave every matching finding a deadline before it was
discovered, so the whole set read as breached the moment the rule was saved. A
threshold of `500%` put the approaching band and the retest trigger years past
the deadline, where neither could ever fire. Both are now bounded (1–3650 days,
1–100%), on creation and on edit.

### 8. A report row with its dates the wrong way round

A row whose Last Observed is earlier than its First Discovered was stored as
given, producing a negative age and an SLA deadline before the finding existed.
The earlier date is now taken as the discovery and the later as the sighting,
whatever the columns were called; a date later than the assessment itself is
pulled back to it, because nothing can be observed after the scan ran. The
original row is still stored verbatim and shown on the full record page, so the
correction is visible rather than hidden.

### What was attacked and held

* **56 authentication and permission probes** — no session, forged tokens,
  tokens signed with another key, expired tokens, tokens naming a user that
  does not exist, a token claiming `role: admin` for an ordinary account,
  disabled accounts, self-promotion, widening your own access or data reach,
  deleting the last administrator, password rules, both logout routes.
  All held.
* **Malformed uploads** — a text file, rubbish inside an `.xlsx`, a zero-byte
  file, an empty sheet, unrelated columns, rows with no plugin name, no IP,
  unparseable dates, unknown severities, negative ports.
  Refused or absorbed, never a 500.
* **Hostile strings** — `'; DROP TABLE findings;--`, `<script>alert(1)</script>`,
  a spreadsheet formula, mixed Arabic/Japanese with an embedded null byte, and a
  5,000 character name. All stored as text; searching for them returns text.
* **Repeats** — the same file twice changes nothing; three identical rows in one
  file collapse to one finding; an old cycle uploaded after a new one does not
  rewind anything.
* **Bad API input** — page zero, negative pages, a page far past the end, page
  size zero and enormous, ids that do not exist, bodies of the wrong shape and
  bodies that are missing. No 500s; asking past the last page returns the last
  page.
* **Lifecycle** — discovered, proven gone by a credentialed assessment, kept
  open when credentials failed, reappearing with its original discovery date,
  a CIS control closing when it passes, an exception that keeps the clock
  running, a failed retest reopening and a passed retest closing as a human
  closure.

The suite now runs **90 checks** and finishes green, against its own database:
running it used to delete the one the platform ships loaded with.

---

## 15. Three more assessments: SAST, DAST and PT

The platform read two kinds of report. It now reads five, and the three new
ones are not variations on the old shape - they describe applications, not
hosts, and almost every assumption in the correlation engine had to be given a
second answer.

| | Told apart by | Correlated on | Lands on |
|---|---|---|---|
| VA | descriptive plugin name | IP + plugin + port + protocol | the host |
| CIS | control name starting `1.1` | IP + control | the host |
| **SAST** | `SAST-#####` in Finding ID | application + title + file/component + CWE | **the application** |
| **DAST** | `DAST-#####` in Finding ID | application + title + URL + OWASP category | the host behind the domain |
| **PT** | `PT-#####` in Finding ID | application + title + URL | the host behind the domain |

Type is read from the **content** of the file, as it always was. A workbook
holding all three on separate sheets is split into three separate assessments
and each is correlated on its own.

### Severity is not part of any key

A finding re-rated from High to Critical is the same finding. Its severity is
updated in place; its code, its discovery date and its age are untouched. Had
severity been part of the key, a re-rate would have closed one finding and
opened another, and the age of something nobody had touched would have reset
itself.

### Where an application finding belongs

SAST reads source code. The same defect exists on every server the application
runs on, so attributing it to one host would be arbitrary - and our own
inventory has around twenty-five servers per application, so "the asset called
X" was genuinely ambiguous. The inventory therefore gained **one row per
application**, and SAST lands there. Those rows are typed `Application` and are
excluded from the credentialed-coverage figures, where they would otherwise
read as servers nobody has ever scanned.

DAST and PT exercise a running service at a URL, which resolves to a real
machine. The inventory gained a **Domain** column so they can find it. The host
is taken from the URL - scheme, port and path stripped - never the whole URL.

An application, or a host name, the inventory has not heard of yet waits on the
Default Asset and moves across on its own once the inventory catches up. That
relinking now understands all three ways home, not just the IP.

### A Scan Date column

The reports carried no date at all. Without one there is no way to tell an old
report from a new one, which is the entire basis of closing a finding by
absence, so the generated reports carry `Scan Date` and the parser reads it.
An optional `First Discovered` is honoured when the report knows it.

### Coverage, for an application

There is no equivalent of a credentialed check - there is no host to log into.
The rule is the application: **if a report tested an application, everything it
does not mention for that application and that assessment type is gone.** An
application absent from the report proves nothing about it, and its findings
stay open. Four of our own applications were not tested in cycle 2, and their
findings correctly stayed open through it.

### Carried through the whole platform

The header filter, every dashboard chart, the SLA policy `source` field, the
exception register, the per-user assessment grants, the reports, the audit
trail and the upload path all take their list of assessments from one place, so
a sixth type would appear in all of them without another pass like this one.

The Findings drawer adapts: an application finding shows its application and
the file or URL it lives in, not an IP and a port it does not have. The full
record page gained a **Classification** group for CWE and OWASP category, and
still shows the original sheet row exactly as it arrived.

### The dataset

The reference workbook was used as a template only; every row shipped is newly
generated against **our own** applications and inventory.

| | Findings | Open | Closed by absence | Reappeared |
|---|---|---|---|---|
| VA | 2,580 | 1,983 | 597 | 97 |
| CIS | 422 | 340 | 82 | 0 |
| SAST | 834 | 633 | 201 | 112 |
| DAST | 526 | 383 | 143 | 49 |
| PT | 167 | 127 | 40 | 26 |
| **Total** | **4,529** | **3,466** | **1,063** | **284** |

Nine new report files across three cycles, plus one combined workbook that
exists to demonstrate the split. The inventory now carries 1,182 hosts and 50
applications.

### Verified

* Every SAST, DAST and PT number reconciles **exactly** against an independently
  computed expectation - totals, closures and reappearances, all three types.
* 834 of 834 SAST findings landed on an application row; 693 of 693 DAST and PT
  findings landed on a real host; **zero** application findings were left
  unmapped.
* Filtering to each of the five assessments reconciles against a direct SQL
  count, as does scope and assessment combined.
* An account granted SAST and DAST only sees 1,360 findings - matching SQL to
  the row - gets 404 on a PT or VA finding by id, and its upload of a PT file
  is refused outright.
* The integrity sweep gained ten checks and runs **26 of 26**; the test suite
  gained twenty-three and runs **114 of 114**.

---

## 16. A second test pass, over the five-source platform

Four problems, all fixed, all now covered by a test.

### 1. Deleting an SLA rule answered 500

Enabling foreign keys in the previous pass turned a silent fault into a loud
one. Every finding a rule had matched still pointed at it, so the delete was
refused by the database - and before foreign keys were enforced, the same
delete had been leaving findings quietly referencing a rule that no longer
existed. The pointer is now released first, and the recalculation that follows
gives each finding whichever rule now matches.

### 2. The SLA policy had nothing to say about SAST, DAST or PT

All 1,527 application findings fell through to the 90-day catch-all, so a
Critical code defect and a Low one had the same deadline. Eleven default rules
were added. A penetration test result gets the tightest window of the three,
because it is a proven, exploited path rather than a scanner's opinion.

| | Critical (Crown Jewel) | Critical | High | Medium |
|---|---|---|---|---|
| SAST | 10 days | 21 | 45 | 75 |
| DAST | 7 days | 14 | 30 | 60 |
| PT | — | 5 | 20 | 45 |

Every rule in the policy now governs a real set of findings, and nothing falls
to the catch-all that should not.

### 3. A second catch-all could be created, hiding the real one

Posting a rule with no fields set produced `Any/Any/Any/Any/Any` and placed it
*above* the catch-all. Being identical, it shadowed the real one completely -
an undeletable rule that nothing could ever reach, indistinguishable on screen
from the one below it. A rule that matches everything is now refused: there is
one catch-all, and it is edited rather than duplicated.

### 4. The movement report cut three findings off its own first day

"What moved between 23 July and 22 August" started at the time of day of the
newest assessment rather than at midnight, so anything discovered on the
morning of the 23rd fell outside a period the screen said it was inside. The
window now spans the whole of both days it names.

### What was driven, and held

* **The whole interface, twice** - every page in light and dark, checking for
  script errors, for sideways scroll, and for any visible table left
  unrendered. Both header filters driven through all five assessments and
  through the scopes. The detail drawer opened on each of the five sources,
  the exception wizard, both upload modals, all three settings tabs, paging,
  and the full record page for each source. **86 checks, no script errors.**
* **The application-security ingest, attacked** - a SAST row on a sheet named
  DAST (the Finding ID wins), a sheet with no Finding ID column (refused), an
  unknown `IAST-` prefix (refused), one stray row of another family inside a
  sheet (dropped, the majority decides the file), a report with no date at all
  (imported and dated), the same finding in different casing and spacing (one
  finding, not two), a URL pointing at a host nobody has registered (falls back
  to the application it names), and the same URL written four ways - plain
  http, with a port, with credentials, uppercase - all resolving to the same
  host.
* **Coverage, precisely** - a report covering two applications, then a later
  one covering only the first: the tested application had its missing finding
  closed, the untested one kept its finding open.
* **Every reported number recomputed** - the dashboard headline, the five SLA
  states, per-assessment and per-severity counts, coverage, the SLA tracking
  page, the findings list under five different filters, the reports matrix, the
  CSV export and the movement report. Then all of it again under each of the
  five assessment filters, checking that the summary, the list, the SLA page,
  the reports matrix and the export all narrow to the same set.
  **71 of 71 match.**

The integrity sweep runs **26 of 26** and the suite **114 of 114**.

---

## 17. Three small changes, no logic touched

### The assessment is labelled beside the finding

Which assessment a finding came from was small grey text under its code. A CIS
control, a code defect and a penetration test result are not the same kind of
statement and should not have to be inferred, so the type is now a coloured
label beside the finding name, on the Findings page and on the dashboard, and
the duplicate grey line under the code is gone.

### The last administrator cannot be disabled by accident

The server always refused it - disabling the only administrator would leave
nobody able to reach Users, the SLA policy or Maintenance. But the button was
still offered, so the rule was only discovered by pressing it. It is now shown
disabled, with the reason on hover, and becomes available the moment a second
administrator exists. The server check is unchanged and still the thing that
enforces it.

### Signing in no longer survives closing the browser

The session cookie was written with a twelve hour lifetime, so reopening the
browser the next morning landed straight on the dashboard as whoever had signed
in last. That is reasonable on one person's laptop and wrong for a platform
reached over the internet. It is now a session cookie: the browser drops it on
close. The token still expires on its own, so a browser left open is not a way
around it. `ASSURANCE_HTTPS=1` additionally marks the cookie secure once the
platform is behind TLS.

Nothing in the correlation engine, the SLA engine, the permission model or the
ingest path was touched. Re-verified afterwards: integrity **26 of 26**, suite
**114 of 114**, every reported number **71 of 71**, and the interface driven in
both themes **100 of 100**.

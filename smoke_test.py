"""End-to-end smoke test for the Assurance platform.

Runs the real application against a throwaway database and asserts the
behaviour the platform promises - not the behaviour it happened to have.

    python smoke_test.py

It builds its own database at data/smoke_test.db and deletes it on every run.
The platform's own data/assurance.db is never touched.
"""
import io
import os
import sys
from datetime import datetime, timedelta

os.environ["ASSURANCE_SECRET_KEY"] = "test-secret-key"
# The suite resets the platform and wipes everything more than once, so it runs
# against its own file. Running it used to delete the database that ships
# loaded with three months of assessments.
os.environ.setdefault("ASSURANCE_DB", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "data", "smoke_test.db"))

from fastapi.testclient import TestClient  # noqa: E402
import pandas as pd  # noqa: E402

from app.database import Base, engine, SessionLocal  # noqa: E402
from app import models  # noqa: E402  (registers tables on Base.metadata)

PASSED = 0
FAILED = 0


def check(name, cond, extra=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  PASS  {name}")
    else:
        FAILED += 1
        print(f"  FAIL  {name} {extra}")


def totals(response):
    """The upload API accepts many files at once and answers with totals."""
    body = response.json()
    return body.get("totals") or {}


def sheet(rows):
    buf = io.BytesIO()
    pd.DataFrame(rows).to_excel(buf, index=False)
    buf.seek(0)
    return buf.getvalue()


def upload(client, filename, rows, kind="assessment"):
    return client.post(
        "/api/upload",
        files=[("files", (filename, sheet(rows),
                          "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))],
        data={"source_type": kind},
    )


# ---------------------------------------------------------------------------
# A fresh database, seeded the way a first install is
# ---------------------------------------------------------------------------
if os.path.exists(os.environ["ASSURANCE_DB"]):
    os.remove(os.environ["ASSURANCE_DB"])

Base.metadata.create_all(bind=engine)
from sample_data.seed_data import seed_if_empty  # noqa: E402

db = SessionLocal()
seed_if_empty(db)
db.close()

from app.main import app  # noqa: E402

client = TestClient(app)

SCAN_INFO = "Nessus Scan Information"


def scan_row(plugin, ip, severity="High", port=443, first="2026-03-01",
             last="2026-03-16", output="evidence"):
    return {"Plugin Name": plugin, "Severity": severity, "IP Address": ip,
            "Protocol": "tcp", "Port": port, "CVE": "CVE-2026-0001",
            "First Discovered": first, "Last Observed": last,
            "Description": "test finding", "Steps to Remediate": "patch it",
            "Plugin Output": output, "Vulnerability Priority Rating": 7.5}


def credentialed(ip, yes=True, last="2026-03-16"):
    """The row that tells the platform whether the host was really assessed."""
    return {"Plugin Name": SCAN_INFO, "Severity": "Info", "IP Address": ip,
            "Protocol": "tcp", "Port": 0, "CVE": None,
            "First Discovered": last, "Last Observed": last,
            "Description": "", "Steps to Remediate": "",
            "Plugin Output": f"Credentialed checks : {'yes' if yes else 'no'}",
            "Vulnerability Priority Rating": None}


print("== Authentication ==")
r = client.get("/login")
check("login page", r.status_code == 200)
check("bad login rejected",
      client.post("/api/login", json={"username": "admin", "password": "wrong"}).status_code == 401)
r = client.post("/api/login", json={"username": "admin", "password": "admin"})
check("admin login", r.status_code == 200 and r.json().get("ok"))
check("cookie set", "assurance_token" in client.cookies)
check("logout works (GET)", client.get("/logout", follow_redirects=False).status_code == 303)
client.post("/api/login", json={"username": "admin", "password": "admin"})

print("== Only one account ships ==")
r = client.get("/api/users")
check("single default account", len(r.json()["users"]) == 1, str(len(r.json()["users"])))
check("and it is an administrator", r.json()["users"][0]["role"] == "admin")

print("== Inventory is uploaded from the Assets page ==")
inv = [{"Asset Code": "AST-9001", "Name": "TEST-SRV-1", "IP Address": "10.99.1.1",
        "Type": "Server", "PCI / NPCI": "PCI", "Crown Jewel (CJ / Not CJ)": "CJ",
        "Environment": "Production", "Location": "HQ", "Owner": "Test Team",
        "Status": "Active"}]
r = upload(client, "Asset_Inventory_test.xlsx", inv, kind="assets")
check("inventory upload", r.status_code == 200 and totals(r)["created"] == 1, r.text[:200])
r = client.get("/api/assets?q=TEST-SRV-1")
check("asset stored", len(r.json()["assets"]) == 1)
asset = r.json()["assets"][0]
check("scope carries both labels", "Crown Jewel" in asset["scope"] and "PCI" in asset["scope"],
      asset["scope"])
r = client.get(f"/api/assets/{asset['id']}")
check("asset detail", r.status_code == 200 and "why_it_matters" in r.json())

print("== Assessment upload ==")
asset_count_before = client.get("/api/assets").json()["total"]
rows = [credentialed("10.99.1.1"),
        scan_row("TEST-Plugin-A", "10.99.1.1", "Critical"),
        scan_row("TEST-Plugin-B", "10.99.1.1", "High", port=22),
        scan_row("TEST-Plugin-C", "10.99.9.9", "Medium", port=161)]   # IP not in inventory
r = upload(client, "VA_C1_2026-03-16_R1_Test.xlsx", rows)
t = totals(r)
check("upload accepted", r.status_code == 200, r.text[:200])
check("three findings created", t["new"] == 3, str(t))
check("scan information row is not a finding", t["records"] == 4 and t["new"] == 3, str(t))
check("unknown IP counted as unmapped", t["unmapped"] == 1, str(t))

check("no asset invented from a scan row",
      client.get("/api/assets").json()["total"] == asset_count_before,
      str(client.get("/api/assets").json()["total"]))
r = client.get("/api/findings?q=TEST-Plugin-C")
check("unmapped finding parked on the default asset",
      r.json()["findings"][0]["asset"]["asset_code"] == "AST-0000",
      str(r.json()["findings"][0]["asset"]))

print("== The whole sheet row is kept ==")
r = client.get("/api/findings?q=TEST-Plugin-A")
fid = r.json()["findings"][0]["id"]
r = client.get(f"/api/findings/{fid}")
raw = r.json().get("raw") or {}
headers = [c[0] for c in raw.get("columns", [])]
check("raw row stored", len(headers) == 12, str(len(headers)))
check("every column kept, in order", headers[0] == "Plugin Name" and "Plugin Output" in headers,
      str(headers[:3]))
check("full record page renders", client.get(f"/findings/{fid}/record").status_code == 200)

print("== Correlation ==")
r = upload(client, "VA_C1_2026-03-17_R1_Test.xlsx", rows)
t = totals(r)
check("re-upload updates, never duplicates", t["updated"] == 3 and t["new"] == 0, str(t))

# An older file must not roll the state backwards.
older = [credentialed("10.99.1.1", last="2026-03-10"),
         scan_row("TEST-Plugin-A", "10.99.1.1", "Critical", last="2026-03-10")]
r = upload(client, "VA_C0_2026-03-10_R1_Test.xlsx", older)
r = client.get("/api/findings?q=TEST-Plugin-A")
check("older evidence does not move Last Observed",
      r.json()["findings"][0]["last_observed"][:10] == "2026-03-16",
      r.json()["findings"][0]["last_observed"])
check("older file closes nothing it did not cover",
      r.json()["findings"][0]["status"] == "Open")

print("== Closure needs proof, not silence ==")
# Same host, credentialed, Plugin B gone -> B closes, A stays.
gone = [credentialed("10.99.1.1", last="2026-03-20"),
        scan_row("TEST-Plugin-A", "10.99.1.1", "Critical", last="2026-03-20")]
r = upload(client, "VA_C2_2026-03-20_R1_Test.xlsx", gone)
check("absent finding closed automatically", totals(r)["closed"] == 1, str(totals(r)))
r = client.get("/api/findings?q=TEST-Plugin-B")
b = r.json()["findings"][0]
check("closure carries provenance", b["status"] == "Closed" and b["closure_method"] == "automatic"
      and bool(b["closed_at"]) and bool(b["closure_evidence"]), str(b["closure_method"]))
check("a closed finding has no deadline", b["due_date"] is None)

# Uncredentialed pass over the same host must NOT close anything.
blind = [credentialed("10.99.1.1", yes=False, last="2026-03-25")]
r = upload(client, "VA_C3_2026-03-25_R1_Test.xlsx", blind)
check("an uncredentialed pass closes nothing", totals(r)["closed"] == 0, str(totals(r)))
r = client.get("/api/assets?q=TEST-SRV-1")
check("host marked Inconclusive", r.json()["assets"][0]["coverage_state"] == "Inconclusive",
      str(r.json()["assets"][0]["coverage_state"]))

print("== Reappearance ==")
back = [credentialed("10.99.1.1", last="2026-03-28"),
        scan_row("TEST-Plugin-A", "10.99.1.1", "Critical", last="2026-03-28"),
        scan_row("TEST-Plugin-B", "10.99.1.1", "High", port=22, last="2026-03-28")]
r = upload(client, "VA_C4_2026-03-28_R1_Test.xlsx", back)
check("closed finding reopened", totals(r)["reappeared"] == 1, str(totals(r)))
r = client.get("/api/findings?q=TEST-Plugin-B")
b = r.json()["findings"][0]
check("original discovery date kept", b["first_discovered"][:10] == "2026-03-01", b["first_discovered"])
check("reappearance dated", bool(b.get("id")) and b["is_reappeared"] and b["reappeared_count"] >= 1)

print("== SLA engine ==")
r = client.get("/api/findings?q=TEST-Plugin-A")
a = r.json()["findings"][0]
check("a rule matched", a["sla_days"] is not None and a["due_date"], str(a["sla_days"]))
check("due date is discovery plus the rule",
      a["due_date"][:10] == (datetime.strptime(a["first_discovered"][:10], "%Y-%m-%d")
                             + timedelta(days=a["sla_days"])).strftime("%Y-%m-%d"),
      f"{a['first_discovered']} + {a['sla_days']} != {a['due_date']}")
check("a passed deadline with fresh evidence is a proven breach",
      a["sla_status"] in ("SLA Exceeded", "Past Due"), a["sla_status"])

r = client.get("/api/sla-rules")
rules = r.json()["rules"]
check("default policy seeded", len(rules) >= 10, str(len(rules)))
catch_all = rules[-1]
check("the last rule is the catch-all",
      catch_all["source"] == "Any" and catch_all["severity"] == "Any")
check("the catch-all cannot be deleted",
      client.delete(f"/api/sla-rules/{catch_all['id']}").status_code == 400)
r = client.post("/api/sla-rules", json={"source": "VA", "severity": "Critical",
                                        "asset_scope": "Crown Jewel", "asset_type": "Any",
                                        "environment": "Any", "sla_days": 3,
                                        "approaching_pct": 60, "retest_pct": 80})
check("a new rule lands above the catch-all", r.status_code == 200)
r = client.get("/api/sla-rules")
check("catch-all still last", r.json()["rules"][-1]["id"] == catch_all["id"])
new_rule = [x for x in r.json()["rules"] if x["sla_days"] == 3][0]
check("policy change recalculates", client.delete(f"/api/sla-rules/{new_rule['id']}"
                                                  ).json().get("recalculated", 0) >= 0)

print("== Exceptions ==")
r = client.get("/api/exceptions/controls")
check("controls listed", r.status_code == 200 and len(r.json()["controls"]) > 0)
r = client.get("/api/exceptions/targets?control=TEST-Plugin-A")
check("the IPs a control fails on are listed", r.json()["count"] >= 1, str(r.json()["count"]))
r = client.post("/api/exceptions/scoped", json={
    "control": "TEST-Plugin-A", "all_current": True, "applies_to_future": True,
    "reason": "Compensating Control",
    "justification": "Isolated management VLAN, reviewed by the network team.",
    "expires_at": "2026-12-31"})
check("scoped exception applied", r.status_code == 200 and r.json()["applied"] >= 1, r.text[:200])
check("a standing record covers future occurrences", bool(r.json()["template"]))
r = client.get("/api/findings?q=TEST-Plugin-A")
check("finding now under exception",
      r.json()["findings"][0]["sla_status"] == "Under Exception",
      r.json()["findings"][0]["sla_status"])
check("an excepted finding keeps its deadline", bool(r.json()["findings"][0]["due_date"]))
r = client.post("/api/exceptions", json={"reason": "not a real reason", "justification": "x"})
check("a free-text reason is refused", r.status_code in (400, 404, 405))

print("== Dashboard, reports and exports ==")
check("summary", client.get("/api/summary").status_code == 200)
d = client.get("/api/summary").json()
check("summary carries the coverage story", "coverage" in d and "past_due" in d)
r = client.get("/api/dashboard/charts")
check("charts", r.status_code == 200 and "aging_trend" in r.json() and "retest_doughnut" in r.json())
r = client.get("/api/dashboard/charts?date_from=2026-03-01&date_to=2026-03-20")
check("charts accept a date range", r.status_code == 200)
r = client.get("/api/reports/summary")
check("reports summary", r.status_code == 200 and "matrix" in r.json())
r = client.get("/api/reports/movement?days=30")
m = r.json()
check("movement window", r.status_code == 200 and "totals" in m and "series" in m, r.text[:200])
check("movement counts what moved",
      all(k in m["totals"] for k in ("fixed", "reappeared", "discovered", "still_open")))
r = client.get("/api/reports/export")
check("csv export", r.status_code == 200 and "text/csv" in r.headers["content-type"])
check("audit trail", client.get("/api/audit").status_code == 200)

print("== Per-page access control ==")
r = client.post("/api/users", json={
    "username": "tester", "password": "tester123", "role": "custom",
    "full_name": "Access Tester",
    "access": {"dashboard": "read", "findings": "write", "sla_tracking": "none",
               "retests": "none", "exceptions": "none", "assets": "read",
               "reports": "none", "settings": "none"}})
check("user created with per-page levels", r.status_code == 200, r.text[:200])

admin_cookies = dict(client.cookies)
client.cookies.clear()
check("tester login", client.post("/api/login",
                                  json={"username": "tester", "password": "tester123"}
                                  ).status_code == 200)
check("read where allowed", client.get("/api/findings").status_code == 200)
check("write where allowed", client.post(f"/api/findings/{fid}/owner",
                                         json={"owner": "Tester"}).status_code == 200)
check("read-only page cannot be written",
      client.post("/api/assets/1/note", json={}).status_code in (403, 404, 405))
check("a page with no access is refused", client.get("/api/sla-tracking").status_code == 403)
check("not an administrator", client.get("/api/users").status_code == 403)
check("cannot wipe the platform",
      client.post("/api/admin/reset-data", json={"scope": "all", "confirm": "RESET EVERYTHING"}).status_code == 403)
check("can change its own password",
      client.post("/api/me/password", json={"current_password": "tester123",
                                            "new_password": "tester999",
                                            "confirm_password": "tester999"}).status_code == 200)
check("the old password no longer works",
      client.post("/api/login", json={"username": "tester", "password": "tester123"}
                  ).status_code == 401)

print("== SAST, DAST and PT ==")
APP = "Payments Console"
client.post("/api/login", json={"username": "admin", "password": "admin"})
# The application has to exist on the register before a code review can land
# on it - that is the rule, and it is worth proving rather than assuming.
r = upload(client, "inventory_app.xlsx", [
    {"Application Name": APP, "PCI / NPCI": "PCI", "Crown Jewel (CJ / Not CJ)": "CJ",
     "Server IP": "10.99.0.5", "OS Type": "Application", "Environment": "Production",
     "Location": "HQ", "Application Owner": "Test Owner",
     "Domain": "payments-console.test.local"}], kind="assets")
check("an application row with a domain is accepted", r.status_code == 200, r.text[:160])


def sast_rows(scan, items):
    return [{"Finding ID": f"SAST-9{i:04d}", "Application Name": APP,
             "Vulnerability Title": t, "CWE ID": c, "Severity": sev,
             "Affected File / Component": loc, "Scan Date": scan}
            for i, (t, c, sev, loc) in enumerate(items, start=1)]


def dast_rows(scan, items):
    return [{"Finding ID": f"DAST-9{i:04d}", "Application Name": APP,
             "Vulnerability Title": t, "OWASP Category": cat, "Severity": sev,
             "Affected URL / Endpoint": url, "Scan Date": scan}
            for i, (t, cat, sev, url) in enumerate(items, start=1)]


def pt_rows(scan, items):
    return [{"Finding ID": f"PT-9{i:04d}", "Application Name": APP,
             "Finding Title": t, "Severity": sev, "Affected URL / Endpoint": url,
             "Description": "found by hand", "Recommendation": "fix it",
             "Scan Date": scan}
            for i, (t, sev, url) in enumerate(items, start=1)]


URL = "https://payments-console.test.local/api/v1/pay"
r = upload(client, "sast_first.xlsx", sast_rows("2026-04-01", [
    ("SQL Injection in Data Access Layer", "CWE-89", "High", "PayRepository.java"),
    ("Weak Hashing Algorithm (MD5)", "CWE-327", "Medium", "TokenUtil.java"),
]))
check("a SAST report is recognised from its Finding ID",
      r.status_code == 200 and r.json()["files"][0]["detected_type"] == "SAST", r.text[:200])
r = upload(client, "dast_first.xlsx", dast_rows("2026-04-02", [
    ("SQL Injection", "A03:2021 - Injection", "Critical", URL),
]))
check("a DAST report is recognised from its Finding ID",
      r.status_code == 200 and r.json()["files"][0]["detected_type"] == "DAST", r.text[:200])
r = upload(client, "pt_first.xlsx", pt_rows("2026-04-03", [
    ("Business Logic Flaw in Transfer Limits", "High", URL),
]))
check("a PT report is recognised from its Finding ID",
      r.status_code == 200 and r.json()["files"][0]["detected_type"] == "PT", r.text[:200])


def one(source, title):
    for f in client.get(f"/api/findings?source={source}&page_size=200").json()["findings"]:
        if f["plugin_name"] == title and f["application_name"] == APP:
            return f
    return None


sast = one("SAST", "SQL Injection in Data Access Layer")
dast = one("DAST", "SQL Injection")
pt = one("PT", "Business Logic Flaw in Transfer Limits")
check("the SAST finding landed on the application, not on a server",
      sast and sast["asset"] and sast["asset"]["type"] == "Application", sast)
check("the DAST finding was resolved to a host through the domain",
      dast and dast["asset"] and dast["asset"]["domain"] == "payments-console.test.local", dast)
check("the PT finding was resolved the same way",
      pt and pt["asset"] and pt["asset"]["domain"] == "payments-console.test.local", pt)
check("the application finding carries its CWE", sast["cwe_id"] == "CWE-89", sast["cwe_id"])
check("the DAST finding carries its OWASP category",
      dast["owasp_category"] == "A03:2021 - Injection", dast["owasp_category"])
check("the report's own id is kept", sast["external_ref"].startswith("SAST-"), sast["external_ref"])

sast_first = sast["first_discovered"]
sast_code = sast["finding_code"]

print("== the severity moves, the finding does not ==")
upload(client, "sast_rerated.xlsx", sast_rows("2026-05-01", [
    ("SQL Injection in Data Access Layer", "CWE-89", "Critical", "PayRepository.java"),
    ("Weak Hashing Algorithm (MD5)", "CWE-327", "Medium", "TokenUtil.java"),
]))
sast = one("SAST", "SQL Injection in Data Access Layer")
check("a re-rated finding keeps its code", sast["finding_code"] == sast_code, sast["finding_code"])
check("its severity is updated in place", sast["severity"] == "Critical", sast["severity"])
check("and its clock never restarted", sast["first_discovered"] == sast_first,
      f'{sast_first} -> {sast["first_discovered"]}')
check("there is still only one of it",
      len([f for f in client.get("/api/findings?source=SAST&page_size=200").json()["findings"]
           if f["plugin_name"] == "SQL Injection in Data Access Layer"
           and f["application_name"] == APP]) == 1)

print("== absence closes, but only where the application was tested ==")
upload(client, "sast_third.xlsx", sast_rows("2026-06-01", [
    ("SQL Injection in Data Access Layer", "CWE-89", "Critical", "PayRepository.java"),
]))
gone = one("SAST", "Weak Hashing Algorithm (MD5)")
check("a finding the newer scan no longer reports is closed",
      gone["status"] == "Closed", gone["status"])
check("and the closure names the assessment that proved it",
      gone["closure_method"] == "automatic" and gone["closure_evidence"], gone)
still = one("DAST", "SQL Injection")
check("a SAST report closes nothing on the DAST side",
      still["status"] == "Open", still["status"])

upload(client, "sast_fourth.xlsx", sast_rows("2026-07-01", [
    ("SQL Injection in Data Access Layer", "CWE-89", "Critical", "PayRepository.java"),
    ("Weak Hashing Algorithm (MD5)", "CWE-327", "Medium", "TokenUtil.java"),
]))
back = one("SAST", "Weak Hashing Algorithm (MD5)")
check("a closed application finding that comes back is open again",
      back["status"] == "Open" and back["is_reappeared"], back["status"])
check("and it kept the date it was first found",
      back["first_discovered"][:10] == "2026-04-01", back["first_discovered"])

print("== one workbook, three assessments ==")
combined_sheets = {
    "SAST Findings": sast_rows("2026-08-01", [
        ("Path Traversal in File Handler", "CWE-22", "High", "FileApi.java")]),
    "DAST Findings": dast_rows("2026-08-01", [
        ("Weak TLS Configuration", "A02:2021 - Cryptographic Failures", "Medium", URL)]),
    "PT Findings": pt_rows("2026-08-01", [
        ("Host Header Injection", "Medium", URL)]),
}
buf = io.BytesIO()
with pd.ExcelWriter(buf, engine="openpyxl") as writer:
    for sheet_name, rows_ in combined_sheets.items():
        pd.DataFrame(rows_).to_excel(writer, sheet_name=sheet_name, index=False)
buf.seek(0)
r = client.post("/api/upload",
                files=[("files", ("AppSec_All.xlsx", buf.getvalue(),
                                  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))],
                data={"source_type": "assessment"})
kinds = {f.get("detected_type") for f in r.json().get("files", [])}
check("a workbook of three assessments is split into three",
      r.status_code == 200 and kinds == {"SAST", "DAST", "PT"}, f'{r.status_code} {kinds}')

print("== an application the register does not know ==")
r = upload(client, "sast_orphan.xlsx", [
    {"Finding ID": "SAST-99999", "Application Name": "Nowhere Ledger",
     "Vulnerability Title": "Insecure Deserialization", "CWE ID": "CWE-502",
     "Severity": "High", "Affected File / Component": "X.java",
     "Scan Date": "2026-08-01"}])
check("it is kept rather than dropped", r.status_code == 200
      and r.json()["totals"]["new"] >= 1, r.text[:200])
orphan = None
for f in client.get("/api/findings?source=SAST&page_size=500").json()["findings"]:
    if f["application_name"] == "Nowhere Ledger":
        orphan = f
        break
check("and it waits on the Default Asset until the inventory explains it",
      orphan and orphan["asset"] and orphan["asset"]["asset_code"] == "AST-0000", orphan)

r = upload(client, "inventory_late.xlsx", [
    {"Application Name": "Nowhere Ledger", "PCI / NPCI": "NPCI",
     "Crown Jewel (CJ / Not CJ)": "Not CJ", "Server IP": "10.99.0.9",
     "OS Type": "Application", "Environment": "Production", "Location": "HQ",
     "Application Owner": "Late Owner", "Domain": "nowhere-ledger.test.local"}],
    kind="assets")
moved = None
for f in client.get("/api/findings?source=SAST&page_size=500").json()["findings"]:
    if f["application_name"] == "Nowhere Ledger":
        moved = f
        break
check("and it moves across on its own once the inventory catches up",
      moved and moved["asset"] and moved["asset"]["asset_code"] != "AST-0000",
      moved["asset"] if moved else None)

print("== Data reach: the header filter ==")
client.cookies.clear()
client.post("/api/login", json={"username": "admin", "password": "admin"})

# A CIS finding to restrict an account away from. A CIS export has ten columns
# and no Description at all - that is the real shape of the file.
r = upload(client, "CIS_bench_2026-03-16.xlsx", [
    {"Plugin Name": "1.1 Ensure something is set", "Severity": "High",
     "IP Address": "10.10.10.11", "Protocol": "tcp", "DNS Name": "srv-a",
     "Plugin Output": "Result: FAILED", "See Also": "",
     "First Discovered": "2026-03-01", "Last Observed": "2026-03-16",
     "Steps to Remediate": "set it"}])
check("a CIS export is recognised from its content",
      r.status_code == 200 and r.json()["files"][0]["detected_type"] == "CIS", r.text[:200])
cis = client.get("/api/findings?source=CIS").json()
check("the CIS finding was stored", cis["total"] >= 1, str(cis["total"]))
cis_id = cis["findings"][0]["id"]
check("a CIS finding has no description, because the file has no such column",
      not (cis["findings"][0].get("description") or ""))

everything = client.get("/api/findings").json()["total"]
scopes = client.get("/api/users").json()["scopes"]
all_sources = client.get("/api/users").json()["sources"]
check("every assessment type is offered when granting access",
      set(all_sources) == {"VA", "CIS", "SAST", "DAST", "PT"}, str(all_sources))
check("scopes are read from the inventory", len(scopes) >= 1, str(scopes))
first_scope = scopes[0]
r = client.post("/api/view", json={"scope": first_scope, "source": ""})
check("the header selection is accepted", r.status_code == 200 and
      r.json()["view"]["scope"] == first_scope, r.text[:200])
narrowed = client.get("/api/findings").json()["total"]
check("the selection narrows the findings list", narrowed <= everything,
      f"{narrowed} > {everything}")
check("the selection narrows the dashboard the same way",
      client.get("/api/summary").json()["total_open"] <=
      client.get("/api/findings?status=Open (any)").json()["total"] + 0)
check("the selection reaches the export",
      len(client.get("/api/reports/export").text.splitlines()) - 1 == narrowed,
      str(len(client.get("/api/reports/export").text.splitlines()) - 1))
r = client.post("/api/view", json={"scope": "Not A Real Scope", "source": ""})
check("an unknown selection is discarded, not obeyed",
      r.json()["view"]["scope"] == "" and
      client.get("/api/findings").json()["total"] == everything)

print("== Data reach: the grant behind it ==")
r = client.post("/api/users", json={
    "username": "narrow", "password": "narrow123", "role": "custom",
    "full_name": "Narrow Reach",
    "access": {k: "write" for k in ("dashboard", "findings", "sla_tracking",
                                    "retests", "exceptions", "assets", "reports")}
    | {"settings": "none"},
    "scopes": [], "sources": ["VA"], "unscoped": True})
check("account created with a restricted reach", r.status_code == 200, r.text[:200])
check("the grant is reported back",
      r.json()["user"]["sources"] == ["VA"] and r.json()["user"]["unscoped"] is True,
      str(r.json()["user"]))
r = client.post("/api/users", json={
    "username": "wideopen", "password": "wide1234", "role": "custom",
    "access": {"dashboard": "read", "findings": "read", "sla_tracking": "none",
               "retests": "none", "exceptions": "none", "assets": "none",
               "reports": "none", "settings": "none"}})
check("an account created without a stated reach reaches everything",
      r.status_code == 200
      and sorted(r.json()["user"]["sources"]) == sorted(all_sources)
      and sorted(r.json()["user"]["scopes"]) == sorted(scopes), r.text[:200])
r = client.put("/api/users/%d" % r.json()["user"]["id"],
               json={"scopes": ["Nowhere"]})
check("an unknown scope is refused", r.status_code == 400, r.text[:120])

admin_cookies = dict(client.cookies)
client.cookies.clear()
client.post("/api/login", json={"username": "narrow", "password": "narrow123"})
v = client.get("/api/view").json()
check("the dropdowns offer only what was granted",
      v["scope_options"] == [] and v["source_options"] == ["VA"], str(v))
check("a CIS finding cannot be reached by id",
      client.get("/api/findings/%d" % cis_id).status_code == 404)
check("a CIS finding cannot be written by id",
      client.post("/api/findings/%d/owner" % cis_id,
                  json={"owner": "x"}).status_code == 404)
check("a bulk action skips it rather than doing it",
      client.post("/api/findings/bulk/owner",
                  json={"ids": [cis_id], "owner": "x"}).json()["count"] == 0)
r = upload(client, "cis_blocked.xlsx", [
    {"Plugin Name": "1.1 Blocked control", "Severity": "High",
     "IP Address": "10.10.10.9", "Protocol": "tcp", "DNS Name": "h",
     "Plugin Output": "Result: FAILED", "See Also": "", "Steps to Remediate": "fix",
     "First Discovered": "2026-03-01", "Last Observed": "2026-03-16"}])
check("a CIS file cannot be imported at all", r.status_code == 400
      and "grant" in r.text, r.text[:160])

client.cookies.clear()
client.cookies.update(admin_cookies)
client.post("/api/view", json={"scope": "", "source": ""})

print("== Administrator reset ==")
client.cookies.clear()
client.post("/api/login", json={"username": "admin", "password": "admin"})
r = client.post("/api/admin/reset-data", json={"scope": "findings", "confirm": "CLEAR FINDINGS"})
check("findings cleared", r.status_code == 200 and r.json()["removed"]["findings"] > 0, r.text[:200])
check("assets kept", client.get("/api/assets").json()["total"] >= 1)
check("policy kept", len(client.get("/api/sla-rules").json()["rules"]) >= 10)
r = client.post("/api/admin/reset-data", json={"scope": "all", "confirm": "RESET EVERYTHING"})
check("factory reset", r.status_code == 200)
check("accounts are never deleted", len(client.get("/api/users").json()["users"]) == 4,
      str(len(client.get("/api/users").json()["users"])))
check("policy seeded again", len(client.get("/api/sla-rules").json()["rules"]) >= 10)

print()
print(f"RESULT: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)

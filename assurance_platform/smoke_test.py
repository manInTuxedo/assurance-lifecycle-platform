"""End-to-end smoke test for the Assurance platform (runs against the real app)."""
import io
import os
import sys
from datetime import datetime, timedelta

os.environ["ASSURANCE_SECRET_KEY"] = "test-secret-key"

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


# --- fresh DB ---
if os.path.exists("data/assurance.db"):
    os.remove("data/assurance.db")

Base.metadata.create_all(bind=engine)
from sample_data.seed_data import seed_if_empty

db = SessionLocal()
seed_if_empty(db)
db.close()

from app.main import app  # noqa: E402

client = TestClient(app)

print("== Auth & RBAC ==")
r = client.get("/login")
check("login page", r.status_code == 200)
r = client.post("/api/login", json={"username": "admin", "password": "wrong"})
check("bad login rejected", r.status_code == 401)
r = client.post("/api/login", json={"username": "admin", "password": "admin"})
check("admin login", r.status_code == 200 and r.json().get("ok"))
check("cookie set", "assurance_token" in client.cookies)

print("== Upload CSV (tz-aware dates + embedded asset columns) ==")
rows1 = [
    {"plugin_name": "TEST-Plugin-A", "severity": "Critical", "ip_address": "10.99.1.1",
     "protocol": "tcp", "port": 443, "cve": "CVE-2026-0001",
     "first_discovered": "2026-03-01T10:00:00+02:00",   # tz-aware on purpose
     "last_observed": "2026-03-16 12:30:00 +0000",      # tz-aware string
     "description": "test", "remediation_steps": "patch", "plugin_output": "x",
     "vpr_score": "9.0", "Hostname": "TEST-SRV-1", "Asset Type": "Server",
     "Scope": "Crown Jewel", "Environment": "Production", "Site": "HQ",
     "Owner Team": "Server Team"},
    {"plugin_name": "TEST-Plugin-B", "severity": "High", "ip_address": "10.99.1.2",
     "protocol": "tcp", "port": 22, "cve": "CVE-2026-0002",
     "first_discovered": "2026-03-10", "last_observed": "2026-03-15",
     "description": "test", "remediation_steps": "patch", "plugin_output": "y",
     "vpr_score": 7.0, "Hostname": "TEST-SRV-2", "Asset Type": "Database",
     "Scope": "PCI", "Environment": "Production", "Site": "HQ",
     "Owner Team": "Database Team"},
    {"plugin_name": "TEST-Plugin-C", "severity": "Medium", "ip_address": "10.99.9.9",
     "protocol": "udp", "port": 161, "cve": None,
     "first_discovered": "2026-03-01", "last_observed": "2026-03-14",
     "description": "test", "remediation_steps": "patch", "plugin_output": "z",
     "vpr_score": 5.5},  # no asset info -> unmapped
]
buf = io.BytesIO()
pd.DataFrame(rows1).to_excel(buf, index=False)
buf.seek(0)
r = client.post("/api/upload", files={"file": ("VA_C1_2026-03-16_R1_Test.xlsx", buf.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}, data={"source_type": "va"})
check("upload 1 ok (tz dates no crash)", r.status_code == 200, r.text[:300])
s1 = r.json()["stats"]
check("upload 1 new=3", s1["new"] == 3, str(s1))
check("upload 1 unmapped=1", s1["unmapped"] == 1, str(s1))

print("== Assets auto-created from CSV ==")
r = client.get("/api/assets?q=TEST-SRV-1")
check("asset 1 created", r.status_code == 200 and len(r.json()["assets"]) == 1)
a1 = r.json()["assets"][0]
check("asset 1 attributes", a1["scope"] == "Crown Jewel" and a1["owner_team"] == "Server Team", str(a1))
r = client.get("/api/assets?q=TEST-SRV-2")
a2 = r.json()["assets"]
check("asset 2 created", len(a2) == 1 and a2[0]["type"] == "Database")
r = client.get("/api/assets")
check("no default-asset-only pollution", len(r.json()["assets"]) == 2, str(len(r.json()["assets"])))

print("== Correlation (no dupes / reappearance) ==")
buf2 = io.BytesIO()
pd.DataFrame(rows1).to_excel(buf2, index=False)
buf2.seek(0)
r = client.post("/api/upload", files={"file": ("VA_C1_2026-03-17_R1_Test.xlsx", buf2.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}, data={"source_type": "va"})
s2 = r.json()["stats"]
check("upload 2 updated=3 (no dupes)", s2["updated"] == 3 and s2["new"] == 0, str(s2))

r = client.get("/api/findings?q=TEST-Plugin-A")
tfa = [f for f in r.json()["findings"] if f["plugin_name"] == "TEST-Plugin-A"][0]
client.post(f"/api/findings/{tfa['id']}/close", json={})
buf3 = io.BytesIO()
pd.DataFrame([rows1[0]]).to_excel(buf3, index=False)
buf3.seek(0)
r = client.post("/api/upload", files={"file": ("VA_C1_2026-03-18_R1_Test.xlsx", buf3.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}, data={"source_type": "va"})
s3 = r.json()["stats"]
check("reappeared=1 on re-upload", s3["reappeared"] == 1, str(s3))
r = client.get("/api/findings?q=TEST-Plugin-A")
tf = [f for f in r.json()["findings"] if f["plugin_name"] == "TEST-Plugin-A"][0]
check("reopened + flagged", tf["status"] == "Open" and tf["is_reappeared"] is True)
check("count incremented", tf["reappeared_count"] >= 1, str(tf["reappeared_count"]))

print("== Dashboard API ==")
r = client.get("/api/summary")
check("summary 200", r.status_code == 200)
d = r.json()
check("summary kpis", all(k in d for k in ("total_open", "within_sla", "sla_exceeded", "pending_retest", "active_exceptions")))
check("findings counted", d["total_findings"] == 3, str(d["total_findings"]))
r = client.get("/api/dashboard/charts")
check("charts 200", r.status_code == 200 and "aging_trend" in r.json() and "retest_doughnut" in r.json())

print("== Findings API ==")
r = client.get("/api/findings")
check("findings list", r.status_code == 200 and len(r.json()["findings"]) == 3)
r = client.get("/api/findings?severity=Critical")
check("severity filter", all(f["severity"] == "Critical" for f in r.json()["findings"]))
fid = r.json()["findings"][0]["id"]
r = client.get(f"/api/findings/{fid}")
check("finding detail", r.status_code == 200)
r = client.post(f"/api/findings/{fid}/owner", json={"owner": "Test Owner"})
check("assign owner", r.status_code == 200 and r.json()["finding"]["owner"] == "Test Owner")
r = client.post(f"/api/findings/{fid}/retest", json={})
check("send to retest", r.status_code == 200 and r.json()["finding"]["retest_status"] == "Pending")
r = client.post(f"/api/findings/{fid}/risk", json={"risk_id": "RSK-2026-0042"})
check("link risk", r.status_code == 200 and r.json()["finding"]["risk_id"] == "RSK-2026-0042")
r = client.post(f"/api/findings/{fid}/exception", json={"reason": "Vendor Roadmap", "expires_at": "2026-12-31"})
check("add exception", r.status_code == 200 and r.json()["finding"]["exception_id"].startswith("EXC"))
r = client.post(f"/api/findings/{fid}/close", json={})
check("close finding", r.status_code == 200 and r.json()["finding"]["sla_status"] == "Closed")

print("== SLA engine ==")
r = client.get("/api/sla-tracking")
check("sla tracking", r.status_code == 200 and "forecast" in r.json() and "by_domain" in r.json())
r = client.get("/api/sla-rules")
rules = r.json()["rules"]
check("default rules seeded", len(rules) >= 10, str(len(rules)))
r = client.post("/api/sla-rules/simulate", json={"source": "VA", "severity": "Critical", "asset_scope": "Crown Jewel", "asset_type": "Server", "environment": "Production"})
check("simulator first-match", r.status_code == 200 and r.json().get("matched") and r.json()["rule"]["sla_days"] == 5)
r = client.post("/api/sla-rules", json={"source": "VA", "severity": "Critical", "asset_scope": "Any", "asset_type": "Any", "environment": "Any", "sla_days": 7, "approaching_pct": 70, "retest_pct": 80})
check("create rule", r.status_code == 200)
r = client.get("/api/sla-rules/log")
check("change log exists", r.status_code == 200 and len(r.json()["logs"]) > 0)

print("== Asset inventory upload ==")
inv = pd.DataFrame([
    {"Asset Code": "AST-9991", "Name": "TEST-SRV-9", "IP Address": "10.99.9.9", "Type": "Router",
     "Scope": "Infrastructure", "Environment": "Test", "Site": "DR", "Owner Team": "Network Team", "Status": "Active"},
])
ibuf = io.BytesIO()
inv.to_excel(ibuf, index=False)
ibuf.seek(0)
r = client.post("/api/upload", files={"file": ("asset_inventory.xlsx", ibuf.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}, data={"source_type": "assets"})
check("inventory upload", r.status_code == 200 and r.json()["stats"]["created"] == 1, r.text[:200])
r = client.get("/api/assets?q=TEST-SRV-9")
check("asset appears", r.status_code == 200 and len(r.json()["assets"]) == 1)
asset_id = r.json()["assets"][0]["id"]
r = client.get(f"/api/assets/{asset_id}")
check("asset detail", r.status_code == 200 and "why_it_matters" in r.json() and "open_findings" in r.json())

print("== RBAC enforcement ==")
r = client.post("/api/users", json={"username": "viewer", "password": "viewer123", "role": "read_only"})
check("create read_only user", r.status_code == 200)
client.cookies.clear()
r = client.post("/api/login", json={"username": "viewer", "password": "viewer123"})
check("viewer login", r.status_code == 200)
r = client.get("/api/summary")
check("viewer can read", r.status_code == 200)
r = client.post("/api/findings/1/close", json={})
check("viewer denied write", r.status_code == 403)
r = client.post("/api/sla-rules", json={"source": "VA"})
check("viewer denied rules", r.status_code == 403)
r = client.post("/api/admin/reset-data", json={"scope": "all"})
check("viewer denied reset", r.status_code == 403)

print("== Admin reset data ==")
client.cookies.clear()
client.post("/api/login", json={"username": "admin", "password": "admin"})
r = client.post("/api/admin/reset-data", json={"scope": "all"})
check("reset all ok", r.status_code == 200 and r.json()["findings_deleted"] > 0, str(r.status_code))
r = client.get("/api/summary")
check("no findings after reset", r.json()["total_findings"] == 0)
r = client.get("/api/assets")
check("only default asset remains", len(r.json()["assets"]) == 0, str(len(r.json()["assets"])))
r = client.get("/api/sla-rules")
check("rules kept after reset", len(r.json()["rules"]) >= 10)

print("== Reports & audit ==")
r = client.get("/api/audit")
check("audit files", r.status_code == 200)
r = client.get("/api/reports/export")
check("csv export", r.status_code == 200 and "text/csv" in r.headers["content-type"])

print()
print(f"RESULT: {PASSED} passed, {FAILED} failed")
sys.exit(1 if FAILED else 0)

"""Verify every UI page renders (200) for admin & read_only roles."""
import os
import sys

os.environ["ASSURANCE_SECRET_KEY"] = "test-secret-key"
from fastapi.testclient import TestClient  # noqa: E402

from app.database import Base, engine, SessionLocal  # noqa: E402
from app import models  # noqa: E402

if os.path.exists("data/assurance.db"):
    os.remove("data/assurance.db")
Base.metadata.create_all(bind=engine)
from sample_data.seed_data import seed_if_empty  # noqa: E402

db = SessionLocal()
seed_if_empty(db)
db.close()

from app.main import app  # noqa: E402

PAGES = ["/", "/findings", "/sla-tracking", "/assets", "/exceptions", "/retests", "/audit", "/reports", "/settings"]

client = TestClient(app)
client.post("/api/login", json={"username": "admin", "password": "admin"})

fail = 0
for p in PAGES:
    r = client.get(p)
    status = "OK" if r.status_code == 200 else "FAIL"
    if r.status_code != 200:
        fail += 1
    print(f"  {status}  admin  {p}  [{r.status_code}]")

# non-admin redirected from settings
client.post("/api/users", json={"username": "viewer", "password": "viewer123", "role": "read_only"})
client.cookies.clear()
client.post("/api/login", json={"username": "viewer", "password": "viewer123"})
r = client.get("/settings", follow_redirects=False)
print(f"  {'OK' if r.status_code == 302 else 'FAIL'}  viewer /settings redirect [{r.status_code}]")
if r.status_code != 302:
    fail += 1

print("PAGE RENDER RESULT:", "ALL OK" if fail == 0 else f"{fail} failures")
sys.exit(1 if fail else 0)

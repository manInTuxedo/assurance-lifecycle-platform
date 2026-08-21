"""Seed script: default admin + default SLA policy rules.

Run automatically on first startup, or manually:

    python -m sample_data.seed_data
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import models  # noqa: E402
from app.auth import hash_password  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402

DEFAULT_RULES = [
    # priority, source, severity,     scope,        type,   environment, sla_days, approaching, retest
    (1, "VA",  "Critical", "Crown Jewel",  "Any",     "Production", 5,  60, 70),
    (2, "VA",  "Critical", "PCI",          "Any",     "Any",       10,  65, 75),
    (3, "VA",  "Critical", "Published",    "Any",     "Any",       14,  70, 80),
    (4, "VA",  "Critical", "Any",          "Any",     "Any",       30,  70, 80),
    (5, "VA",  "High",     "Crown Jewel",  "Any",     "Production", 20, 65, 75),
    (6, "VA",  "High",     "PCI",          "Any",     "Any",       30,  70, 80),
    (7, "VA",  "High",     "Any",          "Any",     "Any",       45,  70, 80),
    (8, "VA",  "Medium",   "Any",          "Any",     "Any",       60,  75, 85),
    (9, "VA",  "Low",      "Any",          "Any",     "Any",       90,  80, 90),
    (10, "CIS", "Critical", "Any",         "Any",     "Any",       30,  70, 80),
    (11, "Any", "Any",     "Any",          "Any",     "Any",       90,  75, 85),
]


def seed_if_empty(db):
    """Idempotent seed: runs only when the DB is empty.

    Seeds the default admin account and the default SLA policy rules only.
    Findings and assets are intentionally NOT seeded - they come from
    uploaded scan / inventory reports.
    """
    created = {"user": 0, "rules": 0}

    if db.query(models.User).count() == 0:
        db.add(models.User(username="Assurance Head", password_hash=hash_password("admin"), role="admin"))
        created["user"] = 1

    if db.query(models.SLARule).count() == 0:
        for prio, src, sev, scope, atype, env, days, appr, ret in DEFAULT_RULES:
            db.add(models.SLARule(
                priority_order=prio, source=src, severity=sev, asset_scope=scope,
                asset_type=atype, environment=env, sla_days=days,
                approaching_pct=appr, retest_pct=ret, is_active=True,
            ))
        created["rules"] = len(DEFAULT_RULES)
        db.add(models.PolicyChangeLog(
            action="Seeded default SLA policy rules ({} rules)".format(len(DEFAULT_RULES)),
            user="system",
        ))

    db.commit()
    return created


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        info = seed_if_empty(db)
        print("Seed complete:", info)
    finally:
        db.close()


if __name__ == "__main__":
    main()

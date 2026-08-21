"""Firewall-style rule-based SLA engine.

Rules are evaluated top-to-bottom (ordered by ``priority_order``) and the
FIRST matching rule wins, exactly like firewall rules.
"""
from datetime import date, datetime, timedelta, timezone

from sqlalchemy.orm import Session

from . import models

# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------

def _matches(rule: models.SLARule, field_value: str, rule_value: str) -> bool:
    if rule_value == "Any":
        return True
    return str(field_value or "").strip().lower() == str(rule_value or "").strip().lower()


def match_rule(finding: models.Finding, rule: models.SLARule) -> bool:
    """Evaluate a single rule against a finding (all fields ANDed).
    
    Asset importance is incorporated through the asset.scope field:
    - Crown Jewel assets (from Asset_Inventory.xlsx) get shorter SLAs
    - PCI assets have specific compliance-driven SLAs
    - Published (internet-facing) assets have elevated priority
    - Infrastructure assets fall under standard SLAs
    """
    if not rule.is_active:
        return False
    asset = finding.asset
    if not _matches(rule, finding.source, rule.source):
        return False
    if not _matches(rule, finding.severity, rule.severity):
        return False
    if not _matches(rule, (asset.scope if asset else None), rule.asset_scope):
        return False
    if not _matches(rule, (asset.type if asset else None), rule.asset_type):
        return False
    if not _matches(rule, (asset.environment if asset else None), rule.environment):
        return False
    return True


def find_rule_for(finding: models.Finding, rules: list[models.SLARule]):
    """First match wins (top-to-bottom)."""
    ordered = sorted(rules, key=lambda r: r.priority_order)
    for rule in ordered:
        if match_rule(finding, rule):
            return rule
    return None


def simulate_match(source: str, severity: str, asset_scope: str, asset_type: str,
                   environment: str, rules: list[models.SLARule]):
    """Lightweight simulator used by the Settings page."""
    ordered = sorted(rules, key=lambda r: r.priority_order)
    for rule in ordered:
        if not rule.is_active:
            continue
        if not _matches(rule, source, rule.source):
            continue
        if not _matches(rule, severity, rule.severity):
            continue
        if not _matches(rule, asset_scope, rule.asset_scope):
            continue
        if not _matches(rule, asset_type, rule.asset_type):
            continue
        if not _matches(rule, environment, rule.environment):
            continue
        return rule
    return None


# ---------------------------------------------------------------------------
# SLA calculation
# ---------------------------------------------------------------------------

def has_active_exception(db: Session, finding_id: int) -> models.ExceptionRecord | None:
    today = date.today()
    exc = (
        db.query(models.ExceptionRecord)
        .filter(
            models.ExceptionRecord.finding_id == finding_id,
            models.ExceptionRecord.status == "Active",
        )
        .first()
    )
    if exc and exc.expires_at and exc.expires_at <= today:
        exc.status = "Expired"
        db.flush()
        return None
    return exc


def recalculate_finding(db: Session, finding: models.Finding,
                        rules: list[models.SLARule],
                        now: datetime | None = None) -> models.SLARule | None:
    """Apply SLA status/due date to a single finding. Returns the matched rule."""
    now = now or datetime.utcnow()

    # Closed findings are outside the SLA clock.
    if finding.status == models.STATUS_CLOSED:
        finding.sla_status = models.SLA_CLOSED
        finding.due_date = None
        return None

    # A live exception overrides everything else.
    if has_active_exception(db, finding.id):
        finding.sla_status = models.SLA_UNDER_EXCEPTION
        return None

    start = finding.original_created_at or finding.first_discovered or now
    if start.tzinfo is not None:  # defensive: never mix aware/naive datetimes
        start = start.astimezone(timezone.utc).replace(tzinfo=None)
    rule = find_rule_for(finding, rules)

    if rule is None:
        finding.sla_status = models.SLA_WITHIN
        finding.due_date = None
        finding.sla_rule_applied_id = None
        finding.sla_days = None
        return None

    due = start + timedelta(days=rule.sla_days)
    finding.sla_rule_applied_id = rule.id
    finding.sla_days = rule.sla_days
    finding.due_date = due

    elapsed = max((now - start).days, 0)
    ratio = elapsed / float(rule.sla_days) if rule.sla_days else 0.0

    if now > due:
        finding.sla_status = models.SLA_EXCEEDED
    elif ratio >= rule.approaching_pct / 100.0:
        finding.sla_status = models.SLA_APPROACHING
    else:
        finding.sla_status = models.SLA_WITHIN

    # Auto-flag findings for retest once the retest threshold is crossed.
    if (
        finding.status == models.STATUS_OPEN
        and finding.retest_status in (None, "Passed")
        and rule.retest_pct
        and ratio >= rule.retest_pct / 100.0
    ):
        finding.retest_status = "Pending"

    return rule


def recalculate_all(db: Session, now: datetime | None = None) -> int:
    """Recompute SLA for every finding (used on upload / policy change)."""
    rules = list(db.query(models.SLARule).all())
    findings = list(db.query(models.Finding).all())
    for f in findings:
        recalculate_finding(db, f, rules, now)
    db.commit()
    return len(findings)


# ---------------------------------------------------------------------------
# Helper: responsible domain for SLA tracking
# ---------------------------------------------------------------------------

DOMAIN_MAP = [
    ("server", "Server"),
    ("network", "Network"),
    ("database", "Database"),
    ("security", "Security"),
    ("middleware", "Middleware"),
]


def domain_for(owner_team: str | None) -> str:
    text = (owner_team or "").lower()
    for needle, label in DOMAIN_MAP:
        if needle in text:
            return label
    return "Other"

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


def scope_values(raw: str | None) -> set[str]:
    """Split the asset scope field.

    Scope is stored as one comma-separated field because an asset can be a
    Crown Jewel *and* PCI *and* Published at the same time. A rule names a
    single scope, so matching is a membership test, not equality - otherwise
    a rule for "Crown Jewel" would never match "Crown Jewel, PCI".
    """
    return {part.strip().lower() for part in str(raw or "").split(",") if part.strip()}


def _matches_scope(rule_value: str, asset_scope: str | None) -> bool:
    if rule_value == "Any":
        return True
    values = scope_values(asset_scope) or {"unknown"}
    return str(rule_value or "").strip().lower() in values


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
    # An unmapped finding is not "Infrastructure" - it has no asset at all,
    # which is a scope a policy rule can deliberately target.
    if not _matches_scope(rule.asset_scope, asset.scope if asset else "No Asset"):
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
        if not _matches_scope(rule.asset_scope, asset_scope):
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

    # An exception changes how the finding is reported, not the clock: the
    # due date is still calculated and the age keeps running underneath, so
    # the moment the exception expires the real SLA position is already there.
    exception = has_active_exception(db, finding.id)

    start = finding.original_created_at or finding.first_discovered or now
    if start.tzinfo is not None:  # defensive: never mix aware/naive datetimes
        start = start.astimezone(timezone.utc).replace(tzinfo=None)
    rule = find_rule_for(finding, rules)

    if rule is None:
        finding.sla_status = (
            models.SLA_UNDER_EXCEPTION if exception else models.SLA_WITHIN
        )
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

    if exception:
        finding.sla_status = models.SLA_UNDER_EXCEPTION
    elif now > due:
        # A breach is only called a breach when something actually saw it.
        # If the newest evidence predates the due date, the deadline has
        # passed but nobody has looked since - that is "Past Due", not
        # "Exceeded". The moment an assessment reports it after the due
        # date, it becomes a proven breach on its own.
        observed_after_due = bool(finding.last_observed and finding.last_observed > due)
        finding.sla_status = (models.SLA_EXCEEDED if observed_after_due
                              else models.SLA_PAST_DUE)
    elif ratio >= rule.approaching_pct / 100.0:
        finding.sla_status = models.SLA_APPROACHING
    else:
        finding.sla_status = models.SLA_WITHIN

    # Auto-flag findings for retest once the retest threshold is crossed, but
    # only while the finding is still inside its SLA. Past the due date it is
    # an SLA breach to chase, not a remediation waiting to be validated -
    # without this the queue filled up with every overdue finding.
    # ------------------------------------------------------------------
    # Retest requests
    # ------------------------------------------------------------------
    # The retest percentage is a point inside the SLA window, not a one-off.
    # The first request lands at that percentage of the whole window. If the
    # retest comes back Failed, the clock is NOT restarted - the finding is
    # still on its original deadline - so the next request lands at the same
    # percentage of whatever time is LEFT. The asks therefore get closer
    # together as the deadline approaches, and stop at the deadline: past it
    # the finding is a breach to chase, not a remediation to validate.
    eligible = (
        not exception
        and finding.status == models.STATUS_OPEN
        and rule.retest_pct
        and now <= due
    )

    if eligible and finding.retest_status != "Pending":
        if finding.retest_status == "Failed" and finding.retest_updated_at:
            anchor = max(finding.retest_updated_at, start)
        elif finding.retest_status == "Passed" and finding.retest_updated_at:
            anchor = max(finding.retest_updated_at, start)
        else:
            anchor = start
        remaining = due - anchor
        next_request = anchor + remaining * (rule.retest_pct / 100.0)
        if now >= next_request:
            finding.retest_status = "Pending"
            finding.retest_auto_flagged = True
            finding.retest_updated_at = now
    elif (
        not eligible
        and finding.retest_auto_flagged
        and finding.retest_status == "Pending"
    ):
        # The window closed (or an exception now covers it) - withdraw the
        # request the engine raised, so the queue only holds live work.
        finding.retest_status = None
        finding.retest_auto_flagged = False
        finding.retest_updated_at = now

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

# Asset type is what actually tells you which team fixes a finding. The
# inventory carries a named owner rather than a team, so grouping by the
# owner string put every finding in "Other".
TYPE_DOMAIN_MAP = [
    (("windows", "rhel", "linux", "aix", "server"), "Server"),
    (("switch", "router", "firewall", "load balancer", "f5"), "Network"),
    (("esxi", "hypervisor", "vmware"), "Virtualisation"),
    (("storage", "san", "nas"), "Storage"),
    (("database", "oracle", "sql"), "Database"),
    (("edr", "pam", "security", "endpoint"), "Security"),
]


def domain_for(owner_team: str | None) -> str:
    text = (owner_team or "").lower()
    for needle, label in DOMAIN_MAP:
        if needle in text:
            return label
    return "Other"


def domain_for_asset(asset) -> str:
    """Which technical domain owns this finding."""
    if asset is None:
        return "Unmapped"
    text = (asset.type or "").lower()
    for needles, label in TYPE_DOMAIN_MAP:
        if any(n in text for n in needles):
            return label
    return domain_for(asset.owner_team)

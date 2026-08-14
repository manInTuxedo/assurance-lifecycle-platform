"""SLA engine: DB-driven SLA matrix, retest/validation lifecycle, alert dispatch.

Key design decisions (instructor requirements):

1. SLA durations are configured at runtime in the ``SLAConfiguration`` table
   (severity x asset classification). Code falls back to defaults only when a
   matrix cell is missing.
2. ``due_date`` is anchored to ``original_created_at`` (first detection),
   never to the latest scan. Retests and reappearances therefore NEVER reset
   the age of a finding.
3. Findings whose SLA is approaching/breached AND which have not been scanned
   recently are moved to ``Pending Retest``. A rescan either fails the retest
   (stays Open, age preserved, ``retest_failed_count++``) or passes it
   (transition to Closed).
4. Findings linked to a ``risk_id`` are "Under Exception": SLA tracking is
   paused (breach flag cleared) until the exception is lifted.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Finding, Notification, SLAConfiguration, utcnow

logger = logging.getLogger("assurance.sla")

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low")
CLASSIFICATION_LEVELS = ("Critical", "High", "Medium", "Low")

OPEN_STATUSES = ("Open", "In Progress", "Pending Verification", "Pending Retest")
TERMINAL_STATUSES = ("Closed", "Risk Accepted")

# Static fallback (severity-only) used when a matrix cell is not configured.
FALLBACK_SLA_DAYS = {"Critical": 7, "High": 14, "Medium": 30, "Low": 60}

APPROACHING_RATIO = 0.25          # flagged "Approaching" within last 25% of window
RETEST_STALE_FACTOR = 3           # no scan for sla_days/3 -> eligible for retest
MIN_RETEST_STALE_DAYS = 3

# Allowed lifecycle transitions: {current: {next, ...}}. Closed / Risk Accepted
# are terminal at the process level; re-opening happens exclusively through the
# correlation engine when a scan proves the finding still exists.
TRANSITIONS: dict[str, set[str]] = {
    "Open": {"In Progress", "Pending Verification", "Pending Retest", "Closed", "Risk Accepted"},
    "In Progress": {"Open", "Pending Verification", "Pending Retest", "Closed", "Risk Accepted"},
    "Pending Verification": {"Closed", "Open", "In Progress", "Risk Accepted"},
    "Pending Retest": {"Open", "In Progress", "Closed", "Risk Accepted"},
    "Closed": set(),
    "Risk Accepted": set(),
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}

# ---------------------------------------------------------------------------
# Default SLA matrix (seeded once; administrators edit via the API/UI)
# ---------------------------------------------------------------------------

DEFAULT_SLA_MATRIX: dict[tuple[str, str], int] = {
    ("Critical", "Critical"): 7,
    ("Critical", "High"): 10,
    ("Critical", "Medium"): 14,
    ("Critical", "Low"): 14,
    ("High", "Critical"): 10,
    ("High", "High"): 14,
    ("High", "Medium"): 30,
    ("High", "Low"): 45,
    ("Medium", "Critical"): 30,
    ("Medium", "High"): 30,
    ("Medium", "Medium"): 45,
    ("Medium", "Low"): 60,
    ("Low", "Critical"): 60,
    ("Low", "High"): 60,
    ("Low", "Medium"): 90,
    ("Low", "Low"): 120,
}


def seed_sla_config(db: Session) -> int:
    """Insert the default severity x classification matrix when empty."""
    existing = db.scalar(select(func.count()).select_from(SLAConfiguration)) or 0
    if existing > 0:
        return 0
    for (severity, classification), days in DEFAULT_SLA_MATRIX.items():
        db.add(
            SLAConfiguration(
                severity=severity, asset_classification=classification, sla_days=days
            )
        )
    db.commit()
    logger.info("Seeded %d SLA matrix rules", len(DEFAULT_SLA_MATRIX))
    return len(DEFAULT_SLA_MATRIX)


# ---------------------------------------------------------------------------
# Duration lookup
# ---------------------------------------------------------------------------


def get_sla_days(db: Session, severity: str, asset_classification: str) -> int:
    """Remediation window from the dynamic matrix (DB), with fallback."""
    row = db.scalar(
        select(SLAConfiguration).where(
            SLAConfiguration.severity == severity,
            SLAConfiguration.asset_classification == asset_classification,
        )
    )
    if row is not None:
        return row.sla_days
    return FALLBACK_SLA_DAYS.get(severity, 30)


def compute_due_date(
    db: Session,
    severity: str,
    asset_classification: str,
    baseline: datetime | None = None,
) -> tuple[datetime, int]:
    """Due date anchored to the finding's first-detection time.

    Uses ``baseline`` (defaults to now for brand-new findings; pass
    ``Finding.original_created_at`` for existing ones so age is preserved).
    """
    days = get_sla_days(db, severity, asset_classification)
    if baseline is None:
        baseline = utcnow()
    if baseline.tzinfo is None:
        baseline = baseline.replace(tzinfo=timezone.utc)
    return baseline + timedelta(days=days), days


# ---------------------------------------------------------------------------
# Status evaluation
# ---------------------------------------------------------------------------


def is_terminal(status: str) -> bool:
    return status in TERMINAL_STATUSES


def is_under_exception(finding: Finding) -> bool:
    return bool(finding.risk_id and finding.risk_id.strip())


def is_sla_breached(finding: Finding, now: datetime | None = None) -> bool:
    """Breach = non-terminal, no exception, and now > due_date."""
    if is_terminal(finding.status) or is_under_exception(finding):
        return False
    if finding.due_date is None:
        return False
    ref = now or utcnow()
    due = finding.due_date
    if due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    return ref > due


def sla_status(finding: Finding, now: datetime | None = None) -> str:
    """Computed SLA status: On Track / Approaching / Breached / Under Exception / Resolved."""
    if is_under_exception(finding):
        return "Under Exception"
    if is_terminal(finding.status):
        return "Resolved"
    if is_sla_breached(finding, now):
        return "Breached"
    ref = now or utcnow()
    if finding.due_date is None:
        return "On Track"
    due = finding.due_date
    if due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    remaining_days = (due - ref).total_seconds() / 86400.0
    threshold = max(1, round(finding.sla_days * APPROACHING_RATIO))
    if remaining_days <= threshold:
        return "Approaching"
    return "On Track"


def finding_age_days(finding: Finding, now: datetime | None = None) -> int:
    ref = now or utcnow()
    created = finding.original_created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return max(0, int((ref - created).total_seconds() // 86400))


def overdue_days(finding: Finding, now: datetime | None = None) -> int:
    if not is_sla_breached(finding, now):
        return 0
    ref = now or utcnow()
    due = finding.due_date
    if due.tzinfo is None:
        due = due.replace(tzinfo=timezone.utc)
    return max(1, int((ref - due).total_seconds() // 86400) + 1)


def should_enter_retest(finding: Finding, now: datetime | None = None) -> bool:
    """True when SLA is approaching/breached AND the asset was not scanned recently.

    This is the trigger that moves a finding to ``Pending Retest`` so the
    remediation team requests a validation rescan.
    """
    if is_terminal(finding.status) or is_under_exception(finding):
        return False
    if sla_status(finding, now) not in {"Approaching", "Breached"}:
        return False
    ref = now or utcnow()
    stale_window = max(MIN_RETEST_STALE_DAYS, round(finding.sla_days / RETEST_STALE_FACTOR))
    last_seen = finding.last_seen
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    elapsed = (ref - last_seen).total_seconds() / 86400.0
    return elapsed >= stale_window


# ---------------------------------------------------------------------------
# Correlation-driven lifecycle transitions
# ---------------------------------------------------------------------------


def mark_reappeared(db: Session, finding: Finding) -> bool:
    """Revert a terminal finding to Open because a scan proved it is back.

    ``original_created_at`` is intentionally left untouched -> the finding
    keeps aging from its first detection. Returns True when state changed.
    """
    if finding.status not in TERMINAL_STATUSES:
        return False
    previous_status = finding.status
    finding.status = "Open"
    finding.closed_at = None
    finding.reappeared = True
    finding.reappeared_count += 1
    now = utcnow()
    if finding.first_reappeared_at is None:
        finding.first_reappeared_at = now
    finding.last_reappeared_at = now
    dispatch_notification(
        db,
        event="reappeared",
        level="high",
        subject=f"[REAPPEARED] {finding.title}",
        message=(
            f"Finding '{finding.title}' (signature {finding.correlation_signature}) was "
            f"previously '{previous_status}' and has been re-detected on asset "
            f"'{finding.affected_asset}' in a new scan. "
            f"Status reverted to Open. Reappearance #{finding.reappeared_count}. "
            f"Age preserved from {finding.original_created_at.isoformat()}."
        ),
        finding=finding,
    )
    return True


# ---------------------------------------------------------------------------
# Retest handling
# ---------------------------------------------------------------------------


def retest_failed(db: Session, finding: Finding) -> bool:
    """A scan proves the finding still exists: stay Open, age preserved."""
    now = utcnow()
    changed = finding.status != "Open"
    finding.status = "Open"
    finding.is_sla_breached = is_sla_breached(finding, now)
    finding.retest_last_at = now
    finding.retest_failed_count += 1
    finding.closed_at = None
    dispatch_notification(
        db,
        event="retest_failed",
        level="high",
        subject=f"[RETEST FAILED] {finding.title}",
        message=(
            f"Validation rescan found finding '{finding.title}' still present on "
            f"'{finding.affected_asset}' (signature {finding.correlation_signature}). "
            f"Retest failed #{finding.retest_failed_count}. Finding remains Open; "
            f"age continues from {finding.original_created_at.isoformat()} and is NOT reset."
        ),
        finding=finding,
    )
    return changed


def retest_passed(db: Session, finding: Finding) -> bool:
    """A scan covering the asset does not contain the signature: remediated."""
    now = utcnow()
    finding.status = "Closed"
    finding.is_sla_breached = False
    finding.closed_at = now
    finding.retest_last_at = now
    finding.retest_passed_at = now
    dispatch_notification(
        db,
        event="retest_passed",
        level="info",
        subject=f"[RETEST PASSED] {finding.title}",
        message=(
            f"Validation rescan confirms '{finding.title}' on '{finding.affected_asset}' "
            f"is no longer present (signature {finding.correlation_signature}). "
            f"Finding closed. Originally detected {finding.original_created_at.isoformat()}."
        ),
        finding=finding,
    )
    return True


# ---------------------------------------------------------------------------
# Full re-evaluation pass
# ---------------------------------------------------------------------------


def refresh_sla_for(db: Session, finding: Finding, now: datetime | None = None) -> dict:
    """Evaluate one open finding: breach flag, pending-retest eligibility, alerts."""
    ref = now or utcnow()
    if is_under_exception(finding):
        finding.is_sla_breached = False
        return {"breached": False, "moved_to_retest": False}

    breached_now = is_sla_breached(finding, ref)
    was_breached = finding.is_sla_breached
    finding.is_sla_breached = breached_now
    if breached_now and not was_breached:
        dispatch_notification(
            db,
            event="sla_breached",
            level="critical",
            subject=f"[SLA BREACHED] {finding.title}",
            message=(
                f"Finding '{finding.title}' on asset '{finding.affected_asset}' "
                f"({finding.severity}) exceeded its {finding.sla_days}-day SLA window "
                f"(due {finding.due_date.isoformat()}) and is {overdue_days(finding, ref)} "
                f"day(s) overdue. Current status: {finding.status}."
            ),
            finding=finding,
        )

    moved = False
    if should_enter_retest(finding, ref) and finding.status != "Pending Retest":
        finding.status = "Pending Retest"
        moved = True
        dispatch_notification(
            db,
            event="pending_retest",
            level="info",
            subject=f"[PENDING RETEST] {finding.title}",
            message=(
                f"Finding '{finding.title}' on '{finding.affected_asset}' has SLA status "
                f"'{sla_status(finding, ref)}' and was last scanned "
                f"{finding.last_seen.isoformat()}. A validation rescan is required."
            ),
            finding=finding,
        )
    elif finding.status == "Pending Retest" and not should_enter_retest(finding, ref):
        finding.status = "Open"  # e.g. SLA matrix shortened or a recent scan arrived

    return {"breached": breached_now, "moved_to_retest": moved}


def refresh_all(db: Session) -> dict:
    """Re-evaluate breach flags and pending-retest state for open findings."""
    findings = db.scalars(
        select(Finding).where(Finding.status.in_(OPEN_STATUSES))
    ).all()
    newly_breached = 0
    moved_to_retest = 0
    now = utcnow()
    for finding in findings:
        result = refresh_sla_for(db, finding, now)
        if result["breached"]:
            newly_breached += 1
        if result["moved_to_retest"]:
            moved_to_retest += 1
    pending = (
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(Finding.status == "Pending Retest")
        )
        or 0
    )
    breached_count = (
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(Finding.is_sla_breached.is_(True))
        )
        or 0
    )
    return {
        "checked": len(findings),
        "newly_breached": newly_breached,
        "currently_breached": breached_count,
        "pending_retest": pending,
        "moved_to_retest": moved_to_retest,
    }


def recompute_all_slas(db: Session, now: datetime | None = None) -> int:
    """Re-derive due dates for all non-terminal findings from the current matrix.

    Anchored to ``original_created_at``: matrix changes shift deadlines but
    never reset finding age.
    """
    def as_naive(value: datetime) -> datetime:
        if isinstance(value, datetime) and value.tzinfo is not None:
            return value.replace(tzinfo=None)
        return value

    findings = db.scalars(
        select(Finding).where(Finding.status.in_(OPEN_STATUSES))
    ).all()
    updated = 0
    for finding in findings:
        classification = (
            finding.asset.classification if finding.asset else "Medium"
        )
        due, days = compute_due_date(
            db, finding.severity, classification, baseline=finding.original_created_at
        )
        if finding.sla_days != days or as_naive(finding.due_date) != as_naive(due):
            finding.sla_days = days
            finding.due_date = due
            updated += 1
    if updated:
        db.commit()
        logger.info("Recomputed SLA deadlines for %d findings from updated matrix", updated)
    return updated


def validate_transition(current: str, requested: str) -> tuple[bool, str]:
    if requested not in TRANSITIONS:
        return False, f"Unknown status '{requested}'"
    allowed = TRANSITIONS.get(current, set())
    if requested == current:
        return True, "no change"
    if requested not in allowed:
        return False, (
            f"Illegal transition '{current}' -> '{requested}'. Allowed transitions "
            f"from '{current}': {', '.join(sorted(allowed)) or 'none (terminal state)'}."
        )
    return True, "ok"


# ---------------------------------------------------------------------------
# Asset classification inference
# ---------------------------------------------------------------------------

ASSET_CLASS_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("Critical", ("dc", "db", "db-", "database", "prod", "production", "dmz", "firewall", "core", "sap", "erp", "bank", "mainframe", "domain-controller")),
    ("High", ("web", "app", "api", "gw", "gateway", "vpn", "mail", "auth", "identity", "proxy")),
    ("Medium", ("file", "build", "dev", "test", "qa", "infra", "staging", "backup", "print")),
]


def classify_asset(name: str) -> str:
    """Infer an asset classification from naming conventions (keyword matching).

    Deterministic, documented, and overridable via the Assets screen.
    """
    probe = re.sub(r"[^a-z0-9]+", "-", str(name or "").lower()).strip("-")
    if not probe:
        return "Low"
    for label, keywords in ASSET_CLASS_KEYWORDS:
        for keyword in keywords:
            if keyword in probe:
                return label
    return "Low"


# ---------------------------------------------------------------------------
# Notification dispatch (simulated webhook / email)
# ---------------------------------------------------------------------------


def dispatch_notification(
    db: Session,
    *,
    event: str,
    level: str,
    subject: str,
    message: str,
    finding: Finding | None = None,
    channel: str = "webhook",
) -> Notification:
    """Record a simulated alert; wire this to Jira/ServiceNow/SMTP in prod."""
    notification = Notification(
        channel=channel,
        event=event,
        subject=subject,
        message=message,
        level=level,
    )
    db.add(notification)
    db.flush()
    logger.info(
        "[MOCK %s] event=%s level=%s subject=%r finding_id=%s",
        channel.upper(),
        event,
        level,
        subject,
        finding.id if finding else None,
    )
    return notification
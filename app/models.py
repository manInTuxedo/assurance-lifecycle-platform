"""SQLAlchemy ORM models for the Assurance Finding Lifecycle platform."""
from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from .database import Base

# Access control -------------------------------------------------------------
# One entry per page of the platform. A user gets an explicit level on each
# one, so "read the findings, but do not touch the policy" is expressible.
MODULES = (
    ("dashboard", "Dashboard"),
    ("findings", "Findings"),
    ("sla_tracking", "SLA Tracking"),
    ("retests", "Retest & Validation"),
    ("exceptions", "Exceptions"),
    ("assets", "Assets"),
    ("reports", "Reports"),
    ("settings", "Settings & Policy"),
)
MODULE_KEYS = tuple(key for key, _ in MODULES)

ACCESS_NONE = "none"
ACCESS_READ = "read"
ACCESS_WRITE = "write"
ACCESS_LEVELS = (ACCESS_NONE, ACCESS_READ, ACCESS_WRITE)

ROLE_ADMIN = "admin"
ROLE_CUSTOM = "custom"

# Data reach ----------------------------------------------------------------
# Two more dimensions sit beside the per-page level. A page level answers
# "may this account open the Findings screen"; these answer "which findings
# exist as far as this account is concerned".
#
#   scope_access       business scopes taken from the inventory, comma separated
#   unscoped_access    the Default Asset and any host the inventory has not
#                      explained yet - on by default, because a brand new IP
#                      belongs to nobody until the inventory says otherwise
#   assessment_access  VA, CIS, or both
#
# Both are read filters AND write filters: a row outside them is not hidden,
# it is absent - it will not be listed, counted, charted, edited or ingested.
SOURCE_VA = "VA"        # infrastructure vulnerability assessment
SOURCE_CIS = "CIS"      # benchmark / hardening audit
SOURCE_SAST = "SAST"    # static application security testing
SOURCE_DAST = "DAST"    # dynamic application security testing
SOURCE_PT = "PT"        # penetration test activity
SOURCES = (SOURCE_VA, SOURCE_CIS, SOURCE_SAST, SOURCE_DAST, SOURCE_PT)

# The three application-side assessments share a shape and a set of rules that
# differ from the infrastructure ones, so they are named together where that
# matters rather than being listed by hand each time.
APPSEC_SOURCES = (SOURCE_SAST, SOURCE_DAST, SOURCE_PT)

SOURCE_LABELS = {
    SOURCE_VA: "Vulnerability Assessment",
    SOURCE_CIS: "CIS Benchmark",
    SOURCE_SAST: "Static Application Security Testing",
    SOURCE_DAST: "Dynamic Application Security Testing",
    SOURCE_PT: "Penetration Test",
}

# What binds a finding to an asset. SAST reads source code: it is a statement
# about an application as a whole and has no host of its own, so it lands on
# the asset that carries the application's name. DAST and PT exercise a
# running service, so they land on the host behind the domain in the URL.
BINDS_BY_APPLICATION = (SOURCE_SAST,)
BINDS_BY_DOMAIN = (SOURCE_DAST, SOURCE_PT)

UNSCOPED_LABEL = "Unscoped / Default Asset"
NO_ASSET_SCOPE = "No Asset"

# An application is an asset, but it is not a host. It appears on the register
# so that SAST - which reports on code, not on a machine - has somewhere real
# to land, and it is excluded from the credentialed-coverage story, where it
# would otherwise read as a server nobody has ever scanned.
ASSET_TYPE_APPLICATION = "Application"

# Lifecycle statuses ---------------------------------------------------------
STATUS_OPEN = "Open"
STATUS_IN_PROGRESS = "In Progress"
STATUS_PENDING_RETEST = "Pending Retest"
STATUS_CLOSED = "Closed"

# Closure provenance --------------------------------------------------------
CLOSURE_AUTOMATIC = "automatic"   # proven gone by a credentialed assessment
CLOSURE_MANUAL = "manual"         # closed by a named user

# Assessment coverage of an asset -------------------------------------------
COVERAGE_ASSESSED = "Assessed"        # credentialed assessment succeeded
COVERAGE_INCONCLUSIVE = "Inconclusive"  # host was reached, credentials failed
COVERAGE_NOT_ASSESSED = "Not Assessed"  # host never appeared in an assessment

# Compliance result of a CIS control ----------------------------------------
RESULT_PASSED = "Passed"
RESULT_FAILED = "Failed"
RESULT_MANUAL = "Manual Review"

# Why a finding may sit outside the normal SLA clock. These are technical,
# operational reasons - the platform tracks assurance findings, it does not
# run an enterprise risk-acceptance process.
EXCEPTION_REASONS = (
    "Compensating Control",
    "Vendor Fix Not Available",
    "Change Window Required",
    "Business Downtime Constraint",
    "End-of-Life Replacement Planned",
    "False Positive - Validated",
    "Not Applicable to Configuration",
)

OPEN_STATUSES = (STATUS_OPEN, STATUS_IN_PROGRESS, STATUS_PENDING_RETEST)

# SLA statuses ---------------------------------------------------------------
SLA_WITHIN = "Within SLA"
SLA_APPROACHING = "Approaching SLA"
# The deadline has passed, but the newest evidence predates it: the finding
# was never reassessed after its due date, so nobody has actually seen it
# breach. Kept apart from SLA Exceeded, which is a proven breach.
SLA_PAST_DUE = "Past Due"
SLA_EXCEEDED = "SLA Exceeded"
SLA_UNDER_EXCEPTION = "Under Exception"
SLA_CLOSED = "Closed"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    full_name = Column(String(120), nullable=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default=ROLE_CUSTOM)  # admin | custom
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)

    # Data reach. Empty string means "nothing"; an administrator ignores both
    # columns entirely and reaches everything.
    scope_access = Column(Text, default="")
    assessment_access = Column(Text, default=",".join(SOURCES))
    unscoped_access = Column(Boolean, default=True)

    permissions = relationship("UserPermission", back_populates="user",
                               cascade="all, delete-orphan")

    def access(self, module: str) -> str:
        """Access level this user has on one page.

        An administrator is not stored with eight write rows - the role is the
        answer. Everybody else is exactly what the permission table says, and
        anything not listed is no access at all.
        """
        if self.role == ROLE_ADMIN:
            return ACCESS_WRITE
        for permission in self.permissions:
            if permission.module == module:
                return permission.level or ACCESS_NONE
        return ACCESS_NONE

    def can_read(self, module: str) -> bool:
        return self.access(module) in (ACCESS_READ, ACCESS_WRITE)

    def can_write(self, module: str) -> bool:
        return self.access(module) == ACCESS_WRITE

    def access_map(self) -> dict:
        return {key: self.access(key) for key in MODULE_KEYS}

    # -- data reach ---------------------------------------------------------
    @property
    def is_admin(self) -> bool:
        return self.role == ROLE_ADMIN

    def scope_grants(self) -> list:
        """Business scopes this account may reach.

        An administrator returns None, which every caller reads as "no
        restriction" rather than "no scopes" - the difference matters, because
        an empty list is a real answer meaning this account reaches nothing.
        """
        if self.is_admin:
            return None
        return [v.strip() for v in (self.scope_access or "").split(",") if v.strip()]

    def source_grants(self) -> list:
        if self.is_admin:
            return None
        wanted = {v.strip().upper() for v in (self.assessment_access or "").split(",") if v.strip()}
        return [s for s in SOURCES if s.upper() in wanted]

    def reaches_unscoped(self) -> bool:
        return True if self.is_admin else bool(self.unscoped_access)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": bool(self.is_active),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None,
            "access": self.access_map(),
            "scopes": self.scope_grants(),
            "sources": self.source_grants(),
            "unscoped": self.reaches_unscoped(),
        }


class UserPermission(Base):
    __tablename__ = "user_permissions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    module = Column(String(40), nullable=False, index=True)
    level = Column(String(10), nullable=False, default=ACCESS_NONE)

    user = relationship("User", back_populates="permissions")

    def to_dict(self):
        return {"module": self.module, "level": self.level}


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True)
    asset_code = Column(String(20), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    ip_address = Column(String(50), unique=True, nullable=False, index=True)
    type = Column(String(60), default="Server")          # Server, Firewall, Database, Router...
    scope = Column(String(60), default="Infrastructure") # Crown Jewel, PCI, Published, Infrastructure
    environment = Column(String(30), default="Production")
    site = Column(String(30), default="HQ")
    owner_team = Column(String(60), default="Server Team")
    status = Column(String(30), default="Active")
    # The host name a DAST or PT report will refer to. Those assessments name
    # a URL, never an IP, so without this there is nothing to correlate them
    # against and every one of their findings would land on the Default Asset.
    domain = Column(String(255), nullable=True, index=True)

    # Assessment coverage - "no finding" only means "clean" when the asset was
    # actually assessed with working credentials.
    last_scanned_at = Column(DateTime, nullable=True)
    last_scan_credentialed = Column(Boolean, default=False)
    coverage_state = Column(String(20), default=COVERAGE_NOT_ASSESSED, index=True)

    findings = relationship("Finding", back_populates="asset")

    def to_dict(self):
        return {
            "id": self.id,
            "asset_code": self.asset_code,
            "name": self.name,
            "ip_address": self.ip_address,
            "type": self.type,
            "scope": self.scope,
            "environment": self.environment,
            "site": self.site,
            "owner_team": self.owner_team,
            "status": self.status,
            "domain": self.domain,
            "last_scanned_at": self.last_scanned_at.isoformat() if self.last_scanned_at else None,
            "coverage_state": self.coverage_state,
        }

    def why_it_matters(self):
        scope = (self.scope or "").lower()
        type_ = (self.type or "").lower()
        site = (self.site or "").upper()
        reasons = []
        if "crown" in scope:
            reasons.append("Classified as a **Crown Jewel** – a business critical asset whose compromise directly impacts core operations and revenue.")
        if scope == "pci":
            reasons.append("**PCI in-scope** asset handling or storing cardholder data – subject to PCI DSS control and remediation deadlines.")
        if "published" in scope:
            reasons.append("**Internet-facing / published** service – exposed to external attack surface and external scanning.")
        if scope == "infrastructure":
            reasons.append("**Core infrastructure** component – underpins multiple downstream services and hosts.")
        if not reasons:
            reasons.append("Standard business asset.")
        if "firewall" in type_:
            reasons.append("Network enforcement point – security posture of the perimeter depends on its hardening state.")
        if "database" in type_:
            reasons.append("Contains sensitive data stores – a primary target for data-exfiltration attacks.")
        if "dr" in site.lower():
            reasons.append("Located at the **DR site** – validation and availability matter for business continuity.")
        return " ".join(reasons)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True)
    finding_code = Column(String(30), unique=True, nullable=False, index=True)
    source = Column(String(20), default="VA")            # VA, CIS, SAST, DAST, PT
    plugin_name = Column(String(255), nullable=False, index=True)
    severity = Column(String(20), index=True)            # Critical, High, Medium, Low, Info
    ip_address = Column(String(50), index=True)
    protocol = Column(String(20))
    port = Column(Integer, nullable=True)
    cve = Column(String(200))
    vpr_score = Column(Float)
    description = Column(Text)
    remediation_steps = Column(Text)
    plugin_output = Column(Text)
    first_discovered = Column(DateTime, index=True)
    last_observed = Column(DateTime, index=True)

    # Lifecycle
    status = Column(String(30), default=STATUS_OPEN, index=True)
    sla_status = Column(String(30), default=SLA_WITHIN, index=True)
    due_date = Column(DateTime, index=True)
    sla_rule_applied_id = Column(Integer, ForeignKey("sla_rules.id"), nullable=True)
    sla_days = Column(Integer, nullable=True)

    # Correlation
    is_reappeared = Column(Boolean, default=False)
    reappeared_count = Column(Integer, default=0)
    # When it last came back. Kept so "what came back this month" is a fact
    # about the reappearance, not a guess from Last Observed.
    reappeared_at = Column(DateTime, nullable=True, index=True)
    original_created_at = Column(DateTime)

    # Relationships / links
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    risk_id = Column(String(50), nullable=True)          # RSK-2026-0042
    exception_id = Column(String(50), nullable=True)     # EXC-2026-0014
    retest_status = Column(String(30), nullable=True)    # Pending, Passed, Failed
    # True when the SLA engine raised the retest flag itself. Only a flag the
    # engine raised may be withdrawn by the engine - a retest a person asked
    # for stays until a person resolves it.
    retest_auto_flagged = Column(Boolean, default=False)
    retest_updated_at = Column(DateTime, nullable=True)   # when the flag last changed
    owner = Column(String(80), nullable=True)

    # CIS only - the raw Tenable severity is kept in `severity` so the SLA
    # policy can still match on it; the compliance verdict lives here.
    compliance_result = Column(String(20), nullable=True)  # Passed, Failed, Manual Review

    # Application-side assessments (SAST, DAST, PT). An infrastructure finding
    # is identified by host and port; an application finding is not - it is
    # identified by which application it is in and where inside it, and those
    # have no equivalent among the columns above.
    application_name = Column(String(200), nullable=True, index=True)
    # SAST: the file or component. DAST and PT: the URL or endpoint.
    affected_location = Column(String(500), nullable=True)
    cwe_id = Column(String(40), nullable=True)          # SAST
    owasp_category = Column(String(120), nullable=True)  # DAST
    external_ref = Column(String(60), nullable=True, index=True)  # the report's own Finding ID

    # The complete original sheet row, exactly as the assessment reported it,
    # kept as JSON [[header, value], ...] in the sheet's own column order.
    # Columns the data model has no field for survive here, so the full record
    # page can show the finding without omitting anything.
    raw_row = Column(Text, nullable=True)
    source_file = Column(String(200), nullable=True)   # file the newest evidence came from

    # Closure provenance: who closed it, or which assessment proved it gone.
    closed_at = Column(DateTime, nullable=True)
    closed_by = Column(String(80), nullable=True)
    closure_method = Column(String(20), nullable=True)     # automatic, manual
    closure_evidence = Column(String(160), nullable=True)  # assessment reference

    asset = relationship("Asset", back_populates="findings")
    exceptions = relationship("ExceptionRecord", back_populates="finding")

    @property
    def correlation_key(self):
        return (self.ip_address or "", self.plugin_name or "", self.port or 0, self.protocol or "")

    def closure_label(self):
        """Human readable provenance shown next to a Closed finding."""
        if self.status != STATUS_CLOSED:
            return ""
        if self.closure_method == CLOSURE_AUTOMATIC:
            return f"Closed - automatic (validated by {self.closure_evidence or 'assessment'})"
        if self.closed_by:
            return f"Closed - by {self.closed_by}"
        return "Closed"

    def age_days(self, now=None):
        now = now or datetime.utcnow()
        base = self.original_created_at or self.first_discovered
        return (now - base).days if base else 0


class SLARule(Base):
    __tablename__ = "sla_rules"

    id = Column(Integer, primary_key=True)
    priority_order = Column(Integer, nullable=False, default=0)
    source = Column(String(20), default="Any")           # VA, CIS, Any
    severity = Column(String(20), default="Any")         # Critical, High, Medium, Low, Any
    asset_scope = Column(String(40), default="Any")      # Published, Crown Jewel, PCI, Infrastructure, Any
    asset_type = Column(String(40), default="Any")       # Any, Server, Firewall, ...
    environment = Column(String(30), default="Any")      # Production, Test, Any
    sla_days = Column(Integer, nullable=False, default=90)
    approaching_pct = Column(Integer, default=70)
    retest_pct = Column(Integer, default=80)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "priority_order": self.priority_order,
            "source": self.source,
            "severity": self.severity,
            "asset_scope": self.asset_scope,
            "asset_type": self.asset_type,
            "environment": self.environment,
            "sla_days": self.sla_days,
            "approaching_pct": self.approaching_pct,
            "retest_pct": self.retest_pct,
            "is_active": self.is_active,
        }


class ExceptionRecord(Base):
    __tablename__ = "exception_records"

    id = Column(Integer, primary_key=True)
    exception_code = Column(String(30), unique=True, nullable=False)
    # finding_id is NULL on a control-level exception, which acts as a
    # template applied to matching findings as they appear.
    finding_id = Column(Integer, ForeignKey("findings.id"), index=True, nullable=True)
    control_key = Column(String(255), nullable=True, index=True)  # plugin / control name
    source = Column(String(20), nullable=True)                    # VA, CIS
    scope_ips = Column(Text, nullable=True)                       # CSV, empty = every IP
    applies_to_future = Column(Boolean, default=False)
    parent_id = Column(Integer, ForeignKey("exception_records.id"), nullable=True)
    reason = Column(String(60), default="Compensating Control")
    justification = Column(Text, nullable=True)
    compensating_control = Column(Text, nullable=True)
    approval_ref = Column(String(120), nullable=True)
    starts_at = Column(Date, nullable=True)
    expires_at = Column(Date, nullable=True)
    status = Column(String(30), default="Active")         # Active, Expired
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(80), nullable=True)

    finding = relationship("Finding", back_populates="exceptions")

    def to_dict(self):
        return {
            "id": self.id,
            "exception_code": self.exception_code,
            "finding_id": self.finding_id,
            "reason": self.reason,
            "control_key": self.control_key,
            "source": self.source,
            "scope_ips": self.scope_ips,
            "applies_to_future": bool(self.applies_to_future),
            "justification": self.justification,
            "compensating_control": self.compensating_control,
            "approval_ref": self.approval_ref,
            "starts_at": self.starts_at.isoformat() if self.starts_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
        }


class AuditFile(Base):
    __tablename__ = "audit_files"

    id = Column(Integer, primary_key=True)
    reference_code = Column(String(20), index=True)        # ASM-0007
    filename = Column(String(255))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    record_count = Column(Integer, default=0)
    source_type = Column(String(30))                      # VA Scan, Asset Inventory
    unmapped_ips = Column(Integer, default=0)
    new_findings = Column(Integer, default=0)
    updated_findings = Column(Integer, default=0)
    reappeared_findings = Column(Integer, default=0)
    closed_findings = Column(Integer, default=0)
    assessed_ips = Column(Integer, default=0)        # credentialed, closure allowed
    inconclusive_ips = Column(Integer, default=0)    # reached, credentials failed

    def to_dict(self):
        return {
            "id": self.id,
            "reference_code": self.reference_code,
            "filename": self.filename,
            "uploaded_at": self.uploaded_at.isoformat() if self.uploaded_at else None,
            "record_count": self.record_count,
            "source_type": self.source_type,
            "unmapped_ips": self.unmapped_ips,
            "new_findings": self.new_findings,
            "updated_findings": self.updated_findings,
            "reappeared_findings": self.reappeared_findings,
            "closed_findings": self.closed_findings,
            "assessed_ips": self.assessed_ips,
            "inconclusive_ips": self.inconclusive_ips,
        }


class PolicyChangeLog(Base):
    __tablename__ = "policy_change_logs"

    id = Column(Integer, primary_key=True)
    action = Column(String(500), nullable=False)
    user = Column(String(80))
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "action": self.action,
            "user": self.user,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

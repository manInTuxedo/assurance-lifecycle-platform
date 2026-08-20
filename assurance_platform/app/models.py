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

# Lifecycle statuses ---------------------------------------------------------
STATUS_OPEN = "Open"
STATUS_IN_PROGRESS = "In Progress"
STATUS_PENDING_RETEST = "Pending Retest"
STATUS_CLOSED = "Closed"
STATUS_RISK_ACCEPTED = "Risk Accepted"

OPEN_STATUSES = (STATUS_OPEN, STATUS_IN_PROGRESS, STATUS_PENDING_RETEST)

# SLA statuses ---------------------------------------------------------------
SLA_WITHIN = "Within SLA"
SLA_APPROACHING = "Approaching SLA"
SLA_EXCEEDED = "SLA Exceeded"
SLA_UNDER_EXCEPTION = "Under Exception"
SLA_CLOSED = "Closed"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default="read_only")  # admin | read_write | read_only
    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


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
    source = Column(String(20), default="VA")            # VA, CIS
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
    original_created_at = Column(DateTime)

    # Relationships / links
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    risk_id = Column(String(50), nullable=True)          # RSK-2026-0042
    exception_id = Column(String(50), nullable=True)     # EXC-2026-0014
    retest_status = Column(String(30), nullable=True)    # Pending, Passed, Failed
    owner = Column(String(80), nullable=True)

    asset = relationship("Asset", back_populates="findings")
    exceptions = relationship("ExceptionRecord", back_populates="finding")

    @property
    def correlation_key(self):
        return (self.ip_address or "", self.plugin_name or "", self.port or 0, self.protocol or "")

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
    finding_id = Column(Integer, ForeignKey("findings.id"), index=True)
    reason = Column(String(60), default="Risk Accepted")  # Compensating Control, Risk Accepted, Vendor Roadmap
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
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "created_by": self.created_by,
        }


class AuditFile(Base):
    __tablename__ = "audit_files"

    id = Column(Integer, primary_key=True)
    filename = Column(String(255))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    record_count = Column(Integer, default=0)
    source_type = Column(String(30))                      # VA Scan, Asset Inventory
    unmapped_ips = Column(Integer, default=0)
    new_findings = Column(Integer, default=0)
    updated_findings = Column(Integer, default=0)
    reappeared_findings = Column(Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "filename": self.filename,
            "uploaded_at": self.uploaded_at.isoformat() if self.uploaded_at else None,
            "record_count": self.record_count,
            "source_type": self.source_type,
            "unmapped_ips": self.unmapped_ips,
            "new_findings": self.new_findings,
            "updated_findings": self.updated_findings,
            "reappeared_findings": self.reappeared_findings,
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

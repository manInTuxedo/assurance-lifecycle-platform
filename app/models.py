"""ORM models for the Assurance platform.

Entities:
    Asset           - infrastructure assets with classification & owner
    SLAConfiguration- severity x asset-classification remediation matrix
    Finding         - correlated security findings with full lifecycle state
    ScanUpload      - audit log of every ingested scan file
    Notification    - simulated webhook/email alert outbox
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    """Timezone-aware UTC now."""
    return datetime.now(timezone.utc)


class Asset(Base):
    """An infrastructure asset with business classification and ownership."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    os_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classification: Mapped[str] = mapped_column(
        String(16), nullable=False, default="Medium"
    )  # Critical | High | Medium | Low
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="asset", passive_deletes=True
    )


class SLAConfiguration(Base):
    """Dynamic SLA matrix: severity x asset classification -> remediation days."""

    __tablename__ = "sla_configuration"
    __table_args__ = (
        UniqueConstraint(
            "severity", "asset_classification", name="uq_sla_severity_classification"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    asset_classification: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    sla_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class Finding(Base):
    """A correlated security finding with lifecycle, SLA, retest and exception state.

    Correlation: findings are matched across scans by ``correlation_signature``
    (CVE + PluginID + Asset + Port). Re-encounters update ``last_seen`` only.
    ``original_created_at`` records first detection and is NEVER reset, so
    finding age is preserved across failed retests and reappearances.
    """

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_severity_status", "severity", "status"),
        Index("ix_findings_sig_status", "correlation_signature", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Detection details
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="Low", index=True)
    cvss_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    source: Mapped[str] = mapped_column(String(64), nullable=False, default="VA Scan")
    cve_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    plugin_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    port: Mapped[str | None] = mapped_column(String(16), nullable=True)
    affected_asset: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    asset_id: Mapped[int | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )
    correlation_signature: Mapped[str] = mapped_column(String(512), nullable=False, index=True)

    # Lifecycle
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="Open", index=True
    )  # Open | In Progress | Pending Verification | Pending Retest | Closed | Risk Accepted
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sla_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    is_sla_breached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)

    # Reappearance correlation state
    reappeared: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    reappeared_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    first_reappeared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_reappeared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Retest / validation
    retest_last_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    retest_failed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retest_passed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Risk exceptions
    risk_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    exception_reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    exception_granted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exception_granted_by: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Manual enrichment
    owner: Mapped[str | None] = mapped_column(String(128), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Audit timeline
    original_created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, index=True
    )  # FIRST detection; intentionally never reset
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped[Asset | None] = relationship(back_populates="findings")


class ScanUpload(Base):
    """Audit log of an ingested scan file (drives the Reports screen)."""

    __tablename__ = "scan_uploads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    filename: Mapped[str] = mapped_column(String(256), nullable=False)
    tool: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)

    total: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    skipped: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reappeared: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retest_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    retest_passed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    assets_covered: Mapped[str] = mapped_column(Text, nullable=False, default="[]")


class Notification(Base):
    """Simulated webhook/email alert outbox."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    channel: Mapped[str] = mapped_column(String(16), nullable=False, default="webhook")
    event: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False, default="")
    level: Mapped[str] = mapped_column(String(16), nullable=False, default="info", index=True)
    triggered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utcnow)
"""Pydantic v2 schemas for the refactored public REST API."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["Critical", "High", "Medium", "Low"]
Classification = Literal["Critical", "High", "Medium", "Low"]
Status = Literal[
    "Open", "In Progress", "Pending Verification", "Pending Retest", "Closed", "Risk Accepted"
]
SlaStatus = Literal["On Track", "Approaching", "Breached", "Under Exception", "Resolved"]


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    ip_address: Optional[str] = None
    os_type: Optional[str] = None
    classification: Classification
    owner: Optional[str] = None
    department: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    findings_count: int = 0
    open_findings: int = 0


class AssetCreate(BaseModel):
    name: str = Field(min_length=1)
    ip_address: Optional[str] = None
    os_type: Optional[str] = None
    classification: Classification = "Medium"
    owner: Optional[str] = None
    department: Optional[str] = None


class AssetUpdate(BaseModel):
    ip_address: Optional[str] = None
    os_type: Optional[str] = None
    classification: Optional[Classification] = None
    owner: Optional[str] = None
    department: Optional[str] = None


class SLAConfigUpdate(BaseModel):
    severity: Severity
    asset_classification: Classification
    sla_days: int = Field(ge=1, le=3650)


class SLAConfigBulkUpdate(BaseModel):
    updates: list[SLAConfigUpdate] = Field(min_length=1)


class SLAConfigOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    severity: Severity
    asset_classification: Classification
    sla_days: int
    updated_at: datetime


class FindingOut(BaseModel):
    """Serialized finding incl. computed SLA state and asset metadata."""

    id: int
    title: str
    description: str
    severity: Severity
    cvss_score: float
    source: str
    cve_id: Optional[str] = None
    plugin_id: Optional[str] = None
    port: Optional[str] = None
    affected_asset: str
    asset_id: Optional[int] = None
    asset_name: Optional[str] = None
    asset_classification: Optional[str] = None
    asset_owner: Optional[str] = None
    correlation_signature: str

    status: Status
    due_date: Optional[datetime] = None
    sla_days: int
    is_sla_breached: bool
    sla_status: SlaStatus
    age_days: int

    reappeared: bool
    reappeared_count: int
    first_reappeared_at: Optional[datetime] = None
    last_reappeared_at: Optional[datetime] = None

    retest_last_at: Optional[datetime] = None
    retest_failed_count: int
    retest_passed_at: Optional[datetime] = None

    risk_id: Optional[str] = None
    exception_reason: str = ""
    exception_granted_at: Optional[datetime] = None
    exception_granted_by: Optional[str] = None

    owner: Optional[str] = None
    notes: str = ""

    original_created_at: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    closed_at: Optional[datetime] = None


class FindingEnrichment(BaseModel):
    """Manual enrichment + lifecycle transition payload (all fields optional)."""

    title: Optional[str] = Field(default=None, min_length=1, max_length=512)
    description: Optional[str] = None
    severity: Optional[Severity] = None
    cvss_score: Optional[float] = Field(default=None, ge=0, le=10)
    source: Optional[str] = None
    cve_id: Optional[str] = None
    plugin_id: Optional[str] = None
    port: Optional[str] = None
    status: Optional[Status] = None
    owner: Optional[str] = None
    notes: Optional[str] = None
    risk_id: Optional[str] = None
    exception_reason: Optional[str] = None
    exception_granted_by: Optional[str] = None


class ExceptionLink(BaseModel):
    """Link a finding to a formal risk exception."""

    risk_id: str = Field(min_length=1, description='e.g. "RSK-2025-0142"')
    reason: str = Field(default="", description="Justification recorded by the Risk team")
    granted_by: Optional[str] = None


class FindingListOut(BaseModel):
    items: list[FindingOut]
    total: int
    page: int
    pages: int
    page_size: int


class UploadResult(BaseModel):
    """Result of ingesting one scan file through the correlation engine."""

    filename: str
    total: int
    created: int
    updated: int
    skipped: int
    reappeared: int
    retest_failed: int
    retest_passed: int
    assets_covered: list[str]
    message: str
    details: list[dict] = Field(default_factory=list)


class UploadOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    filename: str
    tool: Optional[str] = None
    ingested_at: datetime
    total: int
    created: int
    updated: int
    skipped: int
    reappeared: int
    retest_failed: int
    retest_passed: int
    assets_covered: list[str]


class StatsSummary(BaseModel):
    total: int
    open: int
    closed: int
    accepted: int
    breached: int
    reappeared: int
    reappeared_events: int
    pending_retest: int
    exceptions: int
    by_severity: list[dict]
    by_status: list[dict]
    by_source: list[dict]
    sla_compliance: dict


class SlaRefreshResult(BaseModel):
    checked: int
    newly_breached: int
    currently_breached: int
    pending_retest: int
    moved_to_retest: int


class RetestSummary(BaseModel):
    pending: int
    failed_total: int
    passed_total: int
    findings: list[FindingOut]


class ExceptionListOut(BaseModel):
    total: int
    items: list[FindingOut]


class ReportSummary(BaseModel):
    avg_days_to_close: float
    open_aging_max_days: int
    reappeared_findings: int
    reappeared_events: int
    uploads_count: int
    by_source: list[dict]
    by_asset_classification: list[dict]
    by_severity: list[dict]
    oldest_open: list[FindingOut]
    uploads: list[UploadOut]


class NotificationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    channel: str
    event: str
    subject: str
    message: str
    level: str
    triggered_at: datetime


class NotificationIn(BaseModel):
    event: str = "manual_test"
    subject: str = Field(min_length=1)
    message: str = ""
    level: str = "info"
    channel: str = "webhook"


class HealthOut(BaseModel):
    status: str
    service: str
    version: str
    findings: int
    time: datetime
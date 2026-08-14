"""FastAPI application: correlation engine, lifecycle/SLA/retest/exception APIs."""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import case, func, or_, select
from sqlalchemy.orm import Session

from . import __version__
from .database import Base, SessionLocal, engine
from .models import Asset, Finding, Notification, SLAConfiguration, ScanUpload, utcnow
from .parsers import build_correlation_signature, parse_scan_file
from .schemas import (
    AssetCreate,
    AssetOut,
    AssetUpdate,
    ExceptionLink,
    ExceptionListOut,
    FindingEnrichment,
    FindingListOut,
    FindingOut,
    HealthOut,
    NotificationIn,
    NotificationOut,
    ReportSummary,
    RetestSummary,
    SLAConfigBulkUpdate,
    SLAConfigOut,
    SLAConfigUpdate,
    SlaRefreshResult,
    StatsSummary,
    UploadOut,
    UploadResult,
)
from .sla_engine import (
    OPEN_STATUSES,
    SEVERITY_LEVELS,
    SEVERITY_ORDER,
    TERMINAL_STATUSES,
    TRANSITIONS,
    classify_asset,
    compute_due_date,
    dispatch_notification,
    finding_age_days,
    get_sla_days,
    is_sla_breached,
    is_terminal,
    mark_reappeared,
    recompute_all_slas,
    refresh_all,
    refresh_sla_for,
    retest_failed,
    retest_passed,
    seed_sla_config,
    sla_status,
    validate_transition,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("assurance.api")

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_SCAN = BASE_DIR.parent / "sample_data" / "mock_scan.json"

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
STATUS_ORDER = ("Open", "In Progress", "Pending Verification", "Pending Retest", "Closed", "Risk Accepted")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def finding_out(finding: Finding) -> FindingOut:
    now = utcnow()
    asset = finding.asset
    return FindingOut(
        id=finding.id,
        title=finding.title,
        description=finding.description,
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        source=finding.source,
        cve_id=finding.cve_id,
        plugin_id=finding.plugin_id,
        port=finding.port,
        affected_asset=finding.affected_asset,
        asset_id=finding.asset_id,
        asset_name=asset.name if asset else finding.affected_asset,
        asset_classification=asset.classification if asset else None,
        asset_owner=asset.owner if asset else None,
        correlation_signature=finding.correlation_signature,
        status=finding.status,
        due_date=finding.due_date,
        sla_days=finding.sla_days,
        is_sla_breached=finding.is_sla_breached,
        sla_status=sla_status(finding, now),
        age_days=finding_age_days(finding, now),
        reappeared=finding.reappeared,
        reappeared_count=finding.reappeared_count,
        first_reappeared_at=finding.first_reappeared_at,
        last_reappeared_at=finding.last_reappeared_at,
        retest_last_at=finding.retest_last_at,
        retest_failed_count=finding.retest_failed_count,
        retest_passed_at=finding.retest_passed_at,
        risk_id=finding.risk_id,
        exception_reason=finding.exception_reason,
        exception_granted_at=finding.exception_granted_at,
        exception_granted_by=finding.exception_granted_by,
        owner=finding.owner,
        notes=finding.notes,
        original_created_at=finding.original_created_at,
        last_seen=finding.last_seen,
        created_at=finding.created_at,
        updated_at=finding.updated_at,
        closed_at=finding.closed_at,
    )


# ---------------------------------------------------------------------------
# Asset resolution & scan processing
# ---------------------------------------------------------------------------


def ensure_asset(db: Session, name: str, ip_address: str | None = None) -> Asset:
    """Get-or-create an asset, inferring classification from naming rules."""
    existing = db.scalar(select(Asset).where(func.lower(Asset.name) == name.lower()))
    if existing is not None:
        return existing
    asset = Asset(
        name=name.strip(),
        ip_address=ip_address,
        classification=classify_asset(name),
    )
    db.add(asset)
    db.flush()
    logger.info("Auto-registered asset %s (classification=%s)", asset.name, asset.classification)
    return asset


def process_upload(db: Session, parsed: dict) -> dict:
    """Correlate, deduplicate and lifecycle-update findings from a parsed scan.

    Correlation rule: findings with an identical signature
    (CVE + PluginID + Asset + Port) resolve to the same record.

    Lifecycle rules applied per upload:
      * closed/accepted finding re-detected -> status "Open", reappeared flags++
      * Pending Retest finding re-detected   -> retest FAILED: stays Open,
        retest_failed_count++, age (original_created_at) preserved
      * Pending Retest finding on a covered asset NOT present in the scan
        -> retest PASSED: status Closed, closed_at set
    """
    findings = parsed["findings"]
    signatures_in_upload: set[str] = set()
    enriched: list[dict] = []
    for raw in findings:
        sig = build_correlation_signature(
            raw.get("cve_id"),
            raw.get("plugin_id"),
            raw.get("title"),
            raw.get("affected_asset"),
            raw.get("port"),
        )
        item = dict(raw)
        item["_signature"] = sig
        enriched.append(item)
        signatures_in_upload.add(sig)

    assets_covered = sorted({item["affected_asset"].strip().lower() for item in enriched})
    created = updated = skipped = reappeared = 0
    retest_failed_count = 0
    retest_passed_count = 0
    details: list[dict] = []

    for raw in enriched:
        title = (raw.get("title") or "").strip()
        asset_name = (raw.get("affected_asset") or "").strip()
        if not title or not asset_name:
            skipped += 1
            details.append({"action": "skipped", "title": title or "(untitled)", "asset": asset_name or "(none)"})
            continue

        asset = ensure_asset(db, asset_name)
        sig = raw["_signature"]
        now = utcnow()

        existing = db.scalar(
            select(Finding).where(Finding.correlation_signature == sig)
        )
        if existing is not None:
            updated += 1
            existing.last_seen = now
            existing.updated_at = now

            if existing.status in TERMINAL_STATUSES:
                if mark_reappeared(db, existing):
                    reappeared += 1
                    details.append({"action": "reappeared", "title": existing.title, "asset": existing.affected_asset, "severity": existing.severity})
            elif existing.status == "Pending Retest":
                if retest_failed(db, existing):
                    retest_failed_count += 1
                    details.append({"action": "retest_failed", "title": existing.title, "asset": existing.affected_asset, "severity": existing.severity})

            # Drift handling: bump severity / refresh cvss without resetting age
            if SEVERITY_ORDER.get(raw.get("severity"), 9) < SEVERITY_ORDER.get(existing.severity, 9):
                existing.severity = raw["severity"]
                existing.cvss_score = raw.get("cvss_score") or existing.cvss_score
                classification = existing.asset.classification if existing.asset else "Medium"
                due, days = compute_due_date(
                    db, existing.severity, classification, baseline=existing.original_created_at
                )
                existing.due_date = due
                existing.sla_days = days
            elif not existing.cvss_score:
                existing.cvss_score = raw.get("cvss_score") or 0.0
            if raw.get("source") and existing.source != raw["source"]:
                existing.source = raw["source"]

            details.append({"action": "updated", "title": existing.title, "asset": existing.affected_asset, "severity": existing.severity})
            continue

        created += 1
        classification = asset.classification
        due, days = compute_due_date(db, raw.get("severity") or "Low", classification, baseline=now)
        finding = Finding(
            title=title,
            description=(raw.get("description") or "").strip(),
            severity=raw.get("severity") or "Low",
            cvss_score=float(raw.get("cvss_score") or 0.0),
            source=raw.get("source") or "VA Scan",
            cve_id=raw.get("cve_id") or None,
            plugin_id=raw.get("plugin_id") or None,
            port=raw.get("port") or None,
            affected_asset=asset_name,
            asset_id=asset.id,
            correlation_signature=sig,
            status="Open",
            due_date=due,
            sla_days=days,
            original_created_at=now,
            last_seen=now,
        )
        db.add(finding)
        db.flush()
        details.append({"action": "created", "title": finding.title, "asset": finding.affected_asset, "severity": finding.severity})
        if finding.severity == "Critical":
            dispatch_notification(
                db,
                event="finding_created",
                level="critical",
                subject=f"[CRITICAL FINDING] {finding.title}",
                message=(
                    f"New {finding.severity} finding '{finding.title}' (CVSS {finding.cvss_score}) "
                    f"on '{finding.affected_asset}' [{asset.classification} asset]. SLA: "
                    f"{days} days (due {due.strftime('%Y-%m-%d %H:%M')} UTC). "
                    f"Signature {sig}."
                ),
                finding=finding,
            )

    # Retest-pass resolution: pending-retest findings on covered assets whose
    # signature is NOT in this scan are considered remediated.
    covered_names = sorted({item["affected_asset"] for item in enriched})
    pending = db.scalars(
        select(Finding).where(
            Finding.status == "Pending Retest",
            Finding.affected_asset.in_(covered_names),
        )
    ).all()
    for finding in pending:
        if finding.correlation_signature in signatures_in_upload:
            continue
        if retest_passed(db, finding):
            retest_passed_count += 1
            details.append({"action": "retest_passed", "title": finding.title, "asset": finding.affected_asset, "severity": finding.severity})

    # Refresh SLA flags for all affected open findings
    refresh_all(db)
    db.commit()

    sources = {f.get("source") for f in findings if f.get("source")}
    upload_log = ScanUpload(
        filename=parsed["filename"],
        tool=", ".join(sorted(sources))[:64] or None,
        total=len(findings),
        created=created,
        updated=updated,
        skipped=skipped,
        reappeared=reappeared,
        retest_failed=retest_failed_count,
        retest_passed=retest_passed_count,
        assets_covered=json.dumps(assets_covered),
    )
    db.add(upload_log)
    db.commit()
    db.refresh(upload_log)

    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "reappeared": reappeared,
        "retest_failed": retest_failed_count,
        "retest_passed": retest_passed_count,
        "assets_covered": assets_covered,
        "total": len(findings),
        "details": details,
    }


def seed_sample_data(db: Session) -> int:
    """Seed the sample scan report on first boot."""
    existing_count = db.scalar(select(func.count()).select_from(Finding)) or 0
    if existing_count > 0:
        return 0
    if not SAMPLE_SCAN.exists():
        return 0
    parsed = parse_scan_file(SAMPLE_SCAN.name, SAMPLE_SCAN.read_bytes())
    result = process_upload(db, parsed)
    logger.info(
        "Seeded sample data: created=%d updated=%d reappeared=%d",
        result["created"], result["updated"], result["reappeared"],
    )
    return result["created"]


# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        seed_sla_config(db)
        seed_sample_data(db)
        sla_result = refresh_all(db)
        db.commit()
        logger.info("Startup SLA pass: %s", sla_result)
    logger.info("%s v%s ready.", app.title, app.version)
    yield


app = FastAPI(
    title="Assurance Finding Lifecycle & SLA Management Platform",
    version=__version__,
    description=(
        "Advanced finding correlation (CVE + PluginID + Asset + Port), lifecycle "
        "tracking, dynamic severity x asset-classification SLA matrix, retest & "
        "validation workflow, risk exceptions, enrichment and analytics."
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------


@app.get("/", include_in_schema=False)
def dashboard(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"app_title": "Assurance Platform", "version": __version__},
    )


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


def compute_stats(db: Session) -> dict:
    total = db.scalar(select(func.count()).select_from(Finding)) or 0
    open_count = (
        db.scalar(select(func.count()).select_from(Finding).where(Finding.status.in_(OPEN_STATUSES))) or 0
    )
    closed = (
        db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "Closed")) or 0
    )
    accepted = (
        db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "Risk Accepted")) or 0
    )
    breached = (
        db.scalar(select(func.count()).select_from(Finding).where(Finding.is_sla_breached.is_(True))) or 0
    )
    reappeared = (
        db.scalar(select(func.count()).select_from(Finding).where(Finding.reappeared.is_(True))) or 0
    )
    reappeared_events = (
        db.scalar(select(func.coalesce(func.sum(Finding.reappeared_count), 0)).select_from(Finding)) or 0
    )
    pending_retest = (
        db.scalar(select(func.count()).select_from(Finding).where(Finding.status == "Pending Retest")) or 0
    )
    exceptions = (
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(Finding.risk_id.is_not(None), Finding.risk_id != "")
        )
        or 0
    )

    severity_rows = db.execute(
        select(Finding.severity, func.count()).group_by(Finding.severity)
    ).all()
    by_severity = [{"label": label, "count": int(count)} for label, count in severity_rows]
    by_severity.sort(key=lambda row: SEVERITY_ORDER.get(row["label"], 9))

    status_rows = db.execute(
        select(Finding.status, func.count()).group_by(Finding.status)
    ).all()
    by_status = [{"label": label, "count": int(count)} for label, count in status_rows]
    by_status.sort(key=lambda row: STATUS_ORDER.index(row["label"]) if row["label"] in STATUS_ORDER else 99)

    source_rows = db.execute(
        select(Finding.source, func.count()).group_by(Finding.source)
    ).all()
    by_source = [{"label": label or "Unknown", "count": int(count)} for label, count in source_rows]

    now = utcnow()
    sla_counts = {"On Track": 0, "Approaching": 0, "Breached": 0, "Under Exception": 0, "Resolved": 0}
    findings = db.scalars(select(Finding)).all()
    for finding in findings:
        status = sla_status(finding, now)
        sla_counts[status] = sla_counts.get(status, 0) + 1

    return {
        "total": int(total),
        "open": int(open_count),
        "closed": int(closed),
        "accepted": int(accepted),
        "breached": int(breached),
        "reappeared": int(reappeared),
        "reappeared_events": int(reappeared_events),
        "pending_retest": int(pending_retest),
        "exceptions": int(exceptions),
        "by_severity": by_severity,
        "by_status": by_status,
        "by_source": by_source,
        "sla_compliance": sla_counts,
    }


@app.get("/api/v1/stats", response_model=StatsSummary, tags=["analytics"])
def get_stats(db: Session = Depends(get_db)):
    """Dashboard aggregates: totals, correlation, retest and SLA compliance."""
    return compute_stats(db)


@app.get("/api/v1/health", response_model=HealthOut, tags=["system"])
def health_check(db: Session = Depends(get_db)):
    total = db.scalar(select(func.count()).select_from(Finding)) or 0
    return HealthOut(
        status="ok",
        service="assurance-platform-api",
        version=__version__,
        findings=int(total),
        time=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Ingestion & correlation engine
# ---------------------------------------------------------------------------


@app.post(
    "/api/v1/upload",
    response_model=UploadResult,
    tags=["ingestion"],
    summary="Ingest a scan report through the correlation engine",
)
async def upload_scan(
    file: UploadFile = File(..., description="JSON/XML scan report (.json, .nessus, .xml)"),
    db: Session = Depends(get_db),
):
    """Upload a scan report and correlate findings against the registry.

    * Same CVE+PluginID+Asset+Port signature -> updates last_seen (no dup).
    * Re-detected terminal finding -> reverts to Open with reappeared=True.
    * Pending Retest finding still present -> retest failed (age preserved).
    * Pending Retest finding gone on a covered asset -> closed (retest passed).
    """
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds the 50 MB upload limit")
    try:
        parsed = parse_scan_file(file.filename or "scan-report", content)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    result = process_upload(db, parsed)
    message = (
        f"Correlated {result['total']} findings from '{parsed['filename']}': "
        f"{result['created']} new, {result['updated']} refreshed, "
        f"{result['reappeared']} reappeared, {result['retest_failed']} retest failed, "
        f"{result['retest_passed']} retest passed, {result['skipped']} skipped."
    )
    logger.info("Upload processed: %s", message)
    return UploadResult(
        filename=parsed["filename"],
        total=result["total"],
        created=result["created"],
        updated=result["updated"],
        skipped=result["skipped"],
        reappeared=result["reappeared"],
        retest_failed=result["retest_failed"],
        retest_passed=result["retest_passed"],
        assets_covered=result["assets_covered"],
        message=message,
        details=result["details"][:100],
    )


# ---------------------------------------------------------------------------
# Findings registry
# ---------------------------------------------------------------------------

SEVERITY_CASE = case(
    (Finding.severity == "Critical", 0),
    (Finding.severity == "High", 1),
    (Finding.severity == "Medium", 2),
    (Finding.severity == "Low", 3),
    else_=9,
)

SORT_OPTIONS = {
    "severity_desc": (SEVERITY_CASE.asc(), Finding.due_date.asc()),
    "severity_asc": (SEVERITY_CASE.desc(), Finding.due_date.asc()),
    "due_date": (Finding.due_date.asc(), SEVERITY_CASE.asc()),
    "last_seen": (Finding.last_seen.desc(),),
    "created_at": (Finding.created_at.desc(),),
    "age": (Finding.original_created_at.asc(),),
    "reappeared": (Finding.reappeared_count.desc(),),
    "title": (Finding.title.asc(),),
}


@app.get("/api/v1/findings", response_model=FindingListOut, tags=["findings"])
def list_findings(
    search: str | None = Query(None),
    status: str | None = Query(None),
    severity: str | None = Query(None),
    source: str | None = Query(None),
    asset: str | None = Query(None),
    reappeared: bool | None = Query(None, description="Filter to reappeared findings"),
    exception: bool | None = Query(None, description="Filter to findings under risk exception"),
    sort: str = Query("severity_desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Paginated, searchable registry with correlation/lifecycle filters."""
    stmt = select(Finding)
    if search:
        pattern = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Finding.title.ilike(pattern),
                Finding.description.ilike(pattern),
                Finding.affected_asset.ilike(pattern),
                Finding.cve_id.ilike(pattern),
                Finding.plugin_id.ilike(pattern),
                Finding.correlation_signature.ilike(pattern),
            )
        )
    if status:
        stmt = stmt.where(Finding.status == status)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if source:
        stmt = stmt.where(Finding.source == source)
    if asset:
        stmt = stmt.where(Finding.affected_asset.ilike(f"%{asset}%"))
    if reappeared is not None:
        stmt = stmt.where(Finding.reappeared.is_(reappeared))
    if exception is not None:
        if exception:
            stmt = stmt.where(Finding.risk_id.is_not(None), Finding.risk_id != "")
        else:
            stmt = stmt.where(or_(Finding.risk_id.is_(None), Finding.risk_id == ""))

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    pages = max(1, -(-int(total) // page_size))
    page = min(page, pages)
    order = SORT_OPTIONS.get(sort, SORT_OPTIONS["severity_desc"])
    items = db.scalars(
        stmt.order_by(*order).offset((page - 1) * page_size).limit(page_size)
    ).all()

    return FindingListOut(
        items=[finding_out(f) for f in items],
        total=int(total),
        page=page,
        pages=pages,
        page_size=page_size,
    )


@app.get("/api/v1/findings/{finding_id}", response_model=FindingOut, tags=["findings"])
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    return finding_out(finding)


@app.patch(
    "/api/v1/findings/{finding_id}",
    response_model=FindingOut,
    tags=["findings"],
    summary="Enrich a finding and/or transition its lifecycle status",
)
def update_finding(
    finding_id: int,
    payload: FindingEnrichment,
    db: Session = Depends(get_db),
):
    """Manual enrichment (Missing Inputs Handling) + lifecycle transition.

    Supported fields: title, description, severity, cvss_score, source,
    cve_id, plugin_id, port, status, owner, notes, risk_id, exception_reason,
    exception_granted_by. Passing ``risk_id=""`` lifts the exception.
    """
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")

    now = utcnow()
    changes: list[str] = []

    if payload.status is not None and payload.status != finding.status:
        allowed, reason = validate_transition(finding.status, payload.status)
        if not allowed:
            raise HTTPException(status_code=400, detail=reason)
        previous = finding.status
        finding.status = payload.status
        if payload.status == "Closed":
            finding.closed_at = now
        elif payload.status in OPEN_STATUSES and finding.closed_at is not None:
            finding.closed_at = None
        changes.append(f"status {previous} -> {payload.status}")
        dispatch_notification(
            db,
            event="status_changed",
            level="info",
            subject=f"[STATUS] {finding.title} moved to {payload.status}",
            message=f"Finding '{finding.title}' transitioned '{previous}' -> '{payload.status}'.",
            finding=finding,
        )

    fields = {
        "title": payload.title,
        "description": payload.description,
        "cvss_score": payload.cvss_score,
        "source": payload.source,
        "cve_id": payload.cve_id,
        "plugin_id": payload.plugin_id,
        "port": payload.port,
        "owner": payload.owner,
        "notes": payload.notes,
    }
    for field, value in fields.items():
        if value is not None and getattr(finding, field) != value:
            setattr(finding, field, value)
            changes.append(field)

    if payload.severity is not None and payload.severity != finding.severity:
        finding.severity = payload.severity
        classification = finding.asset.classification if finding.asset else "Medium"
        due, days = compute_due_date(
            db, finding.severity, classification, baseline=finding.original_created_at
        )
        finding.due_date = due
        finding.sla_days = days
        changes.append("severity")

    if payload.risk_id is not None:
        new_risk = payload.risk_id.strip()
        if new_risk and new_risk != finding.risk_id:
            finding.risk_id = new_risk
            finding.exception_granted_at = now
            finding.exception_granted_by = payload.exception_granted_by or finding.exception_granted_by
            if payload.exception_reason is not None:
                finding.exception_reason = payload.exception_reason
            finding.is_sla_breached = False
            changes.append(f"risk exception {new_risk}")
            dispatch_notification(
                db,
                event="exception_granted",
                level="info",
                subject=f"[EXCEPTION] {finding.title} linked to {new_risk}",
                message=(
                    f"Risk team accepted finding '{finding.title}' on '{finding.affected_asset}' "
                    f"under exception {new_risk}. SLA tracking paused."
                ),
                finding=finding,
            )
        elif not new_risk and finding.risk_id:
            old_risk = finding.risk_id
            finding.risk_id = None
            finding.exception_reason = ""
            finding.exception_granted_at = None
            changes.append(f"exception {old_risk} lifted")
            dispatch_notification(
                db,
                event="exception_removed",
                level="info",
                subject=f"[EXCEPTION LIFTED] {finding.title}",
                message=f"Exception {old_risk} was lifted for '{finding.title}'.",
                finding=finding,
            )
        elif not new_risk:
            pass
        else:
            if payload.exception_reason is not None:
                finding.exception_reason = payload.exception_reason
            changes.append("exception details")

    finding.updated_at = now
    refresh_sla_for(db, finding)
    db.commit()
    db.refresh(finding)
    logger.info("Finding #%d enriched: %s", finding.id, ", ".join(changes) or "no changes")
    return finding_out(finding)


@app.post(
    "/api/v1/findings/{finding_id}/exception",
    response_model=FindingOut,
    tags=["exceptions"],
    summary="Link a finding to a risk exception",
)
def link_exception(finding_id: int, payload: ExceptionLink, db: Session = Depends(get_db)):
    """Formal risk-acceptance link (e.g. RSK-2025-0142)."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    finding.risk_id = payload.risk_id.strip()
    finding.exception_reason = payload.reason
    finding.exception_granted_at = utcnow()
    finding.exception_granted_by = payload.granted_by
    finding.is_sla_breached = False
    dispatch_notification(
        db,
        event="exception_granted",
        level="info",
        subject=f"[EXCEPTION] {finding.title} linked to {payload.risk_id}",
        message=f"Risk exception {payload.risk_id} granted for '{finding.title}'.",
        finding=finding,
    )
    db.commit()
    db.refresh(finding)
    return finding_out(finding)


@app.delete(
    "/api/v1/findings/{finding_id}/exception",
    response_model=FindingOut,
    tags=["exceptions"],
    summary="Lift the risk exception on a finding",
)
def unlink_exception(finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
    if not finding.risk_id:
        raise HTTPException(status_code=400, detail="Finding is not under a risk exception")
    finding.risk_id = None
    finding.exception_reason = ""
    finding.exception_granted_at = None
    finding.exception_granted_by = None
    refresh_sla_for(db, finding)
    db.commit()
    db.refresh(finding)
    return finding_out(finding)


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


def _asset_out(db: Session, asset: Asset) -> AssetOut:
    findings = db.scalars(select(Finding).where(Finding.asset_id == asset.id)).all()
    return AssetOut(
        id=asset.id,
        name=asset.name,
        ip_address=asset.ip_address,
        os_type=asset.os_type,
        classification=asset.classification,
        owner=asset.owner,
        department=asset.department,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        findings_count=len(findings),
        open_findings=sum(1 for f in findings if f.status in OPEN_STATUSES),
    )


@app.get("/api/v1/assets", response_model=list[AssetOut], tags=["assets"])
def list_assets(db: Session = Depends(get_db)):
    """All registered assets with classification, owner and finding counts."""
    assets = db.scalars(select(Asset).order_by(Asset.name.asc())).all()
    return [_asset_out(db, a) for a in assets]


@app.post("/api/v1/assets", response_model=AssetOut, tags=["assets"])
def create_asset(payload: AssetCreate, db: Session = Depends(get_db)):
    """Register an asset manually (classification defaults by naming rules)."""
    exists = db.scalar(select(Asset).where(func.lower(Asset.name) == payload.name.lower()))
    if exists is not None:
        raise HTTPException(status_code=409, detail=f"Asset '{payload.name}' already exists")
    asset = Asset(
        name=payload.name.strip(),
        ip_address=payload.ip_address,
        os_type=payload.os_type,
        classification=payload.classification,
        owner=payload.owner,
        department=payload.department,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return _asset_out(db, asset)


@app.patch("/api/v1/assets/{asset_id}", response_model=AssetOut, tags=["assets"])
def update_asset(asset_id: int, payload: AssetUpdate, db: Session = Depends(get_db)):
    """Update classification / owner metadata; SLA deadlines recompute."""
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value)
    db.commit()
    recompute_all_slas(db)
    db.refresh(asset)
    return _asset_out(db, asset)


# ---------------------------------------------------------------------------
# SLA administration
# ---------------------------------------------------------------------------


@app.get("/api/v1/sla/config", response_model=list[SLAConfigOut], tags=["sla"])
def get_sla_config(db: Session = Depends(get_db)):
    """Full severity x asset-classification remediation matrix."""
    rows = db.scalars(select(SLAConfiguration).order_by(SLAConfiguration.id.asc())).all()
    return rows


@app.patch("/api/v1/sla/config", response_model=list[SLAConfigOut], tags=["sla"])
def update_sla_config(payload: SLAConfigBulkUpdate, db: Session = Depends(get_db)):
    """Upsert matrix rules, then recompute all open findings' deadlines."""
    for update in payload.updates:
        row = db.scalar(
            select(SLAConfiguration).where(
                SLAConfiguration.severity == update.severity,
                SLAConfiguration.asset_classification == update.asset_classification,
            )
        )
        if row is None:
            row = SLAConfiguration(
                severity=update.severity,
                asset_classification=update.asset_classification,
                sla_days=update.sla_days,
            )
            db.add(row)
        else:
            row.sla_days = update.sla_days
    db.commit()
    recompute_all_slas(db)
    rows = db.scalars(select(SLAConfiguration).order_by(SLAConfiguration.id.asc())).all()
    return rows


@app.post("/api/v1/sla/recompute", response_model=dict, tags=["sla"])
def recompute_slas(db: Session = Depends(get_db)):
    """Re-derive due dates for all open findings from the current matrix."""
    updated = recompute_all_slas(db)
    return {"recomputed": updated}


@app.post("/api/v1/sla/refresh", response_model=SlaRefreshResult, tags=["sla"])
def refresh_sla_endpoint(db: Session = Depends(get_db)):
    """Re-evaluate breach flags and pending-retest transitions (scheduled job mock)."""
    result = refresh_all(db)
    db.commit()
    return SlaRefreshResult(**result)


# ---------------------------------------------------------------------------
# Retest & validation
# ---------------------------------------------------------------------------


@app.get("/api/v1/retests", response_model=RetestSummary, tags=["retests"])
def get_retests(db: Session = Depends(get_db)):
    """Findings awaiting validation rescan + aggregate retest history."""
    pending = db.scalars(
        select(Finding)
        .where(Finding.status == "Pending Retest")
        .order_by(Finding.due_date.asc())
    ).all()
    failed_total = (
        db.scalar(select(func.coalesce(func.sum(Finding.retest_failed_count), 0)).select_from(Finding)) or 0
    )
    passed_total = db.scalar(
        select(func.count()).select_from(Finding).where(Finding.retest_passed_at.is_not(None))
    ) or 0
    return RetestSummary(
        pending=len(pending),
        failed_total=int(failed_total),
        passed_total=int(passed_total),
        findings=[finding_out(f) for f in pending],
    )


@app.post("/api/v1/retests/evaluate", response_model=SlaRefreshResult, tags=["retests"])
def evaluate_retests(db: Session = Depends(get_db)):
    """Manually run the retest eligibility sweep (normally triggered by scans)."""
    result = refresh_all(db)
    db.commit()
    return SlaRefreshResult(**result)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


@app.get("/api/v1/exceptions", response_model=ExceptionListOut, tags=["exceptions"])
def list_exceptions(db: Session = Depends(get_db)):
    """All findings currently linked to a risk exception."""
    items = db.scalars(
        select(Finding)
        .where(Finding.risk_id.is_not(None), Finding.risk_id != "")
        .order_by(Finding.exception_granted_at.desc())
    ).all()
    return ExceptionListOut(total=len(items), items=[finding_out(f) for f in items])


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@app.get("/api/v1/reports", response_model=ReportSummary, tags=["reports"])
def get_reports(db: Session = Depends(get_db)):
    """Operational metrics: aging, reopen rate, sources, upload history."""
    closed_rows = db.scalars(
        select(Finding).where(Finding.status == "Closed", Finding.closed_at.is_not(None))
    ).all()

    def as_naive(value: datetime | None) -> datetime | None:
        if value is not None and value.tzinfo is not None:
            return value.replace(tzinfo=None)
        return value

    durations = [
        (as_naive(f.closed_at) - as_naive(f.original_created_at)).total_seconds() / 86400.0
        for f in closed_rows
        if f.closed_at is not None
    ]
    avg_days = round(sum(durations) / len(durations), 1) if durations else 0.0

    open_findings = db.scalars(
        select(Finding).where(Finding.status.in_(OPEN_STATUSES))
    ).all()
    oldest_open = sorted(
        open_findings, key=lambda f: as_naive(f.original_created_at)
    )[:8]

    reappeared_findings = (
        db.scalar(select(func.count()).select_from(Finding).where(Finding.reappeared.is_(True))) or 0
    )
    reappeared_events = (
        db.scalar(select(func.coalesce(func.sum(Finding.reappeared_count), 0)).select_from(Finding)) or 0
    )

    by_source_rows = db.execute(
        select(Finding.source, func.count()).group_by(Finding.source)
    ).all()
    by_source = [{"label": label or "Unknown", "count": int(count)} for label, count in by_source_rows]

    class_rows = db.execute(
        select(Asset.classification, func.count(Asset.id))
        .select_from(Finding)
        .join(Asset, Finding.asset_id == Asset.id)
        .group_by(Asset.classification)
    ).all()
    by_classification = [{"label": label or "Unknown", "count": int(count)} for label, count in class_rows]
    by_classification.sort(key=lambda row: SEVERITY_ORDER.get(row["label"], 9))

    severity_rows = db.execute(
        select(Finding.severity, func.count()).group_by(Finding.severity)
    ).all()
    by_severity = [{"label": label, "count": int(count)} for label, count in severity_rows]
    by_severity.sort(key=lambda row: SEVERITY_ORDER.get(row["label"], 9))

    uploads = db.scalars(
        select(ScanUpload).order_by(ScanUpload.ingested_at.desc()).limit(12)
    ).all()

    def upload_out(u: ScanUpload) -> UploadOut:
        try:
            covered = json.loads(u.assets_covered)
        except (ValueError, TypeError):
            covered = []
        return UploadOut(
            id=u.id,
            filename=u.filename,
            tool=u.tool,
            ingested_at=u.ingested_at,
            total=u.total,
            created=u.created,
            updated=u.updated,
            skipped=u.skipped,
            reappeared=u.reappeared,
            retest_failed=u.retest_failed,
            retest_passed=u.retest_passed,
            assets_covered=covered,
        )

    return ReportSummary(
        avg_days_to_close=avg_days,
        open_aging_max_days=max((finding_age_days(f) for f in open_findings), default=0),
        reappeared_findings=int(reappeared_findings),
        reappeared_events=int(reappeared_events),
        uploads_count=db.scalar(select(func.count()).select_from(ScanUpload)) or 0,
        by_source=by_source,
        by_asset_classification=by_classification,
        by_severity=by_severity,
        oldest_open=[finding_out(f) for f in oldest_open],
        uploads=[upload_out(u) for u in uploads],
    )


# ---------------------------------------------------------------------------
# Upload history / notifications
# ---------------------------------------------------------------------------


@app.get("/api/v1/uploads", response_model=list[UploadOut], tags=["ingestion"])
def list_uploads(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Recent scan ingestion history with correlation results."""
    uploads = db.scalars(
        select(ScanUpload).order_by(ScanUpload.ingested_at.desc()).limit(limit)
    ).all()
    result = []
    for u in uploads:
        try:
            covered = json.loads(u.assets_covered)
        except (ValueError, TypeError):
            covered = []
        result.append(
            UploadOut(
                id=u.id,
                filename=u.filename,
                tool=u.tool,
                ingested_at=u.ingested_at,
                total=u.total,
                created=u.created,
                updated=u.updated,
                skipped=u.skipped,
                reappeared=u.reappeared,
                retest_failed=u.retest_failed,
                retest_passed=u.retest_passed,
                assets_covered=covered,
            )
        )
    return result


@app.get("/api/v1/notifications", response_model=list[NotificationOut], tags=["notifications"])
def list_notifications(
    limit: int = Query(10, ge=1, le=100),
    level: str | None = Query(None),
    db: Session = Depends(get_db),
):
    stmt = select(Notification).order_by(Notification.triggered_at.desc()).limit(limit)
    if level:
        stmt = stmt.where(Notification.level == level)
    return db.scalars(stmt).all()


@app.post("/api/v1/notifications/test", response_model=NotificationOut, tags=["notifications"])
def send_test_notification(payload: NotificationIn, db: Session = Depends(get_db)):
    notification = dispatch_notification(
        db,
        event=payload.event,
        level=payload.level,
        subject=payload.subject,
        message=payload.message,
        channel=payload.channel,
    )
    db.commit()
    db.refresh(notification)
    return notification


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
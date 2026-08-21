"""Assurance Finding Lifecycle & SLA Management Platform - FastAPI application."""
import os
import re
from datetime import date, datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from . import models, parsers
from .auth import (
    COOKIE_NAME,
    create_access_token,
    hash_password,
    require_admin,
    require_read,
    require_write,
    ui_user,
    verify_password,
)
from .database import Base, SessionLocal, engine, get_db
from .sla_engine import (
    domain_for,
    recalculate_all,
    recalculate_finding,
    simulate_match,
)

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="Assurance Finding Lifecycle & SLA Management Platform")

# Create tables on boot (idempotent) and seed defaults.
Base.metadata.create_all(bind=engine)
from sample_data.seed_data import seed_if_empty  # noqa: E402
from .startup import load_asset_inventory  # noqa: E402

_seed_db = SessionLocal()
try:
    seed_if_empty(_seed_db)
    # Load Asset Inventory from disk on startup
    load_asset_inventory(_seed_db, BASE_DIR.parent)
finally:
    _seed_db.close()


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _iso(dt):
    return dt.isoformat() if dt else None


def _next_code(db, model, prefix, attr, year):
    like = f"{prefix}{year}-%"
    rows = db.query(getattr(model, attr)).filter(getattr(model, attr).like(like)).all()
    mx = 0
    for (code,) in rows:
        try:
            mx = max(mx, int(code.rsplit("-", 1)[1]))
        except (ValueError, IndexError):
            pass
    return f"{prefix}{year}-{mx + 1:04d}"


def next_finding_code(db, year):
    return _next_code(db, models.Finding, "FND", "finding_code", year)


def next_exception_code(db, year):
    return _next_code(db, models.ExceptionRecord, "EXC", "exception_code", year)


def next_asset_code(db):
    rows = db.query(models.Asset.asset_code).all()
    mx = 0
    for (code,) in rows:
        m = re.search(r"AST-(\d+)", code or "")
        if m:
            mx = max(mx, int(m.group(1)))
    return f"AST-{mx + 1:04d}"


def finding_dict(f: models.Finding):
    asset = f.asset
    now = datetime.utcnow()
    return {
        "id": f.id,
        "finding_code": f.finding_code,
        "source": f.source,
        "plugin_name": f.plugin_name,
        "severity": f.severity,
        "ip_address": f.ip_address,
        "protocol": f.protocol,
        "port": f.port,
        "cve": f.cve,
        "vpr_score": f.vpr_score,
        "description": f.description,
        "remediation_steps": f.remediation_steps,
        "plugin_output": f.plugin_output,
        "first_discovered": _iso(f.first_discovered),
        "last_observed": _iso(f.last_observed),
        "status": f.status,
        "sla_status": f.sla_status,
        "due_date": _iso(f.due_date),
        "sla_days": f.sla_days,
        "age_days": f.age_days(now),
        "is_reappeared": bool(f.is_reappeared),
        "reappeared_count": f.reappeared_count or 0,
        "risk_id": f.risk_id,
        "exception_id": f.exception_id,
        "retest_status": f.retest_status,
        "owner": f.owner,
        "asset": asset.to_dict() if asset else None,
    }


def log_policy_change(db, action: str, user):
    db.add(models.PolicyChangeLog(action=action, user=getattr(user, "username", "system")))
    db.commit()


def _ordered_rules(db):
    return list(db.query(models.SLARule).order_by(models.SLARule.priority_order).all())


# ---------------------------------------------------------------------------
# Ingestion engines
# ---------------------------------------------------------------------------

def ingest_scan(db: Session, filename: str, rows: list[dict]) -> dict:
    """Correlate a VA/CIS scan against existing findings & assets."""
    now = datetime.utcnow()
    scan_date = parsers.scan_date_from_filename(filename) or now
    
    # Detect report type from content
    detected_source = rows[0].get("detected_source", "VA") if rows else "VA"
    
    # For VA reports: check which IPs have credentialed scans
    credentialed_ips = {}
    if detected_source == "VA":
        credentialed_ips = parsers.check_credentialed_scan(rows)
    
    default_asset = db.query(models.Asset).filter(models.Asset.asset_code == "AST-0000").first()
    if not default_asset:
        default_asset = models.Asset(
            asset_code="AST-0000",
            name="Default Asset / Unmapped IPs",
            ip_address="0.0.0.0",
            type="Server",
            scope="Infrastructure",
            environment="Production",
            site="HQ",
            owner_team="Server Team",
            status="Active",
        )
        db.add(default_asset)
        db.commit()
        db.refresh(default_asset)

    unmapped = new = updated = reappeared = skipped_uncredentialed = 0

    for row in rows:
        ip = (row.get("ip_address") or "").strip()
        port = row.get("port") or 0
        plugin = (row.get("plugin_name") or "").strip()
        proto = (row.get("protocol") or "").strip()
        
        # Skip Nessus Scan Information rows (metadata only)
        if "nessus scan information" in plugin.lower():
            continue
        
        # For VA reports: Only process IPs with credentialed scans
        if detected_source == "VA":
            if ip not in credentialed_ips or not credentialed_ips[ip]:
                skipped_uncredentialed += 1
                continue
        
        # Determine severity (for CIS reports, map status to severity)
        severity = row.get("severity", "Info").strip().capitalize()
        if detected_source == "CIS":
            # Map CIS status to severity: High->Failed, Medium->Manual, Info->Passed
            original_severity = severity.lower()
            if original_severity == "high":
                severity = "Failed"
            elif original_severity == "medium":
                severity = "Manual Check"
            else:
                severity = "Passed"

        asset = None
        if ip:
            asset = db.query(models.Asset).filter(
                models.Asset.ip_address == ip
            ).first()
        if asset is None:
            has_info = any(row.get(k) for k in (
                "asset_name", "asset_type", "asset_scope",
                "asset_environment", "asset_site", "asset_owner_team",
            ))
            if has_info:
                # Scan carries asset metadata -> create the asset automatically
                asset = models.Asset(
                    asset_code=row.get("asset_code") or next_asset_code(db),
                    name=row.get("asset_name") or ip,
                    ip_address=ip,
                    type=row.get("asset_type") or "Server",
                    scope=row.get("asset_scope") or "Infrastructure",
                    environment=row.get("asset_environment") or "Production",
                    site=row.get("asset_site") or "HQ",
                    owner_team=row.get("asset_owner_team") or "Server Team",
                    status=row.get("asset_status") or "Active",
                )
                db.add(asset)
                db.flush()
            else:
                asset = default_asset
                unmapped += 1
        else:
            # Sync inventory attributes carried by the scan row
            for attr, key in (("name", "asset_name"), ("type", "asset_type"),
                              ("scope", "asset_scope"), ("environment", "asset_environment"),
                              ("site", "asset_site"), ("owner_team", "asset_owner_team"),
                              ("status", "asset_status")):
                val = row.get(key)
                if val:
                    setattr(asset, attr, val)

        # --- Correlation Logic ---
        # VA: Composite Key = (IP + Plugin Name + Port + Protocol)
        # CIS: Composite Key = (IP + Plugin Name) - no port needed
        
        if detected_source == "CIS":
            # CIS correlation: IP + Plugin Name only
            existing = (
                db.query(models.Finding)
                .filter(
                    models.Finding.ip_address == ip,
                    models.Finding.plugin_name == plugin,
                    models.Finding.source == "CIS",
                )
                .order_by(models.Finding.first_discovered.asc())
                .first()
            )
        else:
            # VA correlation: IP + Plugin Name + Port + Protocol
            existing = (
                db.query(models.Finding)
                .filter(
                    models.Finding.ip_address == ip,
                    models.Finding.plugin_name == plugin,
                    models.Finding.port == port,
                    models.Finding.protocol == proto,
                    models.Finding.source == "VA",
                )
                .order_by(models.Finding.first_discovered.asc())
                .first()
            )

        if existing:
            # Finding exists - update it
            if existing.status == models.STATUS_CLOSED:
                # Closed finding reappeared (Fixed -> Reappeared)
                existing.status = models.STATUS_OPEN
                existing.is_reappeared = True
                existing.reappeared_count = (existing.reappeared_count or 0) + 1
                existing.asset_id = asset.id
                reappeared += 1
            else:
                # Existing open finding (update Last Observed = implicit retest)
                updated += 1
            existing.last_observed = row.get("last_observed") or scan_date
            existing.source = detected_source
            existing.severity = severity  # Update severity in case it changed
            continue

        # --- New finding ---
        first = row.get("first_discovered") or scan_date
        f = models.Finding(
            finding_code=next_finding_code(db, first.year),
            source=detected_source,
            plugin_name=plugin,
            severity=severity,
            ip_address=ip,
            protocol=proto,
            port=port,
            cve=row.get("cve"),
            vpr_score=row.get("vpr_score"),
            description=row.get("description"),
            remediation_steps=row.get("remediation_steps"),
            plugin_output=row.get("plugin_output"),
            first_discovered=first,
            last_observed=row.get("last_observed") or scan_date,
            original_created_at=first,
            status=models.STATUS_OPEN,
            asset_id=asset.id,
        )
        db.add(f)
        new += 1
        db.flush()

    db.flush()
    recalculate_all(db)

    db.add(models.AuditFile(
        filename=filename,
        uploaded_at=now,
        record_count=len(rows),
        source_type=f"{detected_source} Scan",
        unmapped_ips=unmapped,
        new_findings=new,
        updated_findings=updated,
        reappeared_findings=reappeared,
    ))
    db.commit()
    
    result = {
        "records": len(rows),
        "new": new,
        "updated": updated,
        "reappeared": reappeared,
        "unmapped": unmapped,
        "detected_type": detected_source,
    }
    
    if detected_source == "VA":
        result["skipped_uncredentialed"] = skipped_uncredentialed
    
    return result


def ingest_assets(db: Session, filename: str, rows: list[dict]) -> dict:
    now = datetime.utcnow()
    created = updated = 0
    for row in rows:
        ip = (row.get("ip_address") or "").strip()
        if not ip:
            continue
        existing = db.query(models.Asset).filter(
            func.lower(models.Asset.ip_address) == ip.lower()
        ).first()
        fields = dict(
            name=row.get("name") or (existing.name if existing else ip),
            type=row.get("type") or (existing.type if existing else "Server"),
            scope=row.get("scope") or (existing.scope if existing else "Infrastructure"),
            environment=row.get("environment") or (existing.environment if existing else "Production"),
            site=row.get("site") or (existing.site if existing else "HQ"),
            owner_team=row.get("owner_team") or (existing.owner_team if existing else "Server Team"),
            status=row.get("status") or (existing.status if existing else "Active"),
        )
        if existing:
            for k, v in fields.items():
                setattr(existing, k, v)
            updated += 1
        else:
            db.add(models.Asset(
                asset_code=row.get("asset_code") or next_asset_code(db),
                ip_address=ip,
                **fields,
            ))
            created += 1
    db.flush()
    recalculate_all(db)
    db.add(models.AuditFile(
        filename=filename, uploaded_at=now, record_count=len(rows),
        source_type="Asset Inventory", unmapped_ips=0,
    ))
    db.commit()
    return {"records": len(rows), "created": created, "updated": updated}


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------

@app.get("/login")
def login_page(request: Request):
    user = ui_user(request, SessionLocal())
    if user:
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(request, "login.html")


@app.post("/api/login")
async def api_login(request: Request, db: Session = Depends(get_db)):
    body = await request.json()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token(user.username, user.role)
    response = JSONResponse({"ok": True, "user": user.to_dict()})
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, max_age=720 * 60, samesite="lax"
    )
    return response


@app.post("/api/logout")
def api_logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------

def _render(request: Request, template: str, ctx: dict = None):
    db = SessionLocal()
    try:
        user = ui_user(request, db)
        if not user:
            return RedirectResponse("/login", status_code=302)
        data = {"request": request, "current_user": user, "path": request.url.path}
        if ctx:
            data.update(ctx)
        return templates.TemplateResponse(request, template, data)
    finally:
        db.close()


@app.get("/")
def dashboard_page(request: Request):
    return _render(request, "dashboard.html")


@app.get("/findings")
def findings_page(request: Request):
    return _render(request, "findings.html")


@app.get("/sla-tracking")
def sla_tracking_page(request: Request):
    return _render(request, "sla_tracking.html")


@app.get("/assets")
def assets_page(request: Request):
    return _render(request, "assets.html")


@app.get("/exceptions")
def exceptions_page(request: Request):
    return _render(request, "exceptions.html")


@app.get("/retests")
def retests_page(request: Request):
    return _render(request, "retests.html")





@app.get("/reports")
def reports_page(request: Request):
    return _render(request, "reports.html")


@app.get("/settings")
def settings_page(request: Request):
    db = SessionLocal()
    try:
        user = ui_user(request, db)
        if not user:
            return RedirectResponse("/login", status_code=302)
        if user.role != "admin":
            return RedirectResponse("/", status_code=302)
    finally:
        db.close()
    return _render(request, "settings.html")


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------

@app.get("/api/summary")
def api_summary(request: Request, db: Session = Depends(get_db)):
    ui_user(request, db)  # auth gate for server context (raises via JSON below)
    user = _require_user(request, db)

    open_findings = db.query(models.Finding).filter(
        models.Finding.status.in_(models.OPEN_STATUSES)
    )
    total_open = open_findings.count()

    def count_sla(st):
        return db.query(models.Finding).filter(
            models.Finding.status.in_(models.OPEN_STATUSES),
            models.Finding.sla_status == st,
        ).count()

    within = count_sla(models.SLA_WITHIN)
    approaching = count_sla(models.SLA_APPROACHING)
    exceeded = count_sla(models.SLA_EXCEEDED)
    under_exc = count_sla(models.SLA_UNDER_EXCEPTION)

    pending_retest = db.query(models.Finding).filter(
        models.Finding.status.in_(models.OPEN_STATUSES),
        models.Finding.retest_status == "Pending",
    ).count()

    active_exceptions = db.query(models.ExceptionRecord).filter(
        models.ExceptionRecord.status == "Active",
    ).count()

    severity_counts = {sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Info")}
    for sev, cnt in db.query(models.Finding.severity, func.count()).group_by(
        models.Finding.severity
    ).all():
        if sev in severity_counts:
            severity_counts[sev] = cnt

    workflow = {st: 0 for st in ("Open", "In Progress", "Pending Retest", "Closed", "Risk Accepted")}
    for st, cnt in db.query(models.Finding.status, func.count()).group_by(
        models.Finding.status
    ).all():
        if st in workflow:
            workflow[st] = cnt

    recent = (
        db.query(models.Finding)
        .filter(models.Finding.status.in_(models.OPEN_STATUSES))
        .order_by(models.Finding.last_observed.desc())
        .limit(8)
        .all()
    )

    exc_recent = (
        db.query(models.ExceptionRecord)
        .filter(models.ExceptionRecord.status == "Active")
        .order_by(models.ExceptionRecord.created_at.desc())
        .limit(5)
        .all()
    )
    exc_list = []
    for ex in exc_recent:
        f = ex.finding
        exc_list.append({
            "exception_code": ex.exception_code,
            "reason": ex.reason,
            "expires_at": _iso(ex.expires_at),
            "finding_code": f.finding_code if f else None,
            "finding_id": f.id if f else None,
            "severity": f.severity if f else None,
        })

    last_audit = db.query(models.AuditFile).order_by(models.AuditFile.id.desc()).first()

    return {
        "user": user.to_dict(),
        "total_open": total_open,
        "within_sla": within,
        "approaching_sla": approaching,
        "sla_exceeded": exceeded,
        "under_exception": under_exc,
        "pending_retest": pending_retest,
        "active_exceptions": active_exceptions,
        "total_findings": db.query(models.Finding).count(),
        "closed": db.query(models.Finding).filter(models.Finding.status == "Closed").count(),
        "risk_accepted": db.query(models.Finding).filter(models.Finding.status == "Risk Accepted").count(),
        "severity_counts": severity_counts,
        "workflow": workflow,
        "assets_total": db.query(models.Asset).filter(models.Asset.asset_code != "AST-0000").count(),
        "assets_assessed": len(db.query(models.Finding.asset_id).distinct().all()),
        "unmapped_ips": (last_audit.unmapped_ips if last_audit else 0),
        "recent": [finding_dict(f) for f in recent],
        "exceptions_recent": exc_list,
    }


@app.get("/api/dashboard/charts")
def api_dashboard_charts(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    now = datetime.utcnow()
    weeks = 8
    labels, opened, exceeded_cum, within, approaching = [], [], [], [], []
    all_exceeded_ids = {
        f.id for f in db.query(models.Finding).filter(
            models.Finding.sla_status == models.SLA_EXCEEDED
        ).all()
    }
    for i in range(weeks - 1, -1, -1):
        start = now - timedelta(days=7 * (i + 1))
        end = now - timedelta(days=7 * i)
        labels.append(start.strftime("%b %d"))
        q = db.query(models.Finding).filter(
            models.Finding.first_discovered >= start,
            models.Finding.first_discovered < end,
        )
        opened.append(q.count())
        ids = {f.id for f in q.all()}
        exceeded_cum.append(len(ids & all_exceeded_ids))
        within.append(db.query(models.Finding).filter(
            models.Finding.first_discovered >= start,
            models.Finding.first_discovered < end,
            models.Finding.sla_status == models.SLA_WITHIN,
        ).count())
        approaching.append(db.query(models.Finding).filter(
            models.Finding.first_discovered >= start,
            models.Finding.first_discovered < end,
            models.Finding.sla_status == models.SLA_APPROACHING,
        ).count())

    retest_labels = ["Pending", "Passed", "Failed"]
    retest_values = []
    for st in retest_labels:
        retest_values.append(db.query(models.Finding).filter(
            models.Finding.retest_status == st,
        ).count())
    not_requested = db.query(models.Finding).filter(
        models.Finding.retest_status.is_(None),
        models.Finding.status.in_(models.OPEN_STATUSES),
    ).count()
    retest_labels.append("Not Requested")
    retest_values.append(not_requested)

    return {
        "aging_trend": {
            "labels": labels,
            "opened": opened,
            "exceeded": exceeded_cum,
            "within": within,
            "approaching": approaching,
        },
        "retest_doughnut": {"labels": retest_labels, "values": retest_values},
    }


# ---------------------------------------------------------------------------
# Findings API
# ---------------------------------------------------------------------------

@app.get("/api/findings")
def api_findings(
    request: Request,
    db: Session = Depends(get_db),
    q: str = "",
    source: str = "",
    severity: str = "",
    scope: str = "",
    environment: str = "",
    owner_team: str = "",
    sla_status: str = "",
    retest: str = "",
    status: str = "",
    limit: int = 200,
):
    _require_user(request, db)
    query = db.query(models.Finding)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            models.Finding.finding_code.ilike(like),
            models.Finding.plugin_name.ilike(like),
            models.Finding.ip_address.ilike(like),
            models.Finding.cve.ilike(like),
        ))
    if source:
        query = query.filter(models.Finding.source == source)
    if severity:
        query = query.filter(models.Finding.severity == severity)
    if scope:
        query = query.join(models.Asset).filter(models.Asset.scope == scope)
    if environment:
        query = query.join(models.Asset).filter(models.Asset.environment == environment)
    if owner_team:
        query = query.join(models.Asset).filter(models.Asset.owner_team == owner_team)
    if sla_status:
        query = query.filter(models.Finding.sla_status == sla_status)
    if retest:
        if retest == "None":
            query = query.filter(models.Finding.retest_status.is_(None))
        else:
            query = query.filter(models.Finding.retest_status == retest)
    if status:
        query = query.filter(models.Finding.status == status)

    findings = query.order_by(
        models.Finding.sla_status.asc(), models.Finding.severity.desc()
    ).limit(limit).all()
    return {"findings": [finding_dict(f) for f in findings]}


@app.post("/api/findings/bulk/owner")
def api_bulk_owner(body: dict, user=Depends(require_write), db: Session = Depends(get_db)):
    ids = body.get("ids") or []
    owner = (body.get("owner") or "").strip() or None
    count = 0
    for f in db.query(models.Finding).filter(models.Finding.id.in_(ids)).all():
        f.owner = owner
        count += 1
    db.commit()
    return {"ok": True, "count": count}


@app.post("/api/findings/bulk/retest")
def api_bulk_retest(body: dict, user=Depends(require_write), db: Session = Depends(get_db)):
    ids = body.get("ids") or []
    rules = _ordered_rules(db)
    count = 0
    for f in db.query(models.Finding).filter(models.Finding.id.in_(ids)).all():
        f.status = models.STATUS_PENDING_RETEST
        f.retest_status = "Pending"
        recalculate_finding(db, f, rules)
        count += 1
    db.commit()
    return {"ok": True, "count": count}


@app.post("/api/findings/bulk/exception")
def api_bulk_exception(body: dict, user=Depends(require_write), db: Session = Depends(get_db)):
    ids = body.get("ids") or []
    reason = body.get("reason") or "Risk Accepted"
    expires = body.get("expires_at")
    try:
        expires_date = date.fromisoformat(expires) if expires else None
    except ValueError:
        expires_date = None
    rules = _ordered_rules(db)
    count = 0
    year = datetime.utcnow().year
    for f in db.query(models.Finding).filter(models.Finding.id.in_(ids)).all():
        code = next_exception_code(db, year)
        db.add(models.ExceptionRecord(
            exception_code=code, finding_id=f.id, reason=reason,
            expires_at=expires_date, status="Active", created_by=user.username,
        ))
        f.exception_id = code
        recalculate_finding(db, f, rules)
        count += 1
    db.commit()
    return {"ok": True, "count": count}


@app.post("/api/findings/bulk/risk")
def api_bulk_risk(body: dict, user=Depends(require_write), db: Session = Depends(get_db)):
    ids = body.get("ids") or []
    risk_id = (body.get("risk_id") or "").strip() or None
    count = 0
    for f in db.query(models.Finding).filter(models.Finding.id.in_(ids)).all():
        f.risk_id = risk_id
        count += 1
    db.commit()
    return {"ok": True, "count": count}


@app.post("/api/findings/bulk/close")
def api_bulk_close(body: dict, user=Depends(require_write), db: Session = Depends(get_db)):
    ids = body.get("ids") or []
    rules = _ordered_rules(db)
    count = 0
    for f in db.query(models.Finding).filter(models.Finding.id.in_(ids)).all():
        f.status = models.STATUS_CLOSED
        recalculate_finding(db, f, rules)
        count += 1
    db.commit()
    return {"ok": True, "count": count}


@app.get("/api/findings/{finding_id}")
def api_finding_detail(finding_id: int, request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    exc = None
    if f.exception_id:
        exc_rec = db.query(models.ExceptionRecord).filter(
            models.ExceptionRecord.finding_id == f.id
        ).order_by(models.ExceptionRecord.id.desc()).first()
        if exc_rec:
            exc = exc_rec.to_dict()
    return {"finding": finding_dict(f), "exception": exc}


@app.post("/api/findings/{finding_id}/owner")
def api_assign_owner(finding_id: int, body: dict, user=Depends(require_write),
                     db: Session = Depends(get_db)):
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.owner = (body.get("owner") or "").strip() or None
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/retest")
def api_send_retest(finding_id: int, user=Depends(require_write),
                    db: Session = Depends(get_db)):
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = models.STATUS_PENDING_RETEST
    f.retest_status = "Pending"
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/retest-result")
def api_retest_result(finding_id: int, body: dict, user=Depends(require_write),
                      db: Session = Depends(get_db)):
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    result = (body.get("result") or "passed").lower()
    if result == "passed":
        f.status = models.STATUS_CLOSED
        f.retest_status = "Passed"
    else:
        f.status = models.STATUS_OPEN
        f.retest_status = "Failed"
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/close")
def api_close_finding(finding_id: int, user=Depends(require_write),
                      db: Session = Depends(get_db)):
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.status = models.STATUS_CLOSED
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/status")
def api_set_status(finding_id: int, body: dict, user=Depends(require_write),
                   db: Session = Depends(get_db)):
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    st = body.get("status") or models.STATUS_OPEN
    allowed = {models.STATUS_OPEN, models.STATUS_IN_PROGRESS,
               models.STATUS_PENDING_RETEST, models.STATUS_RISK_ACCEPTED}
    if st not in allowed:
        raise HTTPException(400, "Invalid status")
    f.status = st
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/exception")
def api_add_exception(finding_id: int, body: dict, user=Depends(require_write),
                      db: Session = Depends(get_db)):
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    code = next_exception_code(db, datetime.utcnow().year)
    expires = body.get("expires_at")
    if expires:
        try:
            expires = date.fromisoformat(expires)
        except ValueError:
            expires = None
    exc = models.ExceptionRecord(
        exception_code=code,
        finding_id=f.id,
        reason=body.get("reason") or "Risk Accepted",
        expires_at=expires,
        status="Active",
        created_by=user.username,
    )
    f.exception_id = code
    db.add(exc)
    db.flush()
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f), "exception": exc.to_dict()}


@app.post("/api/findings/{finding_id}/risk")
def api_link_risk(finding_id: int, body: dict, user=Depends(require_write),
                  db: Session = Depends(get_db)):
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    f.risk_id = (body.get("risk_id") or "").strip() or None
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


# ---------------------------------------------------------------------------
# Upload API
# ---------------------------------------------------------------------------

@app.post("/api/upload")
async def api_upload(
    file: UploadFile = File(...),
    source_type: str = Form("va"),
    user=Depends(require_write),
    db: Session = Depends(get_db),
):
    content = await file.read()
    filename = file.filename or "upload"
    if not content:
        raise HTTPException(400, "Empty file")
    kind = source_type.lower().strip()
    try:
        if kind in ("assets", "asset", "inventory"):
            rows = parsers.parse_asset_inventory(filename, content)
            stats = ingest_assets(db, filename, rows)
        else:
            rows = parsers.parse_va_scan(filename, content)
            stats = ingest_scan(db, filename, rows)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(400, f"Could not parse file: {exc}")
    if not rows:
        raise HTTPException(400, "No usable rows found in file")
    return {"ok": True, "filename": filename, "stats": stats}


# ---------------------------------------------------------------------------
# Assets API
# ---------------------------------------------------------------------------

@app.get("/api/assets")
def api_assets(
    request: Request,
    db: Session = Depends(get_db),
    q: str = "",
    scope: str = "",
    environment: str = "",
):
    _require_user(request, db)
    query = db.query(models.Asset).filter(models.Asset.asset_code != "AST-0000")
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            models.Asset.name.ilike(like),
            models.Asset.asset_code.ilike(like),
            models.Asset.ip_address.ilike(like),
        ))
    if scope:
        query = query.filter(models.Asset.scope == scope)
    if environment:
        query = query.filter(models.Asset.environment == environment)

    assets = query.order_by(models.Asset.asset_code).all()
    result = []
    open_ids = set(models.OPEN_STATUSES)
    for a in assets:
        open_findings = [f for f in a.findings if f.status in open_ids]
        result.append({
            **a.to_dict(),
            "open_findings": len(open_findings),
            "critical": sum(1 for f in open_findings if f.severity == "Critical"),
        })
    last_audit = db.query(models.AuditFile).order_by(models.AuditFile.id.desc()).first()
    return {
        "assets": result,
        "total": len(result),
        "assessed": len(db.query(models.Finding.asset_id).distinct().all()),
        "open_total": db.query(models.Finding).filter(
            models.Finding.status.in_(models.OPEN_STATUSES)).count(),
        "unmapped_ips": (last_audit.unmapped_ips if last_audit else 0),
    }


@app.get("/api/assets/{asset_id}")
def api_asset_detail(asset_id: int, request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    a = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    open_ids = set(models.OPEN_STATUSES)
    open_findings = sorted(
        [f for f in a.findings if f.status in open_ids],
        key=lambda f: f.severity,
    )
    history = []
    for f in sorted(a.findings, key=lambda x: (x.last_observed or x.first_discovered or datetime.utcnow()), reverse=True):
        last_seen = f.last_observed or f.first_discovered
        if not last_seen:
            continue
        if not history or history[-1]["date"] != last_seen.date().isoformat():
            history.append({"date": last_seen.date().isoformat(),
                            "findings": 1, "sources": {f.source}})
        else:
            history[-1]["findings"] += 1
            history[-1]["sources"].add(f.source)
    for h in history:
        h["sources"] = ", ".join(sorted(s for s in h["sources"] if s))
    return {
        "asset": a.to_dict(),
        "why_it_matters": a.why_it_matters(),
        "open_findings": [finding_dict(f) for f in open_findings],
        "history": history,
    }


# ---------------------------------------------------------------------------
# SLA Tracking API
# ---------------------------------------------------------------------------

@app.get("/api/sla-tracking")
def api_sla_tracking(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    now = datetime.utcnow()
    open_findings = db.query(models.Finding).filter(
        models.Finding.status.in_(models.OPEN_STATUSES)
    ).all()

    # Forecast: projected breaches over the next 14 days.
    forecast_labels, forecast_values = [], []
    for d in range(1, 15):
        day = (now + timedelta(days=d)).date()
        forecast_labels.append(day.strftime("%b %d"))
        forecast_values.append(sum(
            1 for f in open_findings
            if f.due_date and f.due_date.date() == day
        ))

    # SLA status by responsible domain.
    domains = ["Server", "Network", "Database", "Security", "Middleware", "Other"]
    by_domain = {d: {"exceeded": 0, "approaching": 0, "within": 0, "exception": 0}
                 for d in domains}
    for f in open_findings:
        dom = domain_for(f.asset.owner_team if f.asset else None)
        bucket = by_domain.setdefault(dom, {"exceeded": 0, "approaching": 0,
                                            "within": 0, "exception": 0})
        key = {"SLA Exceeded": "exceeded", "Approaching SLA": "approaching",
               "Within SLA": "within", "Under Exception": "exception"}.get(f.sla_status)
        if key:
            bucket[key] += 1

    def _list(status):
        return [
            {
                "finding_code": f.finding_code,
                "plugin_name": f.plugin_name,
                "severity": f.severity,
                "ip_address": f.ip_address,
                "asset": f.asset.name if f.asset else None,
                "domain": domain_for(f.asset.owner_team if f.asset else None),
                "age_days": f.age_days(now),
                "due_date": _iso(f.due_date),
                "sla_days": f.sla_days,
                "owner": f.owner,
                "id": f.id,
            }
            for f in sorted(
                [x for x in open_findings if x.sla_status == status],
                key=lambda x: x.due_date or now,
            )[:25]
        ]

    return {
        "forecast": {"labels": forecast_labels, "values": forecast_values},
        "by_domain": {
            "labels": domains,
            "exceeded": [by_domain[d]["exceeded"] for d in domains],
            "approaching": [by_domain[d]["approaching"] for d in domains],
            "within": [by_domain[d]["within"] for d in domains],
            "exception": [by_domain[d]["exception"] for d in domains],
        },
        "exceeded": _list(models.SLA_EXCEEDED),
        "approaching": _list(models.SLA_APPROACHING),
        "within": _list(models.SLA_WITHIN),
    }


# ---------------------------------------------------------------------------
# SLA Policy Rules (admin)
# ---------------------------------------------------------------------------

@app.get("/api/sla-rules")
def api_sla_rules(request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    _require_user(request, db)
    rules = db.query(models.SLARule).order_by(models.SLARule.priority_order).all()
    return {"rules": [r.to_dict() for r in rules]}


@app.get("/api/sla-rules/log")
def api_sla_rules_log(request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    _require_user(request, db)
    logs = db.query(models.PolicyChangeLog).order_by(
        models.PolicyChangeLog.id.desc()).limit(30).all()
    return {"logs": [l.to_dict() for l in logs]}


@app.post("/api/sla-rules")
def api_create_rule(body: dict, user=Depends(require_admin),
                    db: Session = Depends(get_db)):
    max_prio = db.query(func.max(models.SLARule.priority_order)).scalar() or 0
    rule = models.SLARule(
        priority_order=body.get("priority_order") or max_prio + 1,
        source=body.get("source", "Any"),
        severity=body.get("severity", "Any"),
        asset_scope=body.get("asset_scope", "Any"),
        asset_type=body.get("asset_type", "Any"),
        environment=body.get("environment", "Any"),
        sla_days=int(body.get("sla_days", 90)),
        approaching_pct=int(body.get("approaching_pct", 70)),
        retest_pct=int(body.get("retest_pct", 80)),
        is_active=bool(body.get("is_active", True)),
    )
    db.add(rule)
    db.flush()
    log_policy_change(db, f"Added rule #{rule.priority_order} [{rule.source}/{rule.severity} -> {rule.sla_days}d]", user)
    recalculate_all(db)
    return {"ok": True, "rule": rule.to_dict()}


@app.put("/api/sla-rules/{rule_id}")
def api_update_rule(rule_id: int, body: dict, user=Depends(require_admin),
                    db: Session = Depends(get_db)):
    rule = db.query(models.SLARule).filter(models.SLARule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    for field in ("source", "severity", "asset_scope", "asset_type", "environment",
                  "sla_days", "approaching_pct", "retest_pct", "is_active"):
        if field in body:
            setattr(rule, field, body[field])
    db.commit()
    log_policy_change(db, f"Updated rule #{rule.priority_order} [{rule.source}/{rule.severity}]", user)
    recalculate_all(db)
    return {"ok": True, "rule": rule.to_dict()}


@app.post("/api/sla-rules/{rule_id}/toggle")
def api_toggle_rule(rule_id: int, user=Depends(require_admin),
                    db: Session = Depends(get_db)):
    rule = db.query(models.SLARule).filter(models.SLARule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    rule.is_active = not rule.is_active
    db.commit()
    log_policy_change(
        db, f"{'Enabled' if rule.is_active else 'Disabled'} rule #{rule.priority_order}", user)
    recalculate_all(db)
    return {"ok": True, "rule": rule.to_dict()}


@app.post("/api/sla-rules/{rule_id}/move")
def api_move_rule(rule_id: int, body: dict, user=Depends(require_admin),
                  db: Session = Depends(get_db)):
    rule = db.query(models.SLARule).filter(models.SLARule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    direction = body.get("direction", "up")
    rules = _ordered_rules(db)
    idx = next((i for i, r in enumerate(rules) if r.id == rule_id), None)
    if idx is None:
        raise HTTPException(404, "Rule not found")
    target = idx - 1 if direction == "up" else idx + 1
    if target < 0 or target >= len(rules):
        raise HTTPException(400, "Cannot move further")
    rules[idx], rules[target] = rules[target], rules[idx]
    for i, r in enumerate(rules):
        r.priority_order = i + 1
    db.commit()
    log_policy_change(db, f"Moved rule #{rule.priority_order} {direction}", user)
    recalculate_all(db)
    return {"ok": True, "rules": [r.to_dict() for r in _ordered_rules(db)]}


@app.post("/api/sla-rules/simulate")
def api_simulate_rule(body: dict, request: Request, user=Depends(require_admin), db: Session = Depends(get_db)):
    _require_user(request, db)
    rule = simulate_match(
        body.get("source", "VA"),
        body.get("severity", "Critical"),
        body.get("asset_scope", "Infrastructure"),
        body.get("asset_type", "Server"),
        body.get("environment", "Production"),
        _ordered_rules(db),
    )
    if not rule:
        return {"matched": False, "rule": None,
                "note": "No rule matched – finding would fall back to the 90-day default."}
    due = datetime.utcnow() + timedelta(days=rule.sla_days)
    return {"matched": True, "rule": rule.to_dict(),
            "due_date": due.date().isoformat(),
            "note": f"Rule #{rule.priority_order} matches first. Due: {due.date().isoformat()}"}


@app.post("/api/sla-rules/recalculate")
def api_recalculate(user=Depends(require_admin), db: Session = Depends(get_db)):
    count = recalculate_all(db)
    return {"ok": True, "recalculated": count}


# ---------------------------------------------------------------------------
# Exceptions API
# ---------------------------------------------------------------------------

@app.get("/api/exceptions")
def api_exceptions(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    today = date.today()
    ex_list = []
    for ex in db.query(models.ExceptionRecord).order_by(
            models.ExceptionRecord.created_at.desc()).limit(100).all():
        if ex.status == "Active" and ex.expires_at and ex.expires_at <= today:
            ex.status = "Expired"
        f = ex.finding
        ex_list.append({
            **ex.to_dict(),
            "finding_code": f.finding_code if f else None,
            "severity": f.severity if f else None,
            "plugin_name": f.plugin_name if f else None,
            "asset": f.asset.name if f and f.asset else None,
        })
    db.commit()
    return {"exceptions": ex_list}


@app.post("/api/exceptions")
def api_create_exception(body: dict, user=Depends(require_write),
                         db: Session = Depends(get_db)):
    finding_id = body.get("finding_id")
    f = db.query(models.Finding).filter(models.Finding.id == finding_id).first()
    if not f:
        raise HTTPException(404, "Finding not found")
    code = next_exception_code(db, datetime.utcnow().year)
    expires = body.get("expires_at")
    if expires:
        try:
            expires = date.fromisoformat(expires)
        except ValueError:
            expires = None
    ex = models.ExceptionRecord(
        exception_code=code, finding_id=f.id,
        reason=body.get("reason") or "Risk Accepted",
        expires_at=expires, status="Active", created_by=user.username,
    )
    f.exception_id = code
    db.add(ex)
    db.flush()
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "exception": ex.to_dict()}


# ---------------------------------------------------------------------------
# Audit & Reports API
# ---------------------------------------------------------------------------

@app.get("/api/audit")
def api_audit(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    files = db.query(models.AuditFile).order_by(models.AuditFile.id.desc()).limit(100).all()
    return {"files": [f.to_dict() for f in files]}


@app.get("/api/reports/export")
def api_export_findings(request: Request, db: Session = Depends(get_db)):
    _require_user(request, db)
    import csv
    import io as _io
    findings = db.query(models.Finding).order_by(models.Finding.id.desc()).all()
    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Finding Code", "Source", "Plugin Name", "Severity", "IP Address", "Protocol",
        "Port", "CVE", "VPR", "Status", "SLA Status", "Due Date", "Age Days",
        "Reappeared", "Asset", "Owner", "Risk ID", "Exception ID", "Retest",
    ])
    now = datetime.utcnow()
    for f in findings:
        writer.writerow([
            f.finding_code, f.source, f.plugin_name, f.severity, f.ip_address,
            f.protocol, f.port, f.cve, f.vpr_score, f.status, f.sla_status,
            _iso(f.due_date), f.age_days(now), f.is_reappeared,
            f.asset.name if f.asset else "", f.owner, f.risk_id, f.exception_id,
            f.retest_status,
        ])
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=assurance_findings_export.csv"},
    )


# ---------------------------------------------------------------------------
# User management (admin)
# ---------------------------------------------------------------------------

@app.get("/api/users")
def api_users(user=Depends(require_admin), db: Session = Depends(get_db)):
    return {"users": [u.to_dict() for u in db.query(models.User).all()]}


@app.post("/api/users")
def api_create_user(body: dict, user=Depends(require_admin),
                    db: Session = Depends(get_db)):
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role = body.get("role") or "read_only"
    if not username or len(password) < 4:
        raise HTTPException(400, "Username required and password min 4 chars")
    if role not in ("admin", "read_write", "read_only"):
        raise HTTPException(400, "Invalid role")
    if db.query(models.User).filter(models.User.username == username).first():
        raise HTTPException(400, "Username already exists")
    u = models.User(username=username, password_hash=hash_password(password), role=role)
    db.add(u)
    db.commit()
    return {"ok": True, "user": u.to_dict()}


@app.get("/api/me")
def api_me(user=Depends(require_read)):
    return {"user": user.to_dict()}


@app.post("/api/admin/reset-data")
def api_reset_data(body: dict, user=Depends(require_admin),
                   db: Session = Depends(get_db)):
    """Wipe findings (and optionally assets) for a clean re-import.
    Users, SLA rules and the Default Asset (AST-0000) are always kept.
    """
    scope = (body.get("scope") or "findings").lower()
    exc_deleted = db.query(models.ExceptionRecord).delete(synchronize_session=False)
    f_deleted = db.query(models.Finding).delete(synchronize_session=False)
    audit_deleted = db.query(models.AuditFile).delete(synchronize_session=False)
    asset_deleted = 0
    if scope == "all":
        asset_deleted = (
            db.query(models.Asset)
            .filter(models.Asset.asset_code != "AST-0000")
            .delete(synchronize_session=False)
        )
    db.commit()
    recalculate_all(db)
    return {
        "ok": True,
        "findings_deleted": f_deleted,
        "exceptions_deleted": exc_deleted,
        "audit_deleted": audit_deleted,
        "assets_deleted": asset_deleted,
    }


@app.get("/api/search")
def api_search(request: Request, q: str = "", db: Session = Depends(get_db)):
    _require_user(request, db)
    q = q.strip()
    if not q:
        return {"findings": [], "assets": []}
    like = f"%{q}%"
    findings = db.query(models.Finding).filter(or_(
        models.Finding.finding_code.ilike(like),
        models.Finding.plugin_name.ilike(like),
        models.Finding.ip_address.ilike(like),
        models.Finding.cve.ilike(like),
    )).limit(8).all()
    assets = db.query(models.Asset).filter(
        models.Asset.asset_code != "AST-0000",
        or_(
            models.Asset.name.ilike(like),
            models.Asset.asset_code.ilike(like),
            models.Asset.ip_address.ilike(like),
        ),
    ).limit(5).all()
    return {
        "findings": [finding_dict(f) for f in findings],
        "assets": [a.to_dict() for a in assets],
    }


# ---------------------------------------------------------------------------
# Session helper for JSON routes
# ---------------------------------------------------------------------------

def _require_user(request: Request, db: Session) -> models.User:
    user = ui_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

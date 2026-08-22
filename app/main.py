"""Assurance Finding Lifecycle & SLA Management Platform - FastAPI application."""
import json
import os
import re
from datetime import date, datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session, joinedload

from . import models, parsers, scoping
from .auth import (
    COOKIE_NAME,
    available_scopes,
    get_current_user,
    get_view,
    view_for,
    write_reach,
    module_read,
    module_write,
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
    scope_values as sla_scope_values,
    domain_for,
    domain_for_asset,
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
# Front-end assets are served locally - the platform must run on a closed network.
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

# Create tables on boot (idempotent) and seed defaults.
Base.metadata.create_all(bind=engine)
from sample_data.seed_data import seed_if_empty  # noqa: E402
from .startup import (  # noqa: E402
    AssetCodeAllocator,
    ensure_schema,
    load_asset_inventory,
    relink_unmapped_findings,
)

ensure_schema(engine)

_seed_db = SessionLocal()
try:
    seed_if_empty(_seed_db)
    # Load Asset Inventory from disk on startup
    load_asset_inventory(_seed_db, BASE_DIR.parent)
    _PENDING_EXPIRY = True
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


class SequentialCodeAllocator:
    """Year-scoped FND/EXC codes without a database round-trip per row.

    Same reason as AssetCodeAllocator: the session does not autoflush, so
    asking the database for "the next code" inside a loop keeps returning
    the same one.
    """

    def __init__(self, db, prefix, model, attr):
        self._db = db
        self._prefix = prefix
        self._model = model
        self._attr = attr
        self._next: dict[int, int] = {}

    def take(self, year: int) -> str:
        if year not in self._next:
            seed = _next_code(self._db, self._model, self._prefix, self._attr, year)
            self._next[year] = int(seed.rsplit("-", 1)[1])
        number = self._next[year]
        self._next[year] = number + 1
        return f"{self._prefix}{year}-{number:04d}"


def finding_code_allocator(db):
    return SequentialCodeAllocator(db, "FND", models.Finding, "finding_code")


def exception_code_allocator(db):
    return SequentialCodeAllocator(db, "EXC", models.ExceptionRecord, "exception_code")


def next_asset_code(db):
    return AssetCodeAllocator(db).next()


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
        "compliance_result": f.compliance_result,
        "application_name": f.application_name,
        "affected_location": f.affected_location,
        "cwe_id": f.cwe_id,
        "owasp_category": f.owasp_category,
        "external_ref": f.external_ref,
        "closed_at": _iso(f.closed_at),
        "closed_by": f.closed_by,
        "closure_method": f.closure_method,
        "closure_evidence": f.closure_evidence,
        "closure_label": f.closure_label(),
        "source_file": f.source_file,
        "asset": asset.to_dict() if asset else None,
    }


def log_policy_change(db, action: str, user):
    db.add(models.PolicyChangeLog(action=action, user=getattr(user, "username", "system")))
    db.commit()


SCOPE_ACRONYMS = {"pci": "PCI", "npci": "NPCI"}


def scope_label(value: str) -> str:
    """Title-case a scope value without mangling acronyms (PCI, not Pci)."""
    key = (value or "").strip().lower()
    return SCOPE_ACRONYMS.get(key, (value or "").strip().title())


def _ordered_rules(db):
    return list(db.query(models.SLARule).order_by(models.SLARule.priority_order).all())


# ---------------------------------------------------------------------------
# Ingestion engines
# ---------------------------------------------------------------------------

def next_assessment_code(db):
    rows = db.query(models.AuditFile.reference_code).all()
    mx = 0
    for (code,) in rows:
        m = re.search(r"ASM-(\d+)", code or "")
        if m:
            mx = max(mx, int(m.group(1)))
    return f"ASM-{mx + 1:04d}"


def get_default_asset(db):
    """The bucket every finding whose IP is not in the inventory lands in.

    The platform never invents an asset out of a scan row - a scan says
    nothing about ownership, environment or business scope, and a guessed
    asset would silently receive the wrong SLA. Unmapped findings stay
    visible on the Default Asset until the inventory catches up.
    """
    default_asset = db.query(models.Asset).filter(models.Asset.asset_code == "AST-0000").first()
    if not default_asset:
        default_asset = models.Asset(
            asset_code="AST-0000",
            name="Default Asset / Unmapped IPs",
            ip_address="0.0.0.0",
            type="Unknown",
            scope="No Asset",
            environment="Unknown",
            site="Unknown",
            owner_team="Unassigned",
            status="Active",
        )
        db.add(default_asset)
        db.commit()
        db.refresh(default_asset)
    return default_asset


def _norm_key(value) -> str:
    """One field of a correlation key, normalised.

    Case and stray whitespace differ between exports of the same scan and must
    not make the same finding look like a new one.
    """
    return " ".join(str(value or "").split()).lower()


def _correlation_key(source: str, plugin: str, port, protocol: str):
    """What makes two rows the same finding, per assessment type.

    Infrastructure:
        VA    IP + plugin + port + protocol
        CIS   IP + control

    Application side - there is no host or port to key on, so the key is the
    place inside the application:
        SAST  application + title + file or component + CWE
        DAST  application + title + URL + OWASP category
        PT    application + title + URL

    Severity is deliberately NOT part of any of them. A vulnerability that is
    re-rated from High to Critical is the same vulnerability: its severity is
    updated in place and it keeps its original discovery date. Keying on it
    would close the old one and open a new one, and the age of a finding that
    nobody had touched would silently reset.
    """
    if source == "CIS":
        return (_norm_key(plugin), 0, "")
    return (_norm_key(plugin), port or 0, _norm_key(protocol))


def _appsec_key(source: str, row_or_finding) -> tuple:
    """The correlation key for a SAST, DAST or PT row or stored finding."""
    def field(name):
        if isinstance(row_or_finding, dict):
            return row_or_finding.get(name)
        return getattr(row_or_finding, name, None)

    title = field("plugin_name")
    application = field("application_name")
    location = field("affected_location")
    if source == models.SOURCE_SAST:
        return (_norm_key(application), _norm_key(title),
                _norm_key(location), _norm_key(field("cwe_id")))
    if source == models.SOURCE_DAST:
        return (_norm_key(application), _norm_key(title),
                _norm_key(location), _norm_key(field("owasp_category")))
    return (_norm_key(application), _norm_key(title), _norm_key(location))


def close_finding_automatically(finding, when, reference, filename):
    finding.status = models.STATUS_CLOSED
    finding.sla_status = models.SLA_CLOSED
    finding.due_date = None
    finding.closed_at = when
    finding.closed_by = None
    finding.closure_method = models.CLOSURE_AUTOMATIC
    finding.closure_evidence = f"{reference} ({filename})"
    if finding.retest_status == "Pending":
        finding.retest_status = "Passed"


def _parse_iso_date(value):
    try:
        return date.fromisoformat(value) if value else None
    except (TypeError, ValueError):
        return None


def expire_due_exceptions(db) -> int:
    """Retire exceptions whose end date has passed, and re-rate what they covered.

    Marking the record Expired is only half the job. The finding under it still
    reads "Under Exception" until something recalculates it, and nothing runs
    on the expiry date itself - so a finding could sit out of the breach
    reports for weeks after its cover ended. Every finding released here is
    re-rated immediately, which usually drops it straight onto the overdue
    list, where it belongs.
    """
    today = date.today()
    due = (db.query(models.ExceptionRecord)
           .filter(models.ExceptionRecord.status == "Active",
                   models.ExceptionRecord.expires_at.isnot(None),
                   models.ExceptionRecord.expires_at <= today).all())
    if not due:
        return 0
    for ex in due:
        ex.status = "Expired"
    db.flush()            # the engine re-reads this table; see the revoke path
    rules = _ordered_rules(db)
    for ex in due:
        finding = ex.finding
        if finding is None:
            continue
        if finding.exception_id == ex.exception_code:
            finding.exception_id = None
        recalculate_finding(db, finding, rules)
    db.commit()
    return len(due)


def exception_payload(body: dict) -> dict:
    """Validate the shared fields of an exception request.

    An exception is an engineering decision, so the platform insists on a
    technical reason from a fixed list and on a written justification -
    "we accept the risk" is not something this system records.
    """
    reason = (body.get("reason") or "").strip() or models.EXCEPTION_REASONS[0]
    if reason not in models.EXCEPTION_REASONS:
        raise HTTPException(400, f"Unknown exception reason: {reason}")
    justification = (body.get("justification") or "").strip()
    if len(justification) < 10:
        raise HTTPException(400, "A justification of at least 10 characters is required")
    starts_at = _parse_iso_date(body.get("starts_at")) or date.today()
    expires_at = _parse_iso_date(body.get("expires_at"))
    # An exception that has already expired is not an exception - it would be
    # created and retired in the same breath, and the finding would silently
    # go back to being late with an approval reference against it.
    if expires_at and expires_at <= date.today():
        raise HTTPException(400, "The expiry date must be in the future")
    if expires_at and expires_at < starts_at:
        raise HTTPException(400, "The exception cannot expire before it starts")
    return {
        "reason": reason,
        "justification": justification,
        "compensating_control": (body.get("compensating_control") or "").strip() or None,
        "approval_ref": (body.get("approval_ref") or "").strip() or None,
        "starts_at": starts_at,
        "expires_at": expires_at,
    }


def create_exception_for(db, finding, payload, username, allocator, parent=None):
    """Attach one exception to one finding."""
    exc = models.ExceptionRecord(
        exception_code=allocator.take(datetime.utcnow().year),
        finding_id=finding.id,
        control_key=finding.plugin_name,
        source=finding.source,
        status="Active",
        created_by=username,
        parent_id=parent.id if parent is not None else None,
        **payload,
    )
    finding.exception_id = exc.exception_code
    db.add(exc)
    db.flush()
    return exc


def apply_future_exceptions(db, findings, allocator):
    """Cover newly ingested findings by an existing control-level exception.

    A control-level exception (finding_id NULL, applies_to_future set) is a
    standing decision about a control - for example a hardening item that
    the vendor image cannot satisfy. When the same control shows up again on
    an in-scope IP, the decision is applied automatically instead of the
    finding starting a fresh SLA clock nobody expects.
    """
    if not findings:
        return 0
    templates = (
        db.query(models.ExceptionRecord)
        .filter(
            models.ExceptionRecord.finding_id.is_(None),
            models.ExceptionRecord.applies_to_future.is_(True),
            models.ExceptionRecord.status == "Active",
        )
        .all()
    )
    if not templates:
        return 0

    today = date.today()
    applied = 0
    for finding in findings:
        for template in templates:
            if template.expires_at and template.expires_at <= today:
                continue
            if (template.control_key or "") != (finding.plugin_name or ""):
                continue
            if template.source and template.source != finding.source:
                continue
            scope = [ip.strip() for ip in (template.scope_ips or "").split(",") if ip.strip()]
            if scope and finding.ip_address not in scope:
                continue
            create_exception_for(
                db, finding,
                {
                    "reason": template.reason,
                    "justification": template.justification,
                    "compensating_control": template.compensating_control,
                    "approval_ref": template.approval_ref,
                    "starts_at": template.starts_at or today,
                    "expires_at": template.expires_at,
                },
                template.created_by, allocator, parent=template,
            )
            applied += 1
            break
    return applied


def close_finding_manually(finding, username, note=None):
    """A user closing a finding by hand - the provenance says who, not what."""
    finding.status = models.STATUS_CLOSED
    finding.sla_status = models.SLA_CLOSED
    finding.due_date = None
    finding.closed_at = datetime.utcnow()
    finding.closed_by = username
    finding.closure_method = models.CLOSURE_MANUAL
    finding.closure_evidence = note or None


def reopen_finding(finding):
    """Clear the closure trail when a finding goes back into the queue."""
    finding.closed_at = None
    finding.closed_by = None
    finding.closure_method = None
    finding.closure_evidence = None


def _raw_row_json(row: dict, filename: str, reference: str, observed) -> str | None:
    """The untouched sheet row, wrapped with where and when it came from."""
    pairs = row.get("raw")
    if not pairs:
        return None
    return json.dumps({
        "file": filename,
        "assessment": reference,
        "observed": observed.isoformat() if observed else None,
        "columns": pairs,
    }, ensure_ascii=False)


def _sane_dates(row, scan_date):
    """The two dates on a row, made usable.

    Exports are not always clean. Three things are corrected here rather than
    stored and reasoned about later, because every age, due date and SLA state
    in the platform is derived from these two values:

      * a row with no dates at all is dated by the assessment itself;
      * a row whose Last Observed is EARLIER than its First Discovered has them
        the wrong way round - the earlier of the two is the discovery, the
        later is the sighting, whatever the columns were called. Left alone it
        produced a negative age and an SLA deadline before the finding existed;
      * a date in the future cannot be evidence. Nothing has been observed
        after the assessment ran, so anything later than the assessment is
        pulled back to it.

    Nothing is discarded - the original row is still stored verbatim and shown
    on the full record page, so the correction is visible rather than hidden.
    """
    observed = row.get("last_observed") or scan_date
    first_seen = row.get("first_discovered") or observed
    if first_seen and observed and first_seen > observed:
        first_seen, observed = observed, first_seen
    if observed and observed > scan_date:
        observed = scan_date
    if first_seen and first_seen > scan_date:
        first_seen = scan_date
    return observed, first_seen


def ingest_scan(db: Session, filename: str, rows: list[dict], reach=None) -> dict:
    """Correlate a VA/CIS assessment against the existing findings & assets.

    Three things happen here, in this order:

    1. every row in the file is correlated against what is already stored -
       new findings are created, known ones have their Last Observed moved
       forward, closed ones that came back are reopened;
    2. every IP the assessment covered with working credentials is checked
       for findings that are *no longer in the file* - those are proven
       remediated and closed automatically with a reference to this
       assessment;
    3. the coverage state of each asset is recorded, so the UI can tell
       "clean" apart from "never looked at".

    Last Observed is the authority throughout: uploading an older file after
    a newer one must not roll the state backwards.

    `reach` is what the uploading account is allowed to write. It is the
    account's grant, never the filter chosen in the header - looking at one
    scope must not quietly throw the rest of a report away. A row the account
    cannot reach is not rejected with an error either: it is simply not there,
    and the response says how many were left behind.
    """
    now = datetime.utcnow()
    scan_date = parsers.scan_date_from_filename(filename) or now

    detected_source = rows[0].get("detected_source", "VA") if rows else "VA"

    # An account granted VA only cannot import a CIS file at all. The file is
    # not half-imported - nothing in it is visible to this account.
    if reach is not None and not reach.covers_source(detected_source):
        return {"records": len(rows), "new": 0, "updated": 0, "reappeared": 0,
                "closed": 0, "unmapped": 0, "skipped_rows": len(rows),
                "skipped_source": detected_source, "source": detected_source,
                "assessed_ips": 0, "inconclusive_ips": 0, "auto_excepted": 0,
                "reference_code": None, "ignored": True}

    reference_code = next_assessment_code(db)

    # Which IPs can this assessment prove things about?
    coverage = parsers.assessment_coverage(rows, detected_source)

    default_asset = get_default_asset(db)

    def _reachable_ip(ip: str) -> bool:
        """Is this host inside the uploader's grant?

        An IP the inventory has never explained is reachable by anybody who
        holds the unscoped grant - which is the default - because refusing it
        would drop the row on the floor before anyone could classify it.
        """
        if reach is None:
            return True
        asset = db.query(models.Asset).filter(models.Asset.ip_address == ip).first()
        return reach.covers_asset(asset)

    if reach is not None:
        # Coverage is narrowed first. It drives both the closure pass and the
        # per-asset coverage state, so an IP the uploader cannot reach must
        # drop out here or it would close findings they are not allowed to
        # see, on evidence they are not allowed to supply.
        coverage = {ip: cred for ip, cred in coverage.items() if _reachable_ip(ip)}

    skipped_rows = 0

    codes = finding_code_allocator(db)
    unmapped = new = updated = reappeared = closed = 0
    inconclusive_rows = 0
    created_in_file: dict[tuple, models.Finding] = {}
    # IP -> correlation keys that are still open/failing in THIS file.
    present_keys: dict[str, set] = {}
    asset_cache: dict[str, models.Asset] = {}

    for row in rows:
        ip = (row.get("ip_address") or "").strip()
        plugin = (row.get("plugin_name") or "").strip()
        port = row.get("port") or 0
        proto = (row.get("protocol") or "").strip()
        if not ip or not plugin:
            continue

        # The scan information plugin is coverage metadata, not a finding.
        if "nessus scan information" in plugin.lower():
            continue

        severity = str(row.get("severity") or "Info").strip().capitalize()
        result = parsers.cis_result(row) if detected_source == "CIS" else None

        observed, first_seen = _sane_dates(row, scan_date)

        key = _correlation_key(detected_source, plugin, port, proto)

        # Look the finding up before deciding what to do with it.
        query = db.query(models.Finding).filter(
            models.Finding.ip_address == ip,
            models.Finding.plugin_name == plugin,
            models.Finding.source == detected_source,
        )
        if detected_source == "VA":
            query = query.filter(
                models.Finding.port == port,
                models.Finding.protocol == proto,
            )
        existing = (created_in_file.get((ip, key))
                    or query.order_by(models.Finding.first_discovered.asc()).first())

        # A passing CIS control is evidence of compliance, not a finding. It
        # is deliberately left out of present_keys so the closure pass below
        # picks it up and closes the old failure with full provenance.
        if result == models.RESULT_PASSED:
            continue

        present_keys.setdefault(ip, set()).add(key)

        if ip not in asset_cache:
            asset_cache[ip] = db.query(models.Asset).filter(
                models.Asset.ip_address == ip
            ).first() or default_asset
        asset = asset_cache[ip]
        if reach is not None and not reach.covers_asset(
                None if asset is default_asset else asset):
            # Outside this account's scopes. Drop the row before it reaches
            # present_keys, so it cannot influence the closure pass either.
            present_keys.get(ip, set()).discard(key)
            skipped_rows += 1
            continue
        if asset is default_asset:
            unmapped += 1
        if coverage.get(ip) is False:
            inconclusive_rows += 1

        if existing:
            # Evidence older than what we already know may not change the state.
            # For a CLOSED finding the bar is the closure itself: the file that
            # closed it necessarily has the same date as its last observation,
            # so comparing against Last Observed alone let a re-uploaded old
            # cycle "reappear" everything it had already closed.
            stale = bool(existing.last_observed and existing.last_observed > observed)
            if existing.status == models.STATUS_CLOSED and existing.closed_at:
                stale = stale or observed <= existing.closed_at
            if stale:
                # An older file arrived late - keep the newer state, but still
                # let it contribute an earlier First Discovered date.
                if first_seen and (not existing.first_discovered or first_seen < existing.first_discovered):
                    existing.first_discovered = first_seen
                    existing.original_created_at = first_seen
                continue

            if existing.status == models.STATUS_CLOSED:
                existing.status = models.STATUS_OPEN
                existing.is_reappeared = True
                existing.reappeared_count = (existing.reappeared_count or 0) + 1
                existing.reappeared_at = observed
                existing.closed_at = None
                existing.closed_by = None
                existing.closure_method = None
                existing.closure_evidence = None
                existing.retest_status = "Failed"
                reappeared += 1
            else:
                updated += 1

            existing.last_observed = observed
            existing.severity = severity
            existing.compliance_result = result
            existing.asset_id = asset.id
            for attr, value in (("cve", row.get("cve")),
                                ("vpr_score", row.get("vpr_score")),
                                ("description", row.get("description")),
                                ("remediation_steps", row.get("remediation_steps")),
                                ("plugin_output", row.get("plugin_output"))):
                if value:
                    setattr(existing, attr, value)
            # The newest evidence replaces the stored sheet row wholesale, so
            # the full record page always shows the latest report of it.
            if row.get("raw"):
                existing.raw_row = _raw_row_json(row, filename, reference_code, observed)
                existing.source_file = filename
            if first_seen and (not existing.first_discovered or first_seen < existing.first_discovered):
                existing.first_discovered = first_seen
                existing.original_created_at = first_seen
            continue

        finding = models.Finding(
            finding_code=codes.take(first_seen.year),
            source=detected_source,
            plugin_name=plugin,
            severity=severity,
            compliance_result=result,
            ip_address=ip,
            protocol=proto,
            port=port,
            cve=row.get("cve"),
            vpr_score=row.get("vpr_score"),
            description=row.get("description"),
            remediation_steps=row.get("remediation_steps"),
            plugin_output=row.get("plugin_output"),
            first_discovered=first_seen,
            last_observed=observed,
            original_created_at=first_seen,
            status=models.STATUS_OPEN,
            asset_id=asset.id,
            raw_row=_raw_row_json(row, filename, reference_code, observed),
            source_file=filename,
        )
        db.add(finding)
        created_in_file[(ip, key)] = finding
        new += 1

    db.flush()

    # Standing control-level exceptions cover the findings just created.
    auto_excepted = apply_future_exceptions(
        db, list(created_in_file.values()), exception_code_allocator(db))

    # ------------------------------------------------------------------
    # Closure pass - what the assessment proved is gone
    # ------------------------------------------------------------------
    assessed_ips = [ip for ip, credentialed in coverage.items() if credentialed]
    inconclusive_ips = [ip for ip, credentialed in coverage.items() if not credentialed]

    for ip in assessed_ips:
        open_findings = (
            db.query(models.Finding)
            .filter(
                models.Finding.ip_address == ip,
                models.Finding.source == detected_source,
                models.Finding.status.in_(models.OPEN_STATUSES),
            )
            .all()
        )
        seen = present_keys.get(ip, set())
        for finding in open_findings:
            if reach is not None and not reach.covers_finding(finding):
                continue
            key = _correlation_key(detected_source, finding.plugin_name,
                                   finding.port, finding.protocol)
            if key in seen:
                continue
            # Never close on evidence older than what we already know.
            if finding.last_observed and finding.last_observed > scan_date:
                continue
            if finding.first_discovered and finding.first_discovered > scan_date:
                continue
            close_finding_automatically(finding, scan_date, reference_code, filename)
            closed += 1

    # ------------------------------------------------------------------
    # Coverage state of the assets this assessment touched
    # ------------------------------------------------------------------
    for ip, credentialed in coverage.items():
        asset = asset_cache.get(ip) or db.query(models.Asset).filter(
            models.Asset.ip_address == ip
        ).first()
        if not asset or asset.asset_code == "AST-0000":
            continue
        if asset.last_scanned_at and asset.last_scanned_at > scan_date:
            continue
        asset.last_scanned_at = scan_date
        asset.last_scan_credentialed = bool(credentialed)
        asset.coverage_state = (
            models.COVERAGE_ASSESSED if credentialed else models.COVERAGE_INCONCLUSIVE
        )

    db.flush()
    recalculate_all(db)

    db.add(models.AuditFile(
        reference_code=reference_code,
        filename=filename,
        uploaded_at=now,
        record_count=len(rows),
        source_type=f"{detected_source} Assessment",
        unmapped_ips=unmapped,
        new_findings=new,
        updated_findings=updated,
        reappeared_findings=reappeared,
        closed_findings=closed,
        assessed_ips=len(assessed_ips),
        inconclusive_ips=len(inconclusive_ips),
    ))
    db.commit()

    return {
        "reference": reference_code,
        "records": len(rows),
        "new": new,
        "updated": updated,
        "reappeared": reappeared,
        "closed": closed,
        "auto_excepted": auto_excepted,
        "unmapped": unmapped,
        "assessed_ips": len(assessed_ips),
        "inconclusive_ips": len(inconclusive_ips),
        "inconclusive_rows": inconclusive_rows,
        "detected_type": detected_source,
        "skipped_rows": skipped_rows,
    }


# ---------------------------------------------------------------------------
# Application security ingest - SAST, DAST and PT
# ---------------------------------------------------------------------------

def _application_index(db):
    """Every asset that can answer to an application name, lowercased.

    An application usually runs on twenty servers that all carry its name, so
    "the asset called X" is ambiguous. The register row for the application
    itself wins, because a SAST finding is about the application and not about
    any one of the machines it happens to run on - picking a server would
    attribute a code defect to whichever host happened to be listed first.
    A server is used only when the register has no row for the application,
    so an inventory that predates this still correlates instead of parking
    everything on the Default Asset.
    """
    index = {}
    fallback = {}
    for asset in db.query(models.Asset).all():
        is_application = (asset.type or "") == models.ASSET_TYPE_APPLICATION
        for candidate in (asset.name, asset.asset_code):
            key = _norm_key(candidate)
            if not key:
                continue
            target = index if is_application else fallback
            target.setdefault(key, asset)
    for key, asset in fallback.items():
        index.setdefault(key, asset)
    return index


def _domain_index(db):
    """Every asset that can answer to a host name, lowercased."""
    index = {}
    for asset in db.query(models.Asset).all():
        for value in str(asset.domain or "").split(","):
            key = value.strip().lower().strip(".")
            if key and key not in index:
                index[key] = asset
    return index


def bind_appsec_asset(row, applications, domains, default_asset):
    """Which asset an application finding belongs to.

    SAST reads source code. It is a statement about an application, not about
    a host - the same finding exists on every server the application runs on -
    so it binds to the asset that carries the application's name.

    DAST and PT exercise a running service at a URL. The host in that URL is a
    real machine, so they bind through the domain on the inventory. Falling
    back to the application name would be wrong in a quiet way: a finding
    reported against one published host would be attributed to the whole
    application, and closing it would then require the wrong evidence.
    """
    source = row.get("detected_source")
    if source in models.BINDS_BY_DOMAIN:
        asset = domains.get((row.get("domain") or "").strip().lower())
        if asset is not None:
            return asset
    asset = applications.get(_norm_key(row.get("application_name")))
    if asset is not None:
        return asset
    return default_asset


def ingest_appsec(db: Session, filename: str, rows: list[dict], reach=None) -> dict:
    """Correlate one SAST, DAST or PT report.

    The shape of the work is the same as an infrastructure assessment, and so
    are the guarantees: a finding keeps its original discovery date for ever,
    newer evidence never loses to older evidence, and nothing is closed unless
    an assessment that actually covered it failed to report it.

    What differs is the unit of coverage. A VA file proves things about hosts,
    one credentialed host at a time. These files prove things about
    applications: if an application appears in the report, everything the
    report does not mention for that application and that assessment type is
    gone. There is no equivalent of a credentialed check, because there is no
    host to log into - the application either was tested or was not in the
    file at all.
    """
    now = datetime.utcnow()
    detected_source = rows[0].get("detected_source") if rows else models.SOURCE_SAST

    if reach is not None and not reach.covers_source(detected_source):
        return {"records": len(rows), "new": 0, "updated": 0, "reappeared": 0,
                "closed": 0, "unmapped": 0, "skipped_rows": len(rows),
                "skipped_source": detected_source, "detected_type": detected_source,
                "assessed_ips": 0, "inconclusive_ips": 0, "auto_excepted": 0,
                "reference": None, "ignored": True}

    scan_date = (max((r.get("scan_date") for r in rows if r.get("scan_date")), default=None)
                 or parsers.scan_date_from_filename(filename) or now)
    reference_code = next_assessment_code(db)

    default_asset = get_default_asset(db)
    applications = _application_index(db)
    domains = _domain_index(db)
    codes = finding_code_allocator(db)

    new = updated = reappeared = closed = unmapped = skipped_rows = 0
    created_in_file: dict[tuple, models.Finding] = {}
    # application (lowercased) -> the keys this report still reports on it
    present: dict[str, set] = {}
    covered_applications: set[str] = set()

    for row in rows:
        source = row.get("detected_source")
        if source != detected_source:
            continue
        application = _norm_key(row.get("application_name"))
        key = _appsec_key(source, row)
        asset = bind_appsec_asset(row, applications, domains, default_asset)

        if reach is not None and not reach.covers_asset(
                None if asset is default_asset else asset):
            skipped_rows += 1
            continue

        # The application was tested, whether or not this row survives below.
        covered_applications.add(application)
        present.setdefault(application, set()).add(key)

        if asset is default_asset:
            unmapped += 1

        observed, first_seen = _sane_dates(row, scan_date)

        existing = created_in_file.get((application, key))
        if existing is None:
            for candidate in (db.query(models.Finding)
                              .filter(models.Finding.source == source,
                                      models.Finding.application_name.isnot(None),
                                      func.lower(models.Finding.application_name) ==
                                      (row.get("application_name") or "").strip().lower())
                              .all()):
                if _appsec_key(source, candidate) == key:
                    existing = candidate
                    break

        if existing is not None:
            stale = bool(existing.last_observed and existing.last_observed > observed)
            if existing.status == models.STATUS_CLOSED and existing.closed_at:
                stale = stale or observed <= existing.closed_at
            if stale:
                if first_seen and (not existing.first_discovered
                                   or first_seen < existing.first_discovered):
                    existing.first_discovered = first_seen
                    existing.original_created_at = first_seen
                continue

            if existing.status == models.STATUS_CLOSED:
                existing.status = models.STATUS_OPEN
                existing.is_reappeared = True
                existing.reappeared_count = (existing.reappeared_count or 0) + 1
                existing.reappeared_at = observed
                existing.closed_at = None
                existing.closed_by = None
                existing.closure_method = None
                existing.closure_evidence = None
                existing.retest_status = "Failed"
                reappeared += 1
            else:
                updated += 1

            existing.last_observed = observed
            # The severity is the assessment's current opinion and is taken as
            # given. The finding itself, and its age, do not change.
            existing.severity = row.get("severity") or existing.severity
            existing.asset_id = asset.id
            existing.external_ref = row.get("external_ref") or existing.external_ref
            for attr in ("description", "remediation_steps", "cwe_id",
                         "owasp_category", "affected_location"):
                value = row.get(attr)
                if value:
                    setattr(existing, attr, value)
            if row.get("raw"):
                existing.raw_row = _raw_row_json(row, filename, reference_code, observed)
                existing.source_file = filename
            if first_seen and (not existing.first_discovered
                               or first_seen < existing.first_discovered):
                existing.first_discovered = first_seen
                existing.original_created_at = first_seen
            continue

        finding = models.Finding(
            finding_code=codes.take(first_seen.year),
            source=source,
            plugin_name=row.get("plugin_name"),
            severity=row.get("severity") or "Info",
            ip_address=(asset.ip_address if asset is not default_asset else
                        (row.get("domain") or "")),
            protocol="",
            port=0,
            application_name=(row.get("application_name") or "").strip(),
            affected_location=row.get("affected_location"),
            cwe_id=row.get("cwe_id") or None,
            owasp_category=row.get("owasp_category") or None,
            external_ref=row.get("external_ref") or None,
            description=row.get("description") or None,
            remediation_steps=row.get("remediation_steps") or None,
            first_discovered=first_seen,
            last_observed=observed,
            original_created_at=first_seen,
            status=models.STATUS_OPEN,
            asset_id=asset.id,
            raw_row=_raw_row_json(row, filename, reference_code, observed),
            source_file=filename,
        )
        db.add(finding)
        created_in_file[(application, key)] = finding
        new += 1

    db.flush()

    auto_excepted = apply_future_exceptions(
        db, list(created_in_file.values()), exception_code_allocator(db))

    # ------------------------------------------------------------------
    # Closure - what this report proves is gone
    # ------------------------------------------------------------------
    if covered_applications:
        candidates = (db.query(models.Finding)
                      .filter(models.Finding.source == detected_source,
                              models.Finding.status.in_(models.OPEN_STATUSES),
                              models.Finding.application_name.isnot(None))
                      .all())
        for finding in candidates:
            application = _norm_key(finding.application_name)
            if application not in covered_applications:
                continue          # this report did not test that application
            if reach is not None and not reach.covers_finding(finding):
                continue
            if _appsec_key(detected_source, finding) in present.get(application, set()):
                continue
            if finding.last_observed and finding.last_observed > scan_date:
                continue
            if finding.first_discovered and finding.first_discovered > scan_date:
                continue
            close_finding_automatically(finding, scan_date, reference_code, filename)
            closed += 1

    db.flush()
    recalculate_all(db)

    db.add(models.AuditFile(
        reference_code=reference_code,
        filename=filename,
        uploaded_at=now,
        record_count=len(rows),
        source_type=f"{detected_source} Assessment",
        unmapped_ips=unmapped,
        new_findings=new,
        updated_findings=updated,
        reappeared_findings=reappeared,
        closed_findings=closed,
        assessed_ips=len(covered_applications),
        inconclusive_ips=0,
    ))
    db.commit()

    return {
        "reference": reference_code,
        "records": len(rows),
        "new": new,
        "updated": updated,
        "reappeared": reappeared,
        "closed": closed,
        "auto_excepted": auto_excepted,
        "unmapped": unmapped,
        "assessed_ips": len(covered_applications),
        "inconclusive_ips": 0,
        "inconclusive_rows": 0,
        "detected_type": detected_source,
        "skipped_rows": skipped_rows,
    }


def ingest_assets(db: Session, filename: str, rows: list[dict], reach=None) -> dict:
    """Load the asset register.

    An account restricted to some scopes may only load rows about those
    scopes, and may not reclassify an asset out of, or into, a scope it does
    not hold - otherwise the restriction could be lifted by uploading a file.
    """
    now = datetime.utcnow()
    created = updated = skipped = 0
    allocator = AssetCodeAllocator(db)
    # Rows queued with db.add() are not visible to a query before the flush,
    # so the assets created earlier in this same loop are tracked by hand.
    pending: dict[str, models.Asset] = {}
    for row in rows:
        ip = (row.get("ip_address") or "").strip()
        if not ip:
            continue
        existing = pending.get(ip.lower()) or db.query(models.Asset).filter(
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
            domain=row.get("domain") or (existing.domain if existing else None),
        )
        if reach is not None:
            # Both sides must be inside the grant: the row's own scope, and -
            # when the asset already exists - the scope it is being moved out
            # of.
            allowed = reach.covers_scope_value(fields["scope"])
            if existing:
                allowed = allowed and reach.covers_asset(existing)
            if not allowed:
                skipped += 1
                continue

        if existing:
            for k, v in fields.items():
                setattr(existing, k, v)
            updated += 1
        else:
            asset = models.Asset(
                asset_code=allocator.take(row.get("asset_code")),
                ip_address=ip,
                **fields,
            )
            db.add(asset)
            pending[ip.lower()] = asset
            created += 1
    db.flush()
    # The inventory may have just explained IPs that arrived with an earlier
    # assessment and were parked on the Default Asset.
    relinked = relink_unmapped_findings(db)
    recalculate_all(db)
    db.add(models.AuditFile(
        reference_code=next_assessment_code(db),
        filename=filename, uploaded_at=now, record_count=len(rows),
        source_type="Asset Inventory", unmapped_ips=0,
    ))
    db.commit()
    return {"records": len(rows), "created": created, "updated": updated,
            "relinked": relinked, "skipped_rows": skipped}


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------

@app.on_event("startup")
def _retire_lapsed_exceptions():
    """Nothing runs on the day an exception expires, so it is checked here.

    A platform that has been switched off over a weekend comes back with its
    lapsed exceptions already retired and the findings under them re-rated,
    rather than reporting cover that ended three days ago.
    """
    db = SessionLocal()
    try:
        retired = expire_due_exceptions(db)
        if retired:
            print(f"[startup] retired {retired} lapsed exception(s)")
    except Exception as exc:      # noqa: BLE001 - never block the boot
        print(f"[startup] could not check exception expiry: {exc}")
    finally:
        db.close()


@app.on_event("shutdown")
def _checkpoint_database():
    """Fold the write-ahead log back into the database file on the way out.

    Under WAL a recent change lives in assurance.db-wal until SQLite decides to
    checkpoint it. That is invisible in normal use, but it means the .db file
    on its own is behind - copying it, zipping it or backing it up without the
    -wal beside it silently loses whatever had not been folded in yet. Doing it
    here means a stopped platform always leaves one complete file.
    """
    try:
        with engine.begin() as conn:
            conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    except Exception as exc:      # noqa: BLE001 - never block the shutdown
        print(f"[shutdown] could not checkpoint the database: {exc}")


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
    user = db.query(models.User).filter(
        func.lower(models.User.username) == username.lower()).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="This account is disabled")
    user.last_login_at = datetime.utcnow()
    db.commit()
    token = create_access_token(user.username, user.role)
    response = JSONResponse({"ok": True, "user": user.to_dict()})
    # A session cookie: no max-age, so the browser drops it when it closes.
    # It used to be written with a twelve hour lifetime, which meant reopening
    # the browser the next morning landed straight on the dashboard as
    # whoever had signed in last - fine on one person's laptop, wrong for a
    # platform reached over the internet. The token itself still expires on
    # its own, so a cookie kept alive by a browser that never closes is not a
    # way around it either.
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, samesite="lax", path="/",
        secure=bool(os.environ.get("ASSURANCE_HTTPS")),
    )
    return response


@app.post("/api/logout")
def api_logout():
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


@app.api_route("/logout", methods=["GET", "POST"])
def logout():
    """Sign out and go back to the login page.

    Both verbs are accepted: the sidebar posts a form, and a plain link is a
    GET. Registering only GET made the sidebar button return 405, which is
    why signing out appeared to be broken.
    """
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response


# ---------------------------------------------------------------------------
# UI routes
# ---------------------------------------------------------------------------

MODULE_HOME = {
    "dashboard": "/", "findings": "/findings", "sla_tracking": "/sla-tracking",
    "retests": "/retests", "exceptions": "/exceptions", "assets": "/assets",
    "reports": "/reports", "settings": "/settings",
}


def _first_allowed_page(user) -> str:
    for key in models.MODULE_KEYS:
        if user.can_read(key):
            return MODULE_HOME[key]
    return "/no-access"


def _render(request: Request, template: str, module: str, ctx: dict = None):
    db = SessionLocal()
    try:
        user = ui_user(request, db)
        if not user:
            return RedirectResponse("/login", status_code=302)
        if not user.can_read(module):
            # Send the user somewhere they are allowed to be instead of
            # showing a page the navigation already hides.
            target = _first_allowed_page(user)
            if target == request.url.path:
                return templates.TemplateResponse(
                    request, "no_access.html",
                    {"request": request, "current_user": user, "path": request.url.path,
                     "modules": models.MODULES, "access": user.access_map(),
                     "view": view_for(request, user, db).to_dict()})
            return RedirectResponse(target, status_code=302)
        view = view_for(request, user, db)
        data = {
            "request": request,
            "current_user": user,
            "path": request.url.path,
            "module": module,
            "access": user.access_map(),
            "can_write": user.can_write(module),
            "modules": models.MODULES,
            # The header controls are rendered from the server so that a
            # restricted account never receives an option it is not allowed
            # to pick, not even in the markup.
            "view": view.to_dict(),
        }
        if ctx:
            data.update(ctx)
        return templates.TemplateResponse(request, template, data)
    finally:
        db.close()


@app.get("/")
def dashboard_page(request: Request):
    return _render(request, "dashboard.html", "dashboard")


# ---------------------------------------------------------------------------
# Full finding record - everything the platform holds, nothing summarised
# ---------------------------------------------------------------------------

def _raw_row(f: models.Finding) -> dict | None:
    """The stored sheet row, decoded. None for findings imported before the
    platform started keeping it."""
    if not f.raw_row:
        return None
    try:
        return json.loads(f.raw_row)
    except (ValueError, TypeError):
        return None


# Every column of the findings table, grouped for reading. The page is
# generated from this list, so a column added to the model later cannot be
# silently left off the record - _RECORD_UNGROUPED catches it.
RECORD_GROUPS = (
    ("Identity", ("finding_code", "id", "source", "external_ref", "plugin_name",
                  "severity", "compliance_result")),
    ("Where", ("ip_address", "port", "protocol", "asset_id",
               "application_name", "affected_location")),
    ("Classification", ("cwe_id", "owasp_category")),
    ("Assessment data", ("cve", "vpr_score", "first_discovered", "last_observed",
                         "source_file")),
    ("Lifecycle", ("status", "is_reappeared", "reappeared_count", "reappeared_at",
                   "original_created_at")),
    ("SLA", ("sla_status", "due_date", "sla_days", "sla_rule_applied_id")),
    ("Retest", ("retest_status", "retest_auto_flagged", "retest_updated_at")),
    ("Ownership and links", ("owner", "risk_id", "exception_id")),
    ("Closure", ("closed_at", "closed_by", "closure_method", "closure_evidence")),
)
_RECORD_LONG = ("description", "remediation_steps", "plugin_output", "raw_row")


def _record_value(f, name):
    value = getattr(f, name, None)
    if value is None or value == "":
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    if isinstance(value, bool):
        return "Yes" if value else "No"
    return str(value)


def _record_fields(f: models.Finding) -> list:
    """The stored record, grouped. Anything on the model that is not in a
    group and is not one of the long text blocks is appended at the end, so
    the page always shows the whole table."""
    named = {name for _, names in RECORD_GROUPS for name in names}
    named.update(_RECORD_LONG)
    groups = [(title, [(name.replace("_", " ").capitalize(), _record_value(f, name))
                       for name in names])
              for title, names in RECORD_GROUPS]
    leftovers = [(c.name.replace("_", " ").capitalize(), _record_value(f, c.name))
                 for c in models.Finding.__table__.columns if c.name not in named]
    if leftovers:
        groups.append(("Other stored fields", leftovers))
    return groups


@app.get("/findings/{finding_id}/record")
def finding_record_page(finding_id: int, request: Request):
    db = SessionLocal()
    try:
        user = _require_user(request, db, "findings")
        f = _viewable_finding(db, view_for(request, user, db), finding_id)
        exc = None
        exc_rec = (db.query(models.ExceptionRecord)
                   .filter(models.ExceptionRecord.finding_id == f.id)
                   .order_by(models.ExceptionRecord.id.desc()).first())
        if exc_rec:
            exc = exc_rec.to_dict()
        ctx = {
            "finding": finding_dict(f),
            "groups": _record_fields(f),
            "raw": _raw_row(f),
            "exception": exc,
            "asset": f.asset.to_dict() if f.asset else None,
            "long_text": [("Description", f.description),
                          ("Steps to remediate", f.remediation_steps),
                          ("Plugin output", f.plugin_output)],
        }
    finally:
        db.close()
    return _render(request, "finding_record.html", "findings", ctx)


@app.get("/findings")
def findings_page(request: Request):
    return _render(request, "findings.html", "findings")


@app.get("/sla-tracking")
def sla_tracking_page(request: Request):
    return _render(request, "sla_tracking.html", "sla_tracking")


@app.get("/assets")
def assets_page(request: Request):
    return _render(request, "assets.html", "assets")


@app.get("/exceptions")
def exceptions_page(request: Request):
    return _render(request, "exceptions.html", "exceptions")


@app.get("/retests")
def retests_page(request: Request):
    return _render(request, "retests.html", "retests")





@app.get("/reports")
def reports_page(request: Request):
    return _render(request, "reports.html", "reports")


@app.get("/settings")
def settings_page(request: Request):
    return _render(request, "settings.html", "settings")


@app.get("/no-access")
def no_access_page(request: Request):
    db = SessionLocal()
    try:
        user = ui_user(request, db)
        if not user:
            return RedirectResponse("/login", status_code=302)
        return templates.TemplateResponse(
            request, "no_access.html",
            {"request": request, "current_user": user, "path": "/no-access",
             "modules": models.MODULES, "access": user.access_map(),
             "view": view_for(request, user, db).to_dict()})
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------

@app.get("/api/summary")
def api_summary(request: Request, db: Session = Depends(get_db)):
    ui_user(request, db)  # auth gate for server context (raises via JSON below)
    user = _require_user(request, db, ("dashboard", "reports"))
    view = view_for(request, user, db)

    # Every number below is counted inside the view. Nothing is computed on
    # the whole database and then trimmed for display, because a total that
    # does not match the list under it is worse than no total at all.
    FC = view.finding_conditions()
    AC = view.asset_conditions()

    def fq(*conds):
        return db.query(models.Finding).filter(*FC, *conds)

    def aq(*conds):
        return db.query(models.Asset).filter(*AC, *conds)

    open_filter = models.Finding.status.in_(models.OPEN_STATUSES)
    total_open = fq(open_filter).count()

    def count_sla(st):
        return fq(open_filter, models.Finding.sla_status == st).count()

    within = count_sla(models.SLA_WITHIN)
    approaching = count_sla(models.SLA_APPROACHING)
    past_due = count_sla(models.SLA_PAST_DUE)
    exceeded = count_sla(models.SLA_EXCEEDED)
    under_exc = count_sla(models.SLA_UNDER_EXCEPTION)

    pending_retest = fq(open_filter, models.Finding.retest_status == "Pending").count()
    assigned = fq(open_filter, models.Finding.owner.isnot(None)).count()
    reappeared = fq(open_filter, models.Finding.is_reappeared.is_(True)).count()

    active_exceptions = (db.query(models.ExceptionRecord)
                         .filter(*view.exception_conditions(),
                                 models.ExceptionRecord.status == "Active").count())

    severity_counts = {sev: 0 for sev in ("Critical", "High", "Medium", "Low", "Info")}
    for sev, cnt in (db.query(models.Finding.severity, func.count(models.Finding.id))
                     .filter(*FC, open_filter)
                     .group_by(models.Finding.severity).all()):
        if sev in severity_counts:
            severity_counts[sev] = cnt

    workflow = {st: 0 for st in ("Open", "In Progress", "Pending Retest", "Closed")}
    for st, cnt in (db.query(models.Finding.status, func.count(models.Finding.id))
                    .filter(*FC).group_by(models.Finding.status).all()):
        if st in workflow:
            workflow[st] = cnt

    # --- where the open work comes from -----------------------------------
    va_open = fq(open_filter, models.Finding.source == "VA").count()
    cis_failed = fq(open_filter, models.Finding.source == "CIS",
                    models.Finding.compliance_result != models.RESULT_MANUAL).count()
    cis_manual = fq(open_filter, models.Finding.source == "CIS",
                    models.Finding.compliance_result == models.RESULT_MANUAL).count()
    # One open count per assessment, built from the list of sources rather
    # than named one by one, so a source added later appears here by itself.
    by_source = {code: 0 for code in models.SOURCES}
    for code, count in (db.query(models.Finding.source, func.count(models.Finding.id))
                        .filter(*FC, open_filter)
                        .group_by(models.Finding.source).all()):
        if code in by_source:
            by_source[code] = count

    closed_auto = fq(models.Finding.status == models.STATUS_CLOSED,
                     models.Finding.closure_method == models.CLOSURE_AUTOMATIC).count()
    closed_manual = fq(models.Finding.status == models.STATUS_CLOSED,
                       models.Finding.closure_method == models.CLOSURE_MANUAL).count()

    # --- assessment coverage ----------------------------------------------
    # Coverage is a statement about hosts: was this machine assessed with
    # working credentials. An application on the register is neither scanned
    # nor scannable that way, so it is left out rather than counted as a gap.
    host_only = (models.Asset.asset_code != "AST-0000",
                 func.coalesce(models.Asset.type, "") != models.ASSET_TYPE_APPLICATION)
    real_assets = aq(*host_only)
    assets_total = real_assets.count()
    coverage = {models.COVERAGE_ASSESSED: 0, models.COVERAGE_INCONCLUSIVE: 0,
                models.COVERAGE_NOT_ASSESSED: 0}
    for state, cnt in (db.query(models.Asset.coverage_state, func.count(models.Asset.id))
                       .filter(*AC, *host_only)
                       .group_by(models.Asset.coverage_state).all()):
        coverage[state or models.COVERAGE_NOT_ASSESSED] = (
            coverage.get(state or models.COVERAGE_NOT_ASSESSED, 0) + cnt)

    # An asset assessed months ago is not "covered" today. Anything more than
    # 30 days behind the newest assessment is reported as stale, because a
    # clean result from an old cycle says nothing about the asset now.
    latest_scan = (db.query(func.max(models.Asset.last_scanned_at))
                   .filter(*AC, *host_only).scalar())
    stale_before = (latest_scan - timedelta(days=30)) if latest_scan else None
    stale = 0
    if stale_before is not None:
        stale = (real_assets
                 .filter(models.Asset.coverage_state == models.COVERAGE_ASSESSED,
                         models.Asset.last_scanned_at < stale_before).count())

    gap_filter = or_(models.Asset.coverage_state != models.COVERAGE_ASSESSED,
                     models.Asset.coverage_state.is_(None))
    if stale_before is not None:
        gap_filter = or_(gap_filter, models.Asset.last_scanned_at < stale_before)
    gap_assets = real_assets.filter(gap_filter).all()

    # What the gap actually costs: findings on those assets can never close on
    # their own, because no assessment is allowed to prove them gone. The count
    # is per asset, so the list can say which IP is holding what.
    gap_ids = [a.id for a in gap_assets]
    findings_behind_gap = 0
    blocked_by_asset: dict[int, int] = {}
    if gap_ids:
        findings_behind_gap = fq(models.Finding.asset_id.in_(gap_ids), open_filter).count()
        for asset_id, count in (db.query(models.Finding.asset_id, func.count(models.Finding.id))
                                .filter(*FC, models.Finding.asset_id.in_(gap_ids), open_filter)
                                .group_by(models.Finding.asset_id).all()):
            blocked_by_asset[asset_id] = count

    def gap_state(asset):
        if asset.coverage_state == models.COVERAGE_INCONCLUSIVE:
            return "Credentials failed"
        if asset.coverage_state != models.COVERAGE_ASSESSED or not asset.coverage_state:
            return "Never assessed"
        return "Stale"

    # Worst first: the assets holding the most stuck findings.
    gaps = sorted(gap_assets,
                  key=lambda a: (-blocked_by_asset.get(a.id, 0),
                                 a.last_scanned_at or datetime.min,
                                 a.name or ""))[:60]

    # --- findings that never found an asset --------------------------------
    default_asset = aq(models.Asset.asset_code == "AST-0000").first()
    unmapped_findings = 0
    unmapped_ips = 0
    if default_asset:
        unmapped_findings = fq(models.Finding.asset_id == default_asset.id,
                               open_filter).count()
        unmapped_ips = (db.query(func.count(func.distinct(models.Finding.ip_address)))
                        .filter(*FC, models.Finding.asset_id == default_asset.id,
                                open_filter).scalar() or 0)

    # --- exceptions about to lapse ----------------------------------------
    today = date.today()
    horizon = today + timedelta(days=30)
    expiring = (
        db.query(models.ExceptionRecord)
        .options(joinedload(models.ExceptionRecord.finding)
                 .joinedload(models.Finding.asset))
        .filter(*view.exception_conditions(),
                models.ExceptionRecord.status == "Active",
                models.ExceptionRecord.expires_at.isnot(None),
                models.ExceptionRecord.expires_at <= horizon)
        .order_by(models.ExceptionRecord.expires_at.asc())
        .limit(6).all()
    )
    expiring_list = []
    for ex in expiring:
        f = ex.finding
        expiring_list.append({
            "exception_code": ex.exception_code,
            "reason": ex.reason,
            "control": (f.plugin_name if f else ex.control_key),
            "asset": (f.asset.name if f and f.asset else "Control-level"),
            "finding_id": f.id if f else None,
            "days_left": (ex.expires_at - today).days,
            "expires_at": _iso(ex.expires_at),
        })

    # --- busiest assets ----------------------------------------------------
    top_rows = (
        db.query(models.Asset.name, models.Asset.scope, models.Asset.ip_address,
                 func.count(models.Finding.id).label("open_count"))
        .join(models.Finding, models.Finding.asset_id == models.Asset.id)
        .filter(*FC, *AC, open_filter)
        .group_by(models.Asset.id)
        .order_by(func.count(models.Finding.id).desc())
        .limit(6).all()
    )
    top_assets = [{"name": r[0], "scope": r[1], "ip_address": r[2], "open": r[3]}
                  for r in top_rows]

    # The newest findings, worst first - ordering purely by Last Observed
    # filled the panel with one host, because a whole file shares one date.
    recent = (
        fq(open_filter).options(joinedload(models.Finding.asset))
        .order_by(models.Finding.first_discovered.desc(),
                  _order_expression(models.Finding.severity, SEVERITY_RANK),
                  models.Finding.id.desc())
        .limit(8).all()
    )

    last_audit = (db.query(models.AuditFile).filter(*view.audit_conditions())
                  .order_by(models.AuditFile.id.desc()).first())

    return {
        "user": user.to_dict(),
        "generated_at": _iso(datetime.utcnow()),
        "total_open": total_open,
        "within_sla": within,
        "approaching_sla": approaching,
        "sla_exceeded": exceeded,
        "past_due": past_due,
        "under_exception": under_exc,
        "pending_retest": pending_retest,
        "assigned": assigned,
        "reappeared": reappeared,
        "active_exceptions": active_exceptions,
        "total_findings": fq().count(),
        "closed": workflow["Closed"],
        "closed_automatic": closed_auto,
        "closed_manual": closed_manual,
        "severity_counts": severity_counts,
        "workflow": workflow,
        "sources": {"va": va_open, "cis_failed": cis_failed, "cis_manual": cis_manual},
        "by_source": by_source,
        "source_labels": dict(models.SOURCE_LABELS),
        "in_progress": workflow["In Progress"],
        "assets_total": assets_total,
        "assets_with_findings": db.query(
            func.count(func.distinct(models.Finding.asset_id))
        ).filter(*FC, open_filter).scalar() or 0,
        "coverage": {
            "assessed": coverage.get(models.COVERAGE_ASSESSED, 0),
            "inconclusive": coverage.get(models.COVERAGE_INCONCLUSIVE, 0),
            "not_assessed": coverage.get(models.COVERAGE_NOT_ASSESSED, 0),
            "pct": round(100.0 * coverage.get(models.COVERAGE_ASSESSED, 0) / assets_total, 1)
                   if assets_total else 0.0,
            "stale": stale,
            "blocked_findings": findings_behind_gap,
            "last_assessment_date": _iso(latest_scan),
            "gaps": [{
                "name": a.name, "ip_address": a.ip_address, "site": a.site,
                "asset_code": a.asset_code,
                "last_scanned_at": _iso(a.last_scanned_at),
                "blocked": blocked_by_asset.get(a.id, 0),
                "state": gap_state(a),
            } for a in gaps],
            "gap_total": len(gap_assets),
        },
        "unmapped_ips": unmapped_ips,
        "unmapped_findings": unmapped_findings,
        "exceptions_expiring": expiring_list,
        "top_assets": top_assets,
        "recent": [finding_dict(f) for f in recent],
        "last_assessment": last_audit.to_dict() if last_audit else None,
        "view": view.to_dict(),
    }


def _parse_range(date_from: str, date_to: str, fallback_start, fallback_end):
    """Turn the two date inputs into a usable window.

    Either end may be left empty, and an inverted range is swapped rather than
    returning nothing.
    """
    def parse(value, end_of_day=False):
        if not value:
            return None
        try:
            parsed = datetime.strptime(value[:10], "%Y-%m-%d")
        except ValueError:
            return None
        return parsed.replace(hour=23, minute=59, second=59) if end_of_day else parsed

    begin = parse(date_from) or fallback_start
    finish = parse(date_to, end_of_day=True) or fallback_end
    if begin > finish:
        begin, finish = finish, begin
    return begin, finish


@app.get("/api/dashboard/charts")
def api_dashboard_charts(request: Request, db: Session = Depends(get_db),
                         date_from: str = "", date_to: str = ""):
    user = _require_user(request, db, ("dashboard", "retests", "reports"))
    view = view_for(request, user, db)
    FC = view.finding_conditions()

    def fq(*conds):
        return db.query(models.Finding).filter(*FC, *conds)

    now = datetime.utcnow()

    # The chart window follows the data, not the wall clock. Assessment data
    # is uploaded in batches and is often weeks old; anchoring on "today"
    # produced an empty chart whenever the last upload was not this month.
    # It follows the data *inside the view*, so narrowing to one scope moves
    # the axis to that scope's own history instead of leaving dead space.
    first_seen = db.query(func.min(models.Finding.first_discovered)).filter(*FC).scalar()
    last_seen = db.query(func.max(models.Finding.last_observed)).filter(*FC).scalar()
    data_end = max(last_seen or now, now)
    data_start = first_seen or (data_end - timedelta(days=56))

    window_start, window_end = _parse_range(date_from, date_to, data_start, data_end)

    # A finding belongs to the window when its life overlaps it: discovered
    # on or before the end, and still observed on or after the start. Only
    # First Discovered and Last Observed are used - nothing else.
    in_window = (
        models.Finding.first_discovered <= window_end,
        models.Finding.last_observed >= window_start,
    )

    span_days = max((window_end - window_start).days, 7)
    buckets = 12
    step = max(span_days // buckets, 1)

    labels, opened, closed, within, approaching, exceeded = [], [], [], [], [], []
    for i in range(buckets):
        start_dt = window_start + timedelta(days=step * i)
        end_dt = (window_start + timedelta(days=step * (i + 1))
                  if i < buckets - 1 else window_end + timedelta(days=1))
        labels.append(start_dt.strftime("%d %b"))

        period = (models.Finding.first_discovered >= start_dt,
                  models.Finding.first_discovered < end_dt)
        opened.append(fq(*period).count())
        closed.append(fq(models.Finding.closed_at >= start_dt,
                         models.Finding.closed_at < end_dt).count())
        for bucket, state in ((within, models.SLA_WITHIN),
                              (approaching, models.SLA_APPROACHING),
                              (exceeded, models.SLA_EXCEEDED)):
            bucket.append(fq(*period,
                             models.Finding.status.in_(models.OPEN_STATUSES),
                             models.Finding.sla_status == state).count())
        # Past due sits with exceeded in the trend - both are over the line.
        exceeded[-1] += fq(*period,
                           models.Finding.status.in_(models.OPEN_STATUSES),
                           models.Finding.sla_status == models.SLA_PAST_DUE).count()

    # Aging profile of everything still open inside the window.
    bands = [("0-30 days", 0, 30), ("31-60 days", 31, 60),
             ("61-90 days", 61, 90), ("90+ days", 91, 100000)]
    aging_labels, aging_values = [], []
    for label, low, high in bands:
        newest = now - timedelta(days=low)
        oldest = now - timedelta(days=high + 1)
        aging_labels.append(label)
        aging_values.append(fq(
            *in_window,
            models.Finding.status.in_(models.OPEN_STATUSES),
            models.Finding.original_created_at <= newest,
            models.Finding.original_created_at > oldest).count())

    # Validation state, restricted to the window. Only findings that actually
    # went through validation are counted - "never asked for a retest" is the
    # absence of a state, not a state, and it drowned the real numbers.
    retest_labels = ["Pending", "Passed", "Failed"]
    retest_values = [fq(*in_window, models.Finding.retest_status == st).count()
                     for st in retest_labels]

    # Open findings per business scope - one asset can carry several scopes.
    scope_counts: dict[str, int] = {}
    rows = (db.query(models.Asset.scope, func.count(models.Finding.id))
            .join(models.Finding, models.Finding.asset_id == models.Asset.id)
            .filter(*FC, *in_window, models.Finding.status.in_(models.OPEN_STATUSES))
            .group_by(models.Asset.scope).all())
    # Under a scope selection only that scope is charted. An asset tagged
    # "Crown Jewel, PCI, Application" would otherwise smuggle its other two
    # scopes onto a screen that claims to be showing one.
    keep = set(view.scopes) if view.scopes is not None else None
    for raw_scope, count in rows:
        for value in (scoping.scope_tokens(raw_scope) or {"Unscoped"}):
            if keep is not None and value not in keep and value != "Unscoped":
                continue
            label = scope_label(value.lower())
            scope_counts[label] = scope_counts.get(label, 0) + count
    scope_counts = dict(sorted(scope_counts.items(), key=lambda kv: kv[1], reverse=True))

    total_open_line = [within[i] + approaching[i] + exceeded[i] for i in range(buckets)]
    matched = fq(*in_window).count()

    return {
        "window": {"from": _iso(window_start), "to": _iso(window_end),
                   "data_from": _iso(data_start), "data_to": _iso(data_end),
                   "filtered": bool(date_from or date_to),
                   "findings_in_window": matched},
        "aging_trend": {
            "labels": labels,
            "opened": opened,
            "closed": closed,
            "within": within,
            "approaching": approaching,
            "exceeded": exceeded,
            "total_open": total_open_line,
        },
        "aging_profile": {"labels": aging_labels, "values": aging_values},
        "retest_doughnut": {"labels": retest_labels, "values": retest_values},
        "scope_breakdown": {
            "labels": list(scope_counts.keys()),
            "values": list(scope_counts.values()),
        },
        "view": view.to_dict(),
    }


SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SLA_RANK = {models.SLA_EXCEEDED: 0, models.SLA_PAST_DUE: 1, models.SLA_APPROACHING: 2,
            models.SLA_WITHIN: 3, models.SLA_UNDER_EXCEPTION: 4, models.SLA_CLOSED: 5}


def _order_expression(column, ranking):
    """ORDER BY that follows meaning instead of the alphabet.

    Sorting severity as text puts Critical after High and Info in the middle;
    a CASE expression keeps the worst rows on the first page.
    """
    from sqlalchemy import case
    return case(ranking, value=column, else_=99)


@app.get("/api/filters")
def api_filters(request: Request, db: Session = Depends(get_db)):
    """Filter values that actually exist in this database.

    The dropdowns used to be hard-coded, so they offered scopes and teams that
    were never in the data and hid the ones that were.
    """
    user = _require_user(request, db)
    view = view_for(request, user, db)
    AC = view.asset_conditions()

    # The per-page dropdowns never offer a value the header has already ruled
    # out, and never a value this account is not granted. Offering one would
    # produce an empty table and imply data the user may not know about.
    scopes = list(view.scope_options) if view.scopes is None else list(view.scopes)
    if view.include_unscoped and not view.scope:
        scopes = scopes + [models.NO_ASSET_SCOPE]

    def distinct(column):
        return sorted({v for (v,) in db.query(column).filter(*AC).distinct().all() if v})

    return {
        "scopes": sorted(scopes),
        "view": view.to_dict(),
        "environments": distinct(models.Asset.environment),
        "sites": distinct(models.Asset.site),
        "types": distinct(models.Asset.type),
        "owners": distinct(models.Asset.owner_team)[:200],
        "severities": ["Critical", "High", "Medium", "Low", "Info"],
        "sources": list(view.sources) if view.sources is not None else list(models.SOURCES),
        # Every assessment the platform understands, regardless of the current
        # view. The SLA policy is global, so it must be writable against all
        # of them even while the screen is narrowed to one.
        "all_sources": list(models.SOURCES),
        "source_labels": dict(models.SOURCE_LABELS),
        "statuses": [models.STATUS_OPEN, models.STATUS_IN_PROGRESS,
                     models.STATUS_PENDING_RETEST, models.STATUS_CLOSED],
        "sla_statuses": [models.SLA_WITHIN, models.SLA_APPROACHING, models.SLA_PAST_DUE,
                         models.SLA_EXCEEDED, models.SLA_UNDER_EXCEPTION],
        "coverage_states": [models.COVERAGE_ASSESSED, models.COVERAGE_INCONCLUSIVE,
                            models.COVERAGE_NOT_ASSESSED],
        "exception_reasons": list(models.EXCEPTION_REASONS),
    }


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
    asset_id: int = 0,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=500),
):
    user = _require_user(request, db, "findings")
    view = view_for(request, user, db)
    # finding_dict() serialises the asset with every row, so it travels with
    # the query instead of costing one SELECT per finding.
    query = view.findings(
        db.query(models.Finding).options(joinedload(models.Finding.asset)))

    # One join for every asset-side filter - joining per filter produced a
    # cartesian product and silently inflated the row count.
    if scope or environment or owner_team:
        query = query.join(models.Asset, models.Finding.asset_id == models.Asset.id)

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
        # Scope is a comma separated field, so an asset can be in several of
        # them at once - the filter is a membership test, not equality.
        query = query.filter(or_(
            models.Asset.scope == scope,
            models.Asset.scope.ilike(f"{scope},%"),
            models.Asset.scope.ilike(f"%, {scope}"),
            models.Asset.scope.ilike(f"%, {scope},%"),
        ))
    if environment:
        query = query.filter(models.Asset.environment == environment)
    if owner_team:
        query = query.filter(models.Asset.owner_team == owner_team)
    if sla_status:
        query = query.filter(models.Finding.sla_status == sla_status)
    if retest:
        if retest == "None":
            query = query.filter(models.Finding.retest_status.is_(None))
        else:
            query = query.filter(models.Finding.retest_status == retest)
    if status:
        if status == "Open (any)":
            query = query.filter(models.Finding.status.in_(models.OPEN_STATUSES))
        else:
            query = query.filter(models.Finding.status == status)
    if asset_id:
        query = query.filter(models.Finding.asset_id == asset_id)

    total = query.count()
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)

    findings = (
        query.order_by(
            _order_expression(models.Finding.sla_status, SLA_RANK),
            _order_expression(models.Finding.severity, SEVERITY_RANK),
            models.Finding.last_observed.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "findings": [finding_dict(f) for f in findings],
        "total": total,
        "page": page,
        "pages": pages,
        "page_size": page_size,
        "showing": len(findings),
        "view": view.to_dict(),
    }


def _selected_findings(db, user, ids):
    """The findings from a bulk selection that this account may actually change.

    A selection arrives as a list of ids from the browser. The list is not
    trusted: an account granted Application only must not be able to close an
    Infrastructure finding by posting its id, whether it saw the row or
    guessed the number. Anything outside the grant is dropped here, and the
    caller reports how many were dropped rather than pretending they were
    done.
    """
    ids = [int(i) for i in (ids or []) if str(i).strip().lstrip("-").isdigit()]
    if not ids:
        return [], 0
    reach = scoping.WriteReach(user)
    rows = (db.query(models.Finding)
            .filter(*reach.finding_conditions(), models.Finding.id.in_(ids)).all())
    return rows, len(set(ids)) - len(rows)


@app.post("/api/findings/bulk/owner")
def api_bulk_owner(body: dict, user=Depends(module_write("findings")), db: Session = Depends(get_db)):
    owner = (body.get("owner") or "").strip() or None
    rows, skipped = _selected_findings(db, user, body.get("ids"))
    count = 0
    for f in rows:
        f.owner = owner
        count += 1
    db.commit()
    return {"ok": True, "count": count, "skipped": skipped}


@app.post("/api/findings/bulk/retest")
def api_bulk_retest(body: dict, user=Depends(module_write("findings")), db: Session = Depends(get_db)):
    rules = _ordered_rules(db)
    rows, skipped = _selected_findings(db, user, body.get("ids"))
    count = 0
    for f in rows:
        f.status = models.STATUS_PENDING_RETEST
        f.retest_status = "Pending"
        f.retest_auto_flagged = False   # requested by a person, not by the engine
        f.retest_updated_at = datetime.utcnow()
        recalculate_finding(db, f, rules)
        count += 1
    db.commit()
    return {"ok": True, "count": count, "skipped": skipped}


@app.post("/api/findings/bulk/exception")
def api_bulk_exception(body: dict, user=Depends(module_write("exceptions")), db: Session = Depends(get_db)):
    payload = exception_payload(body)
    rules = _ordered_rules(db)
    allocator = exception_code_allocator(db)
    rows, skipped = _selected_findings(db, user, body.get("ids"))
    count = 0
    for f in rows:
        create_exception_for(db, f, payload, user.username, allocator)
        recalculate_finding(db, f, rules)
        count += 1
    db.commit()
    return {"ok": True, "count": count, "skipped": skipped}


@app.post("/api/findings/bulk/risk")
def api_bulk_risk(body: dict, user=Depends(module_write("findings")), db: Session = Depends(get_db)):
    risk_id = (body.get("risk_id") or "").strip() or None
    rows, skipped = _selected_findings(db, user, body.get("ids"))
    count = 0
    for f in rows:
        f.risk_id = risk_id
        count += 1
    db.commit()
    return {"ok": True, "count": count, "skipped": skipped}


@app.post("/api/findings/bulk/close")
def api_bulk_close(body: dict, user=Depends(module_write("findings")), db: Session = Depends(get_db)):
    rules = _ordered_rules(db)
    note = (body.get("note") or "").strip() or None
    rows, skipped = _selected_findings(db, user, body.get("ids"))
    count = 0
    for f in rows:
        close_finding_manually(f, user.username, note)
        recalculate_finding(db, f, rules)
        count += 1
    db.commit()
    return {"ok": True, "count": count, "skipped": skipped}


def _writable_finding(db, user, finding_id):
    """One finding, by id, that this account is allowed to change.

    Outside the grant the answer is 404 rather than 403 on purpose: 403 would
    confirm that the row exists, which is exactly what a scope restriction is
    meant to withhold.
    """
    reach = scoping.WriteReach(user)
    f = (db.query(models.Finding)
         .filter(*reach.finding_conditions(), models.Finding.id == finding_id).first())
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


def _viewable_finding(db, view, finding_id):
    """One finding, by id, inside the current view."""
    f = (view.findings(db.query(models.Finding))
         .filter(models.Finding.id == finding_id).first())
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


@app.get("/api/findings/{finding_id}")
def api_finding_detail(finding_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db, "findings")
    f = _viewable_finding(db, view_for(request, user, db), finding_id)
    exc = None
    if f.exception_id:
        exc_rec = db.query(models.ExceptionRecord).filter(
            models.ExceptionRecord.finding_id == f.id
        ).order_by(models.ExceptionRecord.id.desc()).first()
        if exc_rec:
            exc = exc_rec.to_dict()
    return {"finding": finding_dict(f), "exception": exc, "raw": _raw_row(f)}


@app.post("/api/findings/{finding_id}/owner")
def api_assign_owner(finding_id: int, body: dict, user=Depends(module_write("findings")),
                     db: Session = Depends(get_db)):
    f = _writable_finding(db, user, finding_id)
    f.owner = (body.get("owner") or "").strip() or None
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/retest")
def api_send_retest(finding_id: int, user=Depends(module_write("findings")),
                    db: Session = Depends(get_db)):
    f = _writable_finding(db, user, finding_id)
    f.status = models.STATUS_PENDING_RETEST
    f.retest_status = "Pending"
    f.retest_auto_flagged = False   # requested by a person, not by the engine
    f.retest_updated_at = datetime.utcnow()
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/retest-result")
def api_retest_result(finding_id: int, body: dict, user=Depends(module_write("retests")),
                      db: Session = Depends(get_db)):
    f = _writable_finding(db, user, finding_id)
    result = (body.get("result") or "passed").lower()
    if result == "passed":
        # A validated retest is a human closure - it is recorded as such so it
        # is never confused with a closure proven by an assessment.
        close_finding_manually(f, user.username, "Retest validated")
        f.retest_status = "Passed"
        f.retest_auto_flagged = False
        f.retest_updated_at = datetime.utcnow()
    else:
        if f.status == models.STATUS_CLOSED:
            reopen_finding(f)
        f.status = models.STATUS_OPEN
        f.retest_status = "Failed"
        f.retest_auto_flagged = False
        f.retest_updated_at = datetime.utcnow()
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/close")
def api_close_finding(finding_id: int, user=Depends(module_write("findings")),
                      db: Session = Depends(get_db)):
    f = _writable_finding(db, user, finding_id)
    close_finding_manually(f, user.username)
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/status")
def api_set_status(finding_id: int, body: dict, user=Depends(module_write("findings")),
                   db: Session = Depends(get_db)):
    f = _writable_finding(db, user, finding_id)
    st = body.get("status") or models.STATUS_OPEN
    allowed = {models.STATUS_OPEN, models.STATUS_IN_PROGRESS,
               models.STATUS_PENDING_RETEST, models.STATUS_CLOSED}
    if st not in allowed:
        raise HTTPException(400, "Invalid status")
    if st == models.STATUS_CLOSED:
        close_finding_manually(f, user.username)
    else:
        if f.status == models.STATUS_CLOSED:
            reopen_finding(f)
        f.status = st
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


@app.post("/api/findings/{finding_id}/exception")
def api_add_exception(finding_id: int, body: dict, user=Depends(module_write("exceptions")),
                      db: Session = Depends(get_db)):
    f = _writable_finding(db, user, finding_id)
    exc = create_exception_for(db, f, exception_payload(body), user.username,
                               exception_code_allocator(db))
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "finding": finding_dict(f), "exception": exc.to_dict()}


@app.post("/api/findings/{finding_id}/risk")
def api_link_risk(finding_id: int, body: dict, user=Depends(module_write("findings")),
                  db: Session = Depends(get_db)):
    f = _writable_finding(db, user, finding_id)
    f.risk_id = (body.get("risk_id") or "").strip() or None
    db.commit()
    return {"ok": True, "finding": finding_dict(f)}


# ---------------------------------------------------------------------------
# Upload API
# ---------------------------------------------------------------------------

@app.post("/api/upload")
async def api_upload(
    files: list[UploadFile] = File(...),
    source_type: str = Form("assessment"),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Ingest one or many files in a single request.

    Two kinds of upload exist, and they live on the page they belong to:

      assessment  - VA, CIS, SAST, DAST or PT. Which one it is comes from the
                    CONTENT of the file, never from the file name or a
                    dropdown, so a mixed selection sorts itself out. An
                    application security workbook may carry one assessment per
                    sheet; each is correlated on its own.
      inventory   - the asset register, uploaded from the Assets page only.

    Assessments are processed oldest first. The correlation engine does not
    depend on the order, but processing them in date order keeps the per-file
    counts in the result readable ("this file closed 92 findings").
    """
    kind = (source_type or "assessment").lower().strip()
    inventory = kind in ("assets", "asset", "inventory")

    if inventory and not user.can_write("assets"):
        raise HTTPException(403, "Write access to Assets is required to upload an inventory")
    if not inventory and not user.can_write("findings"):
        raise HTTPException(403, "Write access to Findings is required to upload an assessment")

    if not files:
        raise HTTPException(400, "No file was selected")

    payloads = []
    for upload in files:
        content = await upload.read()
        name = upload.filename or "upload"
        if not name.lower().endswith((".xlsx", ".xls", ".csv")):
            continue          # folder uploads carry every file in the folder
        if not content:
            continue
        payloads.append((name, content))

    if not payloads:
        raise HTTPException(400, "None of the selected files is a spreadsheet (.xlsx or .csv)")

    # Oldest first, using the date in the file name when there is one.
    payloads.sort(key=lambda item: (parsers.scan_date_from_filename(item[0])
                                    or datetime.max, item[0]))

    # What may be written is the account's grant, never the header filter.
    # Looking at one scope is a way of reading; it must not silently discard
    # the rest of a report on the way in.
    reach = scoping.WriteReach(user)
    reach = None if reach.unrestricted else reach

    results, failures = [], []
    ignored = []
    totals = {"records": 0, "new": 0, "updated": 0, "reappeared": 0,
              "closed": 0, "unmapped": 0, "created": 0, "skipped_rows": 0}

    for name, content in payloads:
        try:
            if inventory:
                rows = parsers.parse_asset_inventory(name, content)
                if not rows:
                    raise ValueError("no usable rows found")
                stats = ingest_assets(db, name, rows, reach)
            else:
                # An application security workbook usually holds one
                # assessment per sheet, so each is correlated on its own -
                # they are separate assessments that happen to travel
                # together. Anything that is not one of those three falls
                # through to the infrastructure reader.
                appsec = parsers.parse_appsec_report(name, content)
                if appsec:
                    by_kind: dict[str, list] = {}
                    for row in appsec:
                        by_kind.setdefault(row["detected_source"], []).append(row)
                    stats = None
                    for kind, kind_rows in sorted(by_kind.items()):
                        part = ingest_appsec(db, name, kind_rows, reach)
                        if part.get("ignored"):
                            ignored.append({
                                "filename": f"{name} ({kind})",
                                "reason": f"{kind} assessments are outside this "
                                          "account's grant"})
                            continue
                        for key in totals:
                            totals[key] += part.get(key, 0) or 0
                        results.append({"filename": (name if len(by_kind) == 1
                                                     else f"{name} · {kind}"), **part})
                        stats = part
                    if stats is None:
                        continue
                    continue

                rows = parsers.parse_va_scan(name, content)
                if not rows:
                    raise ValueError("no usable rows found")
                stats = ingest_scan(db, name, rows, reach)
                if stats.get("ignored"):
                    ignored.append({"filename": name,
                                    "reason": f"{stats['skipped_source']} assessments are "
                                              "outside this account's grant"})
                    continue
        except Exception as exc:  # noqa: BLE001
            db.rollback()
            failures.append({"filename": name, "error": str(exc)})
            continue

        for key in totals:
            totals[key] += stats.get(key, 0) or 0
        results.append({"filename": name, **stats})

    if not results:
        detail = "; ".join(f"{f['filename']}: {f['error']}" for f in failures)
        if ignored and not detail:
            detail = "; ".join(f"{f['filename']}: {f['reason']}" for f in ignored)
        raise HTTPException(400, detail or "Nothing could be imported")

    return {
        "ok": True,
        "kind": "inventory" if inventory else "assessment",
        "processed": len(results),
        "failed": len(failures),
        "ignored": ignored,
        "skipped_rows": totals.get("skipped_rows", 0),
        "totals": totals,
        "files": results,
        "errors": failures,
    }


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
    coverage: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=10, le=500),
):
    user = _require_user(request, db, "assets")
    view = view_for(request, user, db)
    AC = view.asset_conditions()
    FC = view.finding_conditions()
    query = db.query(models.Asset).filter(*AC, models.Asset.asset_code != "AST-0000")
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            models.Asset.name.ilike(like),
            models.Asset.asset_code.ilike(like),
            models.Asset.ip_address.ilike(like),
            models.Asset.type.ilike(like),
            models.Asset.owner_team.ilike(like),
        ))
    if scope:
        query = query.filter(or_(
            models.Asset.scope == scope,
            models.Asset.scope.ilike(f"{scope},%"),
            models.Asset.scope.ilike(f"%, {scope}"),
            models.Asset.scope.ilike(f"%, {scope},%"),
        ))
    if environment:
        query = query.filter(models.Asset.environment == environment)
    if coverage:
        query = query.filter(models.Asset.coverage_state == coverage)

    total = query.count()
    pages = max(1, (total + page_size - 1) // page_size)
    page = min(page, pages)
    assets = (query.order_by(models.Asset.asset_code)
              .offset((page - 1) * page_size).limit(page_size).all())

    # Counting in SQL for the page only - walking asset.findings for every row
    # meant one query per asset and several seconds on a 1,400 asset register.
    ids = [a.id for a in assets]
    open_counts: dict[int, int] = {}
    crit_counts: dict[int, int] = {}
    if ids:
        for asset_id, count in (db.query(models.Finding.asset_id, func.count(models.Finding.id))
                                .filter(*FC, models.Finding.asset_id.in_(ids),
                                        models.Finding.status.in_(models.OPEN_STATUSES))
                                .group_by(models.Finding.asset_id).all()):
            open_counts[asset_id] = count
        for asset_id, count in (db.query(models.Finding.asset_id, func.count(models.Finding.id))
                                .filter(*FC, models.Finding.asset_id.in_(ids),
                                        models.Finding.status.in_(models.OPEN_STATUSES),
                                        models.Finding.severity.in_(("Critical", "High")))
                                .group_by(models.Finding.asset_id).all()):
            crit_counts[asset_id] = count

    result = [{
        **a.to_dict(),
        "open_findings": open_counts.get(a.id, 0),
        "critical": crit_counts.get(a.id, 0),
    } for a in assets]

    default_asset = db.query(models.Asset).filter(
        *AC, models.Asset.asset_code == "AST-0000").first()
    unmapped = 0
    if default_asset:
        unmapped = (db.query(func.count(func.distinct(models.Finding.ip_address)))
                    .filter(*FC, models.Finding.asset_id == default_asset.id)
                    .scalar() or 0)

    coverage_counts = {state: 0 for state in (models.COVERAGE_ASSESSED,
                                              models.COVERAGE_INCONCLUSIVE,
                                              models.COVERAGE_NOT_ASSESSED)}
    for state, count in (db.query(models.Asset.coverage_state, func.count(models.Asset.id))
                         .filter(*AC, models.Asset.asset_code != "AST-0000",
                                 func.coalesce(models.Asset.type, "")
                                 != models.ASSET_TYPE_APPLICATION)
                         .group_by(models.Asset.coverage_state).all()):
        coverage_counts[state or models.COVERAGE_NOT_ASSESSED] = (
            coverage_counts.get(state or models.COVERAGE_NOT_ASSESSED, 0) + count)

    return {
        "assets": result,
        "total": total,
        "page": page,
        "pages": pages,
        "page_size": page_size,
        "registered": db.query(models.Asset).filter(
            *AC, models.Asset.asset_code != "AST-0000").count(),
        "assessed": coverage_counts.get(models.COVERAGE_ASSESSED, 0),
        "coverage": coverage_counts,
        "open_total": db.query(models.Finding).filter(
            *FC, models.Finding.status.in_(models.OPEN_STATUSES)).count(),
        "unmapped_ips": unmapped,
        "view": view.to_dict(),
    }


@app.get("/api/assets/{asset_id}")
def api_asset_detail(asset_id: int, request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db, "assets")
    view = view_for(request, user, db)
    a = view.assets(db.query(models.Asset)).filter(models.Asset.id == asset_id).first()
    if not a:
        raise HTTPException(404, "Asset not found")
    open_ids = set(models.OPEN_STATUSES)
    # The asset's own findings are filtered too - an assessment selection has
    # to reach the detail panel, not stop at the list behind it.
    visible = [f for f in a.findings if view.covers_source(f.source)]
    open_findings = sorted(
        [f for f in visible if f.status in open_ids],
        key=lambda f: f.severity,
    )
    history = []
    for f in sorted(visible, key=lambda x: (x.last_observed or x.first_discovered or datetime.utcnow()), reverse=True):
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
    user = _require_user(request, db, "sla_tracking")
    view = view_for(request, user, db)
    now = datetime.utcnow()
    # The asset is read for every finding here - for its name and for the
    # responsible domain - so it is fetched in the same query. Left lazy it was
    # one extra SELECT per finding: over a thousand round trips for one page,
    # which only showed up once several people used the platform at once.
    open_findings = view.findings(
        db.query(models.Finding).options(joinedload(models.Finding.asset))
    ).filter(models.Finding.status.in_(models.OPEN_STATUSES)).all()

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
    domains = ["Server", "Network", "Virtualisation", "Storage", "Database",
               "Security", "Unmapped", "Other"]
    by_domain = {d: {"exceeded": 0, "past_due": 0, "approaching": 0, "within": 0, "exception": 0}
                 for d in domains}
    for f in open_findings:
        dom = domain_for_asset(f.asset)
        bucket = by_domain.setdefault(dom, {"exceeded": 0, "past_due": 0, "approaching": 0,
                                            "within": 0, "exception": 0})
        key = {"SLA Exceeded": "exceeded", "Past Due": "past_due",
               "Approaching SLA": "approaching",
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
                "domain": domain_for_asset(f.asset),
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

    counts = {status: sum(1 for f in open_findings if f.sla_status == status)
              for status in (models.SLA_EXCEEDED, models.SLA_PAST_DUE, models.SLA_APPROACHING,
                             models.SLA_WITHIN, models.SLA_UNDER_EXCEPTION)}

    return {
        "counts": {
            "exceeded": counts[models.SLA_EXCEEDED],
            "past_due": counts[models.SLA_PAST_DUE],
            "approaching": counts[models.SLA_APPROACHING],
            "within": counts[models.SLA_WITHIN],
            "exception": counts[models.SLA_UNDER_EXCEPTION],
            "shown": 25,
        },
        "forecast": {"labels": forecast_labels, "values": forecast_values},
        "by_domain": {
            "labels": domains,
            "exceeded": [by_domain[d]["exceeded"] for d in domains],
            "past_due": [by_domain[d]["past_due"] for d in domains],
            "approaching": [by_domain[d]["approaching"] for d in domains],
            "within": [by_domain[d]["within"] for d in domains],
            "exception": [by_domain[d]["exception"] for d in domains],
        },
        "exceeded": _list(models.SLA_EXCEEDED),
        "past_due": _list(models.SLA_PAST_DUE),
        "approaching": _list(models.SLA_APPROACHING),
        "within": _list(models.SLA_WITHIN),
        "view": view.to_dict(),
    }


# ---------------------------------------------------------------------------
# SLA Policy Rules (admin)
# ---------------------------------------------------------------------------

@app.get("/api/sla-rules")
def api_sla_rules(request: Request, user=Depends(module_read("settings")), db: Session = Depends(get_db)):
    _require_user(request, db, "settings")
    rules = db.query(models.SLARule).order_by(models.SLARule.priority_order).all()
    # How many open findings each rule is currently governing - a rule that
    # matches nothing is usually a rule sitting under a broader one.
    usage = dict(
        db.query(models.Finding.sla_rule_applied_id, func.count(models.Finding.id))
        .filter(models.Finding.status.in_(models.OPEN_STATUSES))
        .group_by(models.Finding.sla_rule_applied_id).all()
    )
    return {
        "rules": [{**r.to_dict(), "matched_findings": usage.get(r.id, 0)} for r in rules],
        "catch_all_id": rules[-1].id if rules else None,
        "can_write": user.can_write("settings"),
        "unmatched": usage.get(None, 0),
    }


@app.get("/api/sla-rules/log")
def api_sla_rules_log(request: Request, user=Depends(module_read("settings")), db: Session = Depends(get_db)):
    _require_user(request, db, "settings")
    logs = db.query(models.PolicyChangeLog).order_by(
        models.PolicyChangeLog.id.desc()).limit(30).all()
    return {"logs": [l.to_dict() for l in logs]}


def _validated_rule_numbers(body, current=None):
    """The three numbers on an SLA rule, checked before they reach the engine.

    They were taken on trust. A window of -10 days gave every matching finding
    a deadline before it was discovered, so the whole set read as breached the
    moment the rule was saved; a percentage of 500 put the approaching band and
    the retest trigger years past the deadline, where neither could ever fire.
    Neither is a state anyone would ask for on purpose, and neither is
    recoverable by looking at the screen - the numbers simply come out wrong.
    """
    def number(name, label, low, high, fallback):
        raw = body.get(name, fallback)
        if raw is None or raw == "":
            raw = fallback
        try:
            value = int(raw)
        except (TypeError, ValueError):
            raise HTTPException(400, f"{label} must be a whole number")
        if not (low <= value <= high):
            raise HTTPException(400, f"{label} must be between {low} and {high}")
        return value

    days = number("sla_days", "The SLA window", 1, 3650,
                  current.sla_days if current else 90)
    approaching = number("approaching_pct", "The approaching threshold", 1, 100,
                         current.approaching_pct if current else 70)
    retest = number("retest_pct", "The retest trigger", 1, 100,
                    current.retest_pct if current else 80)
    return days, approaching, retest


@app.post("/api/sla-rules")
def api_create_rule(body: dict, user=Depends(module_write("settings")),
                    db: Session = Depends(get_db)):
    # A new rule goes immediately ABOVE the catch-all. Appending it at the
    # bottom made it unreachable: the catch-all matches everything, and the
    # first match wins, so a rule below it can never fire.
    existing = _ordered_rules(db)
    days, approaching, retest = _validated_rule_numbers(body)

    # A rule with "Any" in every dimension IS the catch-all. A second one
    # placed above the real catch-all shadows it completely and can never be
    # told apart from it on screen - the policy then has an undeletable rule
    # nothing reaches. One is all there can be.
    dimensions = {field: (body.get(field) or "Any")
                  for field in ("source", "severity", "asset_scope",
                                "asset_type", "environment")}
    if all(value == "Any" for value in dimensions.values()):
        raise HTTPException(
            400, "A rule that matches everything is the catch-all, and there is "
                 "already one at the bottom of the policy. Edit that instead, or "
                 "narrow this rule.")
    try:
        position = int(body.get("priority_order") or max(len(existing), 1))
    except (TypeError, ValueError):
        raise HTTPException(400, "The position must be a whole number")
    position = max(1, min(position, max(len(existing), 1)))
    rule = models.SLARule(
        priority_order=position,
        source=dimensions["source"],
        severity=dimensions["severity"],
        asset_scope=dimensions["asset_scope"],
        asset_type=dimensions["asset_type"],
        environment=dimensions["environment"],
        sla_days=days,
        approaching_pct=approaching,
        retest_pct=retest,
        is_active=bool(body.get("is_active", True)),
    )
    db.add(rule)
    db.flush()
    # Renumber so the ordering stays 1..n with the catch-all last.
    ordered = [r for r in existing if r.id != rule.id]
    ordered.insert(min(position - 1, len(ordered)), rule)
    if len(ordered) > 1 and ordered[-1] is rule:
        ordered[-2], ordered[-1] = ordered[-1], ordered[-2]
    for index, item in enumerate(ordered, start=1):
        item.priority_order = index
    db.flush()
    log_policy_change(db, f"Added rule #{rule.priority_order} [{rule.source}/{rule.severity} -> {rule.sla_days}d]", user)
    recalculate_all(db)
    return {"ok": True, "rule": rule.to_dict(),
            "recalculated": db.query(models.Finding).count()}


@app.put("/api/sla-rules/{rule_id}")
def api_update_rule(rule_id: int, body: dict, user=Depends(module_write("settings")),
                    db: Session = Depends(get_db)):
    rule = db.query(models.SLARule).filter(models.SLARule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    # The same checks as creation - an edit is just as capable of producing a
    # rule with a negative window as a new one was.
    days, approaching, retest = _validated_rule_numbers(body, rule)
    for field in ("source", "severity", "asset_scope", "asset_type", "environment",
                  "is_active"):
        if field in body:
            setattr(rule, field, body[field])
    rule.sla_days, rule.approaching_pct, rule.retest_pct = days, approaching, retest
    db.commit()
    log_policy_change(db, f"Updated rule #{rule.priority_order} [{rule.source}/{rule.severity}]", user)
    recalculate_all(db)
    return {"ok": True, "rule": rule.to_dict(),
            "recalculated": db.query(models.Finding).count()}


@app.delete("/api/sla-rules/{rule_id}")
def api_delete_rule(rule_id: int, user=Depends(module_write("settings")),
                    db: Session = Depends(get_db)):
    """Remove a rule and close the gap in the ordering.

    The last rule is the catch-all: it is what guarantees every finding gets
    an SLA at all, so it cannot be deleted - only edited.
    """
    rules = _ordered_rules(db)
    rule = next((r for r in rules if r.id == rule_id), None)
    if not rule:
        raise HTTPException(404, "Rule not found")
    if len(rules) == 1 or rules[-1].id == rule.id:
        raise HTTPException(
            400, "The last rule is the catch-all and cannot be deleted. Edit it instead.")

    description = (f"{rule.source}/{rule.severity}/{rule.asset_scope}/"
                   f"{rule.asset_type}/{rule.environment} -> {rule.sla_days}d")

    # Every finding this rule had matched still points at it. The pointer has
    # to be released before the row goes, or the delete is refused by the
    # foreign key - and, before foreign keys were enforced, it left findings
    # quietly referencing a rule that no longer existed. The recalculation
    # below gives each of them whichever rule now matches.
    released = (db.query(models.Finding)
                .filter(models.Finding.sla_rule_applied_id == rule.id)
                .update({models.Finding.sla_rule_applied_id: None},
                        synchronize_session=False))
    db.flush()
    db.delete(rule)
    db.flush()
    for index, remaining in enumerate(_ordered_rules(db), start=1):
        remaining.priority_order = index
    log_policy_change(db, f"Deleted SLA rule #{rule.priority_order} ({description})", user)
    db.flush()
    # Every finding may now match a different rule, so the whole ledger is
    # recalculated - a policy change is never allowed to leave a stale due date.
    recalculate_all(db)
    db.commit()
    return {"ok": True, "released": released,
            "recalculated": db.query(models.Finding).count()}


@app.post("/api/sla-rules/{rule_id}/toggle")
def api_toggle_rule(rule_id: int, user=Depends(module_write("settings")),
                    db: Session = Depends(get_db)):
    rule = db.query(models.SLARule).filter(models.SLARule.id == rule_id).first()
    if not rule:
        raise HTTPException(404, "Rule not found")
    rule.is_active = not rule.is_active
    db.commit()
    log_policy_change(
        db, f"{'Enabled' if rule.is_active else 'Disabled'} rule #{rule.priority_order}", user)
    recalculate_all(db)
    return {"ok": True, "rule": rule.to_dict(),
            "recalculated": db.query(models.Finding).count()}


@app.post("/api/sla-rules/{rule_id}/move")
def api_move_rule(rule_id: int, body: dict, user=Depends(module_write("settings")),
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
    if target == len(rules) - 1 or idx == len(rules) - 1:
        raise HTTPException(400, "The catch-all rule must stay last")
    rules[idx], rules[target] = rules[target], rules[idx]
    for i, r in enumerate(rules):
        r.priority_order = i + 1
    db.commit()
    log_policy_change(db, f"Moved rule #{rule.priority_order} {direction}", user)
    recalculate_all(db)
    return {"ok": True, "rules": [r.to_dict() for r in _ordered_rules(db)],
            "recalculated": db.query(models.Finding).count()}


@app.post("/api/sla-rules/simulate")
def api_simulate_rule(body: dict, request: Request, user=Depends(module_read("settings")), db: Session = Depends(get_db)):
    _require_user(request, db, "settings")
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
def api_recalculate(user=Depends(module_write("settings")), db: Session = Depends(get_db)):
    count = recalculate_all(db)
    return {"ok": True, "recalculated": count}


# ---------------------------------------------------------------------------
# Exceptions API
# ---------------------------------------------------------------------------

@app.get("/api/exceptions")
def api_exceptions(request: Request, db: Session = Depends(get_db),
                   page: int = Query(1, ge=1), page_size: int = Query(25, ge=5, le=200),
                   status: str = "", q: str = ""):
    user = _require_user(request, db, "exceptions")
    view = view_for(request, user, db)
    EC = view.exception_conditions()
    today = date.today()

    expire_due_exceptions(db)

    query = db.query(models.ExceptionRecord).filter(*EC)
    if status:
        query = query.filter(models.ExceptionRecord.status == status)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(
            models.ExceptionRecord.exception_code.ilike(like),
            models.ExceptionRecord.control_key.ilike(like),
            models.ExceptionRecord.reason.ilike(like),
            models.ExceptionRecord.approval_ref.ilike(like),
        ))
    total = query.count()
    records = (query.options(joinedload(models.ExceptionRecord.finding)
                             .joinedload(models.Finding.asset))
               .order_by(models.ExceptionRecord.created_at.desc(),
                         models.ExceptionRecord.id.desc())
               .offset((page - 1) * page_size).limit(page_size).all())

    ex_list = []
    for ex in records:
        f = ex.finding
        ex_list.append({
            **ex.to_dict(),
            "finding_code": f.finding_code if f else None,
            "severity": f.severity if f else None,
            "plugin_name": f.plugin_name if f else (ex.control_key or None),
            "ip_address": f.ip_address if f else None,
            "asset": f.asset.name if f and f.asset else None,
            "is_template": f is None,
        })
    return {
        "exceptions": ex_list,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "reasons": list(models.EXCEPTION_REASONS),
        "active": db.query(models.ExceptionRecord).filter(
            *EC, models.ExceptionRecord.status == "Active").count(),
        "expired": db.query(models.ExceptionRecord).filter(
            *EC, models.ExceptionRecord.status == "Expired").count(),
        "standing": db.query(models.ExceptionRecord).filter(
            *EC, models.ExceptionRecord.finding_id.is_(None),
            models.ExceptionRecord.status == "Active").count(),
        "view": view.to_dict(),
    }


@app.get("/api/exceptions/controls")
def api_exception_controls(request: Request, db: Session = Depends(get_db),
                           q: str = "", source: str = ""):
    """Controls that currently have open findings - the first step of the wizard."""
    user = _require_user(request, db, "exceptions")
    view = view_for(request, user, db)
    query = (
        db.query(
            models.Finding.plugin_name,
            models.Finding.source,
            func.count(models.Finding.id).label("findings"),
            func.count(func.distinct(models.Finding.ip_address)).label("hosts"),
        )
        .filter(*view.finding_conditions(),
                models.Finding.status.in_(models.OPEN_STATUSES))
    )
    if source:
        query = query.filter(models.Finding.source == source)
    if q:
        query = query.filter(models.Finding.plugin_name.ilike(f"%{q}%"))
    rows = (query.group_by(models.Finding.plugin_name, models.Finding.source)
            .order_by(func.count(models.Finding.id).desc()).limit(100).all())
    return {"controls": [
        {"plugin_name": r[0], "source": r[1], "findings": r[2], "hosts": r[3]}
        for r in rows
    ]}


@app.get("/api/exceptions/targets")
def api_exception_targets(request: Request, db: Session = Depends(get_db),
                          control: str = "", source: str = ""):
    """Every IP a control is currently failing on, so the user can tick a subset."""
    user = _require_user(request, db, "exceptions")
    view = view_for(request, user, db)
    if not control:
        return {"targets": []}
    query = view.findings(
        db.query(models.Finding).options(joinedload(models.Finding.asset))
    ).filter(
        models.Finding.plugin_name == control,
        models.Finding.status.in_(models.OPEN_STATUSES),
    )
    if source:
        query = query.filter(models.Finding.source == source)
    targets = []
    for f in query.order_by(models.Finding.ip_address).limit(1000).all():
        targets.append({
            "id": f.id,
            "finding_code": f.finding_code,
            "ip_address": f.ip_address,
            "asset": f.asset.name if f.asset else "Unmapped",
            "scope": f.asset.scope if f.asset else "No Asset",
            "severity": f.severity,
            "port": f.port,
            "protocol": f.protocol,
            "sla_status": f.sla_status,
            "already_excepted": bool(f.exception_id),
        })
    return {"targets": targets, "count": len(targets)}


@app.post("/api/exceptions/scoped")
def api_scoped_exception(body: dict, user=Depends(module_write("exceptions")),
                         db: Session = Depends(get_db)):
    """Apply one decision to a control across the IPs the user selected.

    Three shapes are supported, and they combine:
      * the ticked findings only;
      * every IP the control is currently failing on;
      * future occurrences, stored as a control-level record that later
        assessments apply automatically.
    """
    control = (body.get("control") or "").strip()
    if not control:
        raise HTTPException(400, "A control must be selected")
    source = (body.get("source") or "").strip() or None
    payload = exception_payload(body)
    all_current = bool(body.get("all_current"))
    future = bool(body.get("applies_to_future"))
    ids = body.get("finding_ids") or []

    reach = scoping.WriteReach(user)
    query = db.query(models.Finding).filter(
        *reach.finding_conditions(),
        models.Finding.plugin_name == control,
        models.Finding.status.in_(models.OPEN_STATUSES),
    )
    if source:
        if not reach.covers_source(source):
            raise HTTPException(403, f"{source} assessments are outside this account's grant")
        query = query.filter(models.Finding.source == source)
    if not all_current:
        if not ids:
            raise HTTPException(400, "Select at least one host, or apply to all current hosts")
        query = query.filter(models.Finding.id.in_(ids))
    targets = query.all()

    allocator = exception_code_allocator(db)
    rules = _ordered_rules(db)
    applied = 0
    for f in targets:
        if f.exception_id:
            continue
        create_exception_for(db, f, payload, user.username, allocator)
        recalculate_finding(db, f, rules)
        applied += 1

    template_code = None
    if future:
        scope_ips = None if all_current else ",".join(
            sorted({f.ip_address for f in targets if f.ip_address}))
        template = models.ExceptionRecord(
            exception_code=allocator.take(datetime.utcnow().year),
            finding_id=None,
            control_key=control,
            source=source,
            scope_ips=scope_ips,
            applies_to_future=True,
            status="Active",
            created_by=user.username,
            **payload,
        )
        db.add(template)
        db.flush()
        template_code = template.exception_code

    db.add(models.PolicyChangeLog(
        action=(f"Exception applied to control '{control}' on {applied} finding(s)"
                + (f"; future occurrences covered by {template_code}" if template_code else "")),
        user=user.username,
    ))
    db.commit()
    return {"ok": True, "applied": applied, "template": template_code,
            "targets": len(targets)}


@app.post("/api/exceptions/{exception_id}/revoke")
def api_revoke_exception(exception_id: int, user=Depends(module_write("exceptions")),
                         db: Session = Depends(get_db)):
    """End an exception now - the SLA clock never stopped, so the finding
    immediately shows its true position."""
    reach = scoping.WriteReach(user)
    ex = db.query(models.ExceptionRecord).filter(
        models.ExceptionRecord.id == exception_id).first()
    if not ex:
        raise HTTPException(404, "Exception not found")
    # A finding-level exception is only revocable by someone who may change
    # the finding under it. A control-level one needs the assessment grant.
    if ex.finding is not None:
        if not reach.covers_finding(ex.finding):
            raise HTTPException(404, "Exception not found")
    elif not reach.covers_source(ex.source):
        raise HTTPException(404, "Exception not found")
    ex.status = "Revoked"
    if ex.finding:
        ex.finding.exception_id = None
        # The session runs with autoflush off, so the revoke above is still
        # only in memory. The SLA engine re-reads the exception table to decide
        # whether the finding is covered, and without this flush it read the
        # row it was in the middle of revoking - the finding stayed "Under
        # Exception" for ever, hidden from the breach reports.
        db.flush()
        recalculate_finding(db, ex.finding, _ordered_rules(db))
    db.add(models.PolicyChangeLog(
        action=f"Exception {ex.exception_code} revoked", user=user.username))
    db.commit()
    return {"ok": True}


@app.post("/api/exceptions")
def api_create_exception(body: dict, user=Depends(module_write("exceptions")),
                         db: Session = Depends(get_db)):
    finding_id = body.get("finding_id")
    f = _writable_finding(db, user, finding_id)
    ex = create_exception_for(db, f, exception_payload(body), user.username,
                              exception_code_allocator(db))
    recalculate_finding(db, f, _ordered_rules(db))
    db.commit()
    return {"ok": True, "exception": ex.to_dict()}


# ---------------------------------------------------------------------------
# Audit & Reports API
# ---------------------------------------------------------------------------

@app.get("/api/audit")
def api_audit(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db, "reports")
    view = view_for(request, user, db)
    files = (db.query(models.AuditFile).filter(*view.audit_conditions())
             .order_by(models.AuditFile.id.desc()).limit(100).all())
    return {"files": [f.to_dict() for f in files], "view": view.to_dict()}


@app.get("/api/reports/summary")
def api_reports_summary(request: Request, db: Session = Depends(get_db)):
    """Aggregates for the Reports page.

    These used to be computed in the browser from the first page of findings,
    so every chart silently described a sample instead of the population.
    """
    user = _require_user(request, db, "reports")
    view = view_for(request, user, db)
    FC = view.finding_conditions()
    open_filter = models.Finding.status.in_(models.OPEN_STATUSES)

    severities = ["Critical", "High", "Medium", "Low", "Info"]
    states = [models.SLA_EXCEEDED, models.SLA_PAST_DUE, models.SLA_APPROACHING,
              models.SLA_WITHIN, models.SLA_UNDER_EXCEPTION]
    matrix = {sev: {st: 0 for st in states} for sev in severities}
    for sev, state, count in (db.query(models.Finding.severity, models.Finding.sla_status,
                                       func.count(models.Finding.id))
                              .filter(*FC, open_filter)
                              .group_by(models.Finding.severity, models.Finding.sla_status).all()):
        if sev in matrix and state in matrix[sev]:
            matrix[sev][state] = count

    scope_counts: dict[str, int] = {}
    keep = set(view.scopes) if view.scopes is not None else None
    for raw_scope, count in (db.query(models.Asset.scope, func.count(models.Finding.id))
                             .join(models.Finding, models.Finding.asset_id == models.Asset.id)
                             .filter(*FC, open_filter).group_by(models.Asset.scope).all()):
        for value in (scoping.scope_tokens(raw_scope) or {"Unscoped"}):
            if keep is not None and value not in keep and value != "Unscoped":
                continue
            label = scope_label(value.lower())
            scope_counts[label] = scope_counts.get(label, 0) + count
    scope_counts = dict(sorted(scope_counts.items(), key=lambda kv: kv[1], reverse=True))

    owners = (db.query(models.Asset.owner_team, func.count(models.Finding.id))
              .join(models.Finding, models.Finding.asset_id == models.Asset.id)
              .filter(*FC, open_filter, models.Finding.sla_status == models.SLA_EXCEEDED)
              .group_by(models.Asset.owner_team)
              .order_by(func.count(models.Finding.id).desc()).limit(10).all())

    return {
        "severities": severities,
        "states": states,
        "matrix": {sev: [matrix[sev][st] for st in states] for sev in severities},
        "scope": {"labels": list(scope_counts.keys()), "values": list(scope_counts.values())},
        "breach_owners": [{"owner": o or "Unassigned", "count": c} for o, c in owners],
        "view": view.to_dict(),
    }


@app.get("/api/reports/movement")
def api_reports_movement(request: Request, db: Session = Depends(get_db),
                         date_from: str = "", date_to: str = "", days: int = 30):
    """What actually moved inside a period.

    The rest of the Reports page describes where the estate stands right now.
    This one answers the other question - over these dates, what was fixed,
    what came back, what is new, and what is still sitting there.

    Every number below is anchored on a date the platform recorded when the
    event happened:
      discovered   first_discovered
      fixed        closed_at        (only a credentialed assessment sets it)
      reappeared   reappeared_at
      breached     due_date, for findings that are still open
    Nothing is inferred from the upload order.
    """
    user = _require_user(request, db, "reports")
    view = view_for(request, user, db)
    FC = view.finding_conditions()

    now = datetime.utcnow()
    newest = db.query(func.max(models.Finding.last_observed)).filter(*FC).scalar() or now
    end_default = max(newest, now)
    start_default = end_default - timedelta(days=max(days, 1))
    start, end = _parse_range(date_from, date_to, start_default, end_default)
    # The page shows two dates and the numbers underneath must be those two
    # whole days. Carrying the time of the newest assessment through meant the
    # first day of the window started at, say, 14:20 - and anything discovered
    # that morning fell outside a period the screen said it was inside.
    start = start.replace(hour=0, minute=0, second=0, microsecond=0)
    end = end.replace(hour=23, minute=59, second=59, microsecond=999999)

    def count(*conditions):
        return (db.query(func.count(models.Finding.id))
                .filter(*FC, *conditions).scalar() or 0)

    discovered = count(models.Finding.first_discovered >= start,
                       models.Finding.first_discovered <= end)
    fixed = count(models.Finding.closed_at.isnot(None),
                  models.Finding.closed_at >= start,
                  models.Finding.closed_at <= end)
    reappeared = count(models.Finding.reappeared_at.isnot(None),
                       models.Finding.reappeared_at >= start,
                       models.Finding.reappeared_at <= end)
    # Open at the end of the window: it existed by then and nothing closed it
    # on or before the end.
    still_open = count(models.Finding.first_discovered <= end,
                       models.Finding.status.in_(models.OPEN_STATUSES))
    breached = count(models.Finding.status.in_(models.OPEN_STATUSES),
                     models.Finding.due_date.isnot(None),
                     models.Finding.due_date >= start,
                     models.Finding.due_date <= end,
                     models.Finding.sla_status.in_([models.SLA_EXCEEDED, models.SLA_PAST_DUE]))

    # Weekly buckets, so a month reads as four columns rather than thirty.
    span = max((end - start).days, 1)
    step = max(span // 8, 1)
    labels, new_series, fixed_series, back_series = [], [], [], []
    cursor = start
    while cursor < end:
        stop = min(cursor + timedelta(days=step), end)
        labels.append(cursor.strftime("%d %b"))
        new_series.append(count(models.Finding.first_discovered >= cursor,
                                models.Finding.first_discovered < stop))
        fixed_series.append(count(models.Finding.closed_at.isnot(None),
                                  models.Finding.closed_at >= cursor,
                                  models.Finding.closed_at < stop))
        back_series.append(count(models.Finding.reappeared_at.isnot(None),
                                 models.Finding.reappeared_at >= cursor,
                                 models.Finding.reappeared_at < stop))
        cursor = stop

    def listing(*conditions, order):
        rows = (db.query(models.Finding).options(joinedload(models.Finding.asset))
                .filter(*FC, *conditions).order_by(order).limit(50).all())
        return [{"id": f.id, "finding_code": f.finding_code, "plugin_name": f.plugin_name,
                 "severity": f.severity, "ip_address": f.ip_address,
                 "asset": f.asset.name if f.asset else "Unmapped",
                 "date": _iso(f.closed_at or f.reappeared_at or f.first_discovered)}
                for f in rows]

    return {
        "window": {"from": start.strftime("%Y-%m-%d"), "to": end.strftime("%Y-%m-%d"),
                   "days": span},
        "totals": {"discovered": discovered, "fixed": fixed, "reappeared": reappeared,
                   "still_open": still_open, "breached": breached,
                   "net": discovered + reappeared - fixed},
        "series": {"labels": labels, "discovered": new_series,
                   "fixed": fixed_series, "reappeared": back_series},
        "fixed_list": listing(models.Finding.closed_at.isnot(None),
                              models.Finding.closed_at >= start,
                              models.Finding.closed_at <= end,
                              order=models.Finding.closed_at.desc()),
        "reappeared_list": listing(models.Finding.reappeared_at.isnot(None),
                                   models.Finding.reappeared_at >= start,
                                   models.Finding.reappeared_at <= end,
                                   order=models.Finding.reappeared_at.desc()),
        "view": view.to_dict(),
    }


@app.get("/api/reports/export")
def api_export_findings(request: Request, db: Session = Depends(get_db)):
    user = _require_user(request, db, "reports")
    view = view_for(request, user, db)
    import csv
    import io as _io
    # The export is the view, written out. A person who cannot see a row on
    # the screen cannot obtain it by pressing Export either.
    findings = view.findings(
        db.query(models.Finding).options(joinedload(models.Finding.asset))
    ).order_by(models.Finding.id.desc()).all()
    buf = _io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Finding Code", "Source", "Compliance Result", "Plugin Name", "Severity",
        "IP Address", "Protocol", "Port", "CVE", "VPR", "Status", "SLA Status",
        "First Discovered", "Last Observed", "Due Date", "Age Days", "Reappeared",
        "Asset", "Asset Scope", "Coverage", "Owner", "Risk ID", "Exception ID",
        "Retest", "Closed At", "Closure",
    ])
    now = datetime.utcnow()
    for f in findings:
        writer.writerow([
            f.finding_code, f.source, f.compliance_result or "", f.plugin_name,
            f.severity, f.ip_address, f.protocol, f.port, f.cve, f.vpr_score,
            f.status, f.sla_status, _iso(f.first_discovered), _iso(f.last_observed),
            _iso(f.due_date), f.age_days(now), f.is_reappeared,
            f.asset.name if f.asset else "", f.asset.scope if f.asset else "",
            f.asset.coverage_state if f.asset else "",
            f.owner, f.risk_id, f.exception_id,
            f.retest_status, _iso(f.closed_at), f.closure_label(),
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
    users = db.query(models.User).order_by(models.User.username).all()
    return {
        "users": [u.to_dict() for u in users],
        "modules": [{"key": key, "label": label} for key, label in models.MODULES],
        "levels": list(models.ACCESS_LEVELS),
        "scopes": available_scopes(db),
        "sources": list(models.SOURCES),
        "unscoped_label": models.UNSCOPED_LABEL,
        "me": user.username,
    }


def _apply_reach(db, target: models.User, body: dict):
    """Store the scope and assessment grants submitted by the administrator.

    An administrator has no stored grant at all - the role is the answer - so
    writing one would be a lie waiting to be read back. Everybody else gets
    exactly what was ticked, validated against the scopes the inventory
    really contains, so a typo cannot quietly grant nothing.
    """
    if target.role == models.ROLE_ADMIN:
        return
    known = set(available_scopes(db))
    if "scopes" in body:
        wanted = [str(v).strip() for v in (body.get("scopes") or []) if str(v).strip()]
        unknown = [v for v in wanted if v not in known]
        if unknown:
            raise HTTPException(400, f"Unknown scope: {', '.join(unknown)}")
        target.scope_access = ",".join(sorted(set(wanted)))
    if "sources" in body:
        wanted = {str(v).strip().upper() for v in (body.get("sources") or []) if str(v).strip()}
        unknown = wanted - {s.upper() for s in models.SOURCES}
        if unknown:
            raise HTTPException(400, f"Unknown assessment type: {', '.join(sorted(unknown))}")
        target.assessment_access = ",".join(s for s in models.SOURCES if s.upper() in wanted)
    if "unscoped" in body:
        target.unscoped_access = bool(body.get("unscoped"))


def _apply_permissions(db, target: models.User, access: dict):
    """Replace a user's per-page access with what the admin submitted."""
    if target.role == models.ROLE_ADMIN:
        return
    wanted = {}
    for key in models.MODULE_KEYS:
        level = (access or {}).get(key, models.ACCESS_NONE)
        if level not in models.ACCESS_LEVELS:
            raise HTTPException(400, f"Invalid access level for {key}: {level}")
        wanted[key] = level

    current = {p.module: p for p in target.permissions}
    for key, level in wanted.items():
        if key in current:
            current[key].level = level
        else:
            db.add(models.UserPermission(user_id=target.id, module=key, level=level))
    for module, permission in current.items():
        if module not in wanted:
            db.delete(permission)


@app.post("/api/users")
def api_create_user(body: dict, user=Depends(require_admin),
                    db: Session = Depends(get_db)):
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role = body.get("role") or models.ROLE_CUSTOM
    if not username or len(password) < 4:
        raise HTTPException(400, "Username required and password min 4 characters")
    if role not in (models.ROLE_ADMIN, models.ROLE_CUSTOM):
        raise HTTPException(400, "Invalid role")
    if db.query(models.User).filter(func.lower(models.User.username) == username.lower()).first():
        raise HTTPException(400, "Username already exists")

    target = models.User(
        username=username,
        full_name=(body.get("full_name") or "").strip() or None,
        password_hash=hash_password(password),
        role=role,
        is_active=True,
    )
    db.add(target)
    db.flush()
    _apply_permissions(db, target, body.get("access"))
    # A new account reaches everything unless the caller says otherwise.
    # Restricting is a deliberate act; an account that silently reaches nothing
    # looks like a broken platform rather than a locked-down one, and a caller
    # that never heard of data reach - a script, an older client - must not
    # create accounts that see an empty screen.
    body.setdefault("scopes", available_scopes(db))
    body.setdefault("sources", list(models.SOURCES))
    body.setdefault("unscoped", True)
    _apply_reach(db, target, body)
    db.add(models.PolicyChangeLog(
        action=f"Created user '{username}' ({'administrator' if role == models.ROLE_ADMIN else 'custom access'})",
        user=user.username))
    db.commit()
    db.refresh(target)
    return {"ok": True, "user": target.to_dict()}


@app.put("/api/users/{user_id}")
def api_update_user(user_id: int, body: dict, user=Depends(require_admin),
                    db: Session = Depends(get_db)):
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")

    if "full_name" in body:
        target.full_name = (body.get("full_name") or "").strip() or None

    if "role" in body and body["role"] in (models.ROLE_ADMIN, models.ROLE_CUSTOM):
        # The platform must never end up with no administrator.
        if (target.role == models.ROLE_ADMIN and body["role"] != models.ROLE_ADMIN
                and _admin_count(db) <= 1):
            raise HTTPException(400, "This is the only administrator left")
        target.role = body["role"]

    if "is_active" in body:
        if not body["is_active"] and target.role == models.ROLE_ADMIN and _admin_count(db) <= 1:
            raise HTTPException(400, "This is the only administrator left")
        target.is_active = bool(body["is_active"])

    if body.get("password"):
        if len(body["password"]) < 4:
            raise HTTPException(400, "Password must be at least 4 characters")
        target.password_hash = hash_password(body["password"])

    if "access" in body:
        _apply_permissions(db, target, body["access"])
    _apply_reach(db, target, body)

    db.add(models.PolicyChangeLog(
        action=f"Updated access for user '{target.username}'", user=user.username))
    db.commit()
    db.refresh(target)
    return {"ok": True, "user": target.to_dict()}


@app.delete("/api/users/{user_id}")
def api_delete_user(user_id: int, user=Depends(require_admin),
                    db: Session = Depends(get_db)):
    target = db.query(models.User).filter(models.User.id == user_id).first()
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == user.id:
        raise HTTPException(400, "You cannot delete the account you are signed in with")
    if target.role == models.ROLE_ADMIN and _admin_count(db) <= 1:
        raise HTTPException(400, "This is the only administrator left")
    username = target.username
    db.delete(target)
    db.add(models.PolicyChangeLog(action=f"Deleted user '{username}'", user=user.username))
    db.commit()
    return {"ok": True}


def _admin_count(db) -> int:
    return db.query(models.User).filter(
        models.User.role == models.ROLE_ADMIN,
        models.User.is_active.is_(True)).count()


@app.post("/api/view")
def api_set_view(body: dict, request: Request, response: JSONResponse = None,
                 user=Depends(get_current_user), db: Session = Depends(get_db)):
    """Store the header selection.

    It lives in a cookie rather than in the URL so that every page, every
    chart and every export is narrowed by the same value without each one
    having to remember to pass it along. The value is validated here and
    intersected with the account's grant on every read, so a hand-edited
    cookie cannot widen anything.
    """
    scopes = available_scopes(db)
    view = scoping.ViewFilter(user,
                              scope_choice=str(body.get("scope") or ""),
                              source_choice=str(body.get("source") or ""),
                              available_scopes=scopes)
    payload = JSONResponse({"ok": True, "view": view.to_dict()})
    for name, value in ((scoping.SCOPE_COOKIE, view.scope),
                        (scoping.SOURCE_COOKIE, view.source)):
        if value:
            payload.set_cookie(name, value, path="/", max_age=60 * 60 * 24 * 365,
                               samesite="lax")
        else:
            payload.delete_cookie(name, path="/")
    return payload


@app.get("/api/view")
def api_get_view(request: Request, user=Depends(get_current_user),
                 db: Session = Depends(get_db)):
    return view_for(request, user, db).to_dict()


@app.get("/api/me")
def api_me(user=Depends(require_read)):
    return {"user": user.to_dict()}


@app.post("/api/me/password")
def api_change_own_password(body: dict, user=Depends(require_read),
                            db: Session = Depends(get_db)):
    """Any account changes its own password.

    The current password is required, so a machine left unlocked cannot be
    used to take the account over. An administrator resetting somebody else's
    password is a different action, in Settings -> Users.
    """
    current = body.get("current_password") or ""
    new = body.get("new_password") or ""
    confirm = body.get("confirm_password") or ""

    if not verify_password(current, user.password_hash):
        raise HTTPException(400, "The current password is not correct")
    if len(new) < 4:
        raise HTTPException(400, "The new password must be at least 4 characters")
    if new != confirm:
        raise HTTPException(400, "The two new passwords do not match")
    if verify_password(new, user.password_hash):
        raise HTTPException(400, "The new password is the same as the current one")

    target = db.query(models.User).filter(models.User.id == user.id).first()
    target.password_hash = hash_password(new)
    db.add(models.PolicyChangeLog(
        action=f"'{target.username}' changed their own password", user=target.username))
    db.commit()
    return {"ok": True}


# What must be typed to confirm each depth of reset. The same words are shown
# in the interface; the server is what enforces them.
RESET_CONFIRMATION = {
    "findings": "CLEAR FINDINGS",
    "assets": "CLEAR ALL DATA",
    "all": "RESET EVERYTHING",
}


@app.post("/api/admin/reset-data")
def api_reset_data(body: dict, user=Depends(require_admin),
                   db: Session = Depends(get_db)):
    """Empty the platform so it can be exercised again from nothing.

    Three depths, because "start over" means different things:

      findings  - the assessment history only. The inventory, the policy and
                  the accounts stay, so the next upload lands on known assets.
      assets    - the above plus the asset register.
      all       - a factory reset: everything above, plus the SLA policy and
                  the change log, then the default policy is seeded again.
                  Accounts are never deleted - that would lock you out.

    The inventory on disk is reloaded afterwards, so the platform comes back
    in exactly the state a fresh install would be in.
    """
    scope = (body.get("scope") or "findings").lower()
    if scope not in ("findings", "assets", "all"):
        raise HTTPException(400, "scope must be findings, assets or all")

    # The typed confirmation was checked in the browser and nowhere else, so
    # the API would empty the platform for anyone who could reach it - a
    # mistyped curl, a stale tab replaying a request, a script. It is checked
    # here now, where it cannot be skipped.
    expected = RESET_CONFIRMATION[scope]
    supplied = str(body.get("confirm") or "").strip()
    if supplied.upper() != expected.upper():
        raise HTTPException(
            400, f'Type "{expected}" to confirm this reset')

    removed = {
        "exceptions": db.query(models.ExceptionRecord).delete(synchronize_session=False),
        "findings": db.query(models.Finding).delete(synchronize_session=False),
        "assessments": db.query(models.AuditFile).delete(synchronize_session=False),
        "assets": 0,
        "sla_rules": 0,
        "policy_log": 0,
    }

    if scope in ("assets", "all"):
        removed["assets"] = db.query(models.Asset).delete(synchronize_session=False)

    if scope == "all":
        removed["sla_rules"] = db.query(models.SLARule).delete(synchronize_session=False)
        removed["policy_log"] = db.query(models.PolicyChangeLog).delete(synchronize_session=False)

    db.commit()

    reseeded = {}
    if scope == "all":
        reseeded = seed_if_empty(db)

    reloaded = {}
    if scope in ("assets", "all"):
        reloaded = load_asset_inventory(db, BASE_DIR.parent)

    recalculate_all(db)
    db.add(models.PolicyChangeLog(
        action=(f"Platform reset ({scope}): {removed['findings']} findings, "
                f"{removed['exceptions']} exceptions, {removed['assessments']} assessments, "
                f"{removed['assets']} assets removed"),
        user=user.username))
    db.commit()

    return {
        "ok": True,
        "scope": scope,
        "removed": removed,
        "reseeded": reseeded,
        "inventory_reloaded": reloaded.get("created", 0),
    }


@app.get("/api/search")
def api_search(request: Request, q: str = "", db: Session = Depends(get_db)):
    user = _require_user(request, db)
    view = view_for(request, user, db)
    q = q.strip()
    if not q:
        return {"findings": [], "assets": []}
    like = f"%{q}%"
    # Search obeys the view as well. It would be the easiest way around a
    # scope restriction otherwise - type an IP and read the answer.
    findings = view.findings(db.query(models.Finding)).filter(
        models.Finding.id.isnot(None) if user.can_read("findings")
        else models.Finding.id.is_(None),
        or_(
            models.Finding.finding_code.ilike(like),
            models.Finding.plugin_name.ilike(like),
            models.Finding.ip_address.ilike(like),
            models.Finding.cve.ilike(like),
        )).limit(8).all()
    assets = view.assets(db.query(models.Asset)).filter(
        models.Asset.id.isnot(None) if user.can_read("assets")
        else models.Asset.id.is_(None),
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

def _require_user(request: Request, db: Session, module=None) -> models.User:
    """Resolve the caller and check they may read the page this data belongs to.

    `module` may be a tuple, because a few aggregates genuinely belong to more
    than one page - the retest doughnut is drawn on the dashboard and on
    Retest & Validation, and the KPI strip on the dashboard and on Reports.
    Requiring the dashboard for all of them locked accounts out of pages they
    were explicitly granted.
    """
    user = ui_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    if module:
        wanted = (module,) if isinstance(module, str) else tuple(module)
        if not any(user.can_read(key) for key in wanted):
            names = " or ".join(key.replace("_", " ") for key in wanted)
            raise HTTPException(status_code=403, detail=f"No access to {names}")
    return user

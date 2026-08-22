"""Startup tasks for the Assurance Platform.

This module handles application initialization tasks including loading
the Asset Inventory from Excel file on disk.
"""
import os
import re
from pathlib import Path

from sqlalchemy.orm import Session

from . import models, parsers
from .database import Base


def ensure_schema(engine) -> list[str]:
    """Add columns that were introduced after the first release.

    The platform ships as a single SQLite file that users keep between
    versions. create_all() only creates missing *tables*, so a new column on
    an existing table would raise "no such column" on the next query. Every
    added column is nullable or has a Python-side default, so an in-place
    ALTER TABLE is enough - no data is touched.
    """
    added = []
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            present = {r[1] for r in conn.exec_driver_sql(
                f"PRAGMA table_info({table.name})")}
            if not present:          # table does not exist yet - create_all made it
                continue
            for column in table.columns:
                if column.name in present:
                    continue
                ddl = column.type.compile(engine.dialect)
                conn.exec_driver_sql(
                    f"ALTER TABLE {table.name} ADD COLUMN {column.name} {ddl}")
                added.append(f"{table.name}.{column.name}")
    if added:
        print(f"[schema] added {len(added)} column(s): {', '.join(added)}")
    backfill_defaults(engine)
    return added


def backfill_defaults(engine) -> None:
    """Give the new columns a value on rows that predate them.

    ALTER TABLE ADD COLUMN leaves existing rows NULL, and the defaults on the
    model are applied by Python at insert time only. An account created before
    the data-reach columns existed would therefore read as "reaches no
    assessment type and not even the unscoped bucket" - locked out of data it
    was never meant to lose. The safe reading of NULL here is the default the
    column was given, so it is written once.
    """
    statements = (
        "UPDATE users SET unscoped_access = 1 WHERE unscoped_access IS NULL",
        "UPDATE users SET assessment_access = 'VA,CIS' WHERE assessment_access IS NULL",
        "UPDATE users SET scope_access = '' WHERE scope_access IS NULL",
    )
    with engine.begin() as conn:
        present = {r[1] for r in conn.exec_driver_sql("PRAGMA table_info(users)")}
        if not {"unscoped_access", "assessment_access", "scope_access"} <= present:
            return
        for sql in statements:
            conn.exec_driver_sql(sql)


class AssetCodeAllocator:
    """Hands out unique AST-#### codes for a whole import in one pass.

    The session is created with autoflush=False, so assets queued with
    db.add() stay invisible to a follow-up query until the next flush.
    Asking the database for "the next code" once per row therefore returned
    the same value over and over and every inventory import died with
    UNIQUE constraint failed: assets.asset_code. The allocator reads the
    existing codes once and then tracks what it has handed out in memory.
    """

    def __init__(self, db):
        self._used = set()
        self._max = 0
        for (code,) in db.query(models.Asset.asset_code).all():
            if not code:
                continue
            self._used.add(code)
            m = re.search(r"AST-(\d+)", code)
            if m:
                self._max = max(self._max, int(m.group(1)))

    def next(self):
        while True:
            self._max += 1
            code = f"AST-{self._max:04d}"
            if code not in self._used:
                self._used.add(code)
                return code

    def take(self, code):
        """Keep the code supplied by the inventory file when it is still free."""
        code = (code or "").strip()
        if code and code not in self._used:
            self._used.add(code)
            return code
        return self.next()


def relink_unmapped_findings(db: Session) -> int:
    """Attach findings parked on the Default Asset to a real asset.

    Assessments regularly arrive before the inventory is updated. Those
    findings are kept on AST-0000 so nothing is lost; as soon as the
    inventory learns the IP they must move to the real asset, otherwise they
    would keep the Default Asset SLA forever.
    """
    default_asset = (
        db.query(models.Asset).filter(models.Asset.asset_code == "AST-0000").first()
    )
    if not default_asset:
        return 0

    parked = (
        db.query(models.Finding)
        .filter(models.Finding.asset_id == default_asset.id)
        .all()
    )
    if not parked:
        return 0

    real_assets = (db.query(models.Asset)
                   .filter(models.Asset.asset_code != "AST-0000").all())

    by_ip = {(a.ip_address or "").lower(): a for a in real_assets if a.ip_address}
    # An application finding has no IP to match on. SAST names an application,
    # DAST and PT name a host, so both need their own way home - otherwise
    # they sit on the Default Asset for ever even after the inventory learns
    # about them.
    by_domain = {}
    by_name = {}
    for asset in real_assets:
        for value in str(asset.domain or "").split(","):
            key = value.strip().lower().strip(".")
            if key:
                by_domain.setdefault(key, asset)
        for candidate in (asset.name, asset.asset_code):
            key = " ".join(str(candidate or "").split()).lower()
            if key:
                by_name.setdefault(key, asset)

    moved = 0
    for finding in parked:
        asset = by_ip.get((finding.ip_address or "").lower())
        if asset is None and finding.source in models.BINDS_BY_DOMAIN:
            asset = by_domain.get((finding.ip_address or "").strip().lower())
        if asset is None and finding.application_name:
            asset = by_name.get(" ".join(str(finding.application_name).split()).lower())
        if asset:
            finding.asset_id = asset.id
            # A DAST or PT finding was carrying the host name in place of an
            # address until the inventory explained it; now it can hold the
            # real one.
            if finding.source in models.BINDS_BY_DOMAIN and asset.ip_address:
                finding.ip_address = asset.ip_address
            moved += 1
    if moved:
        db.flush()
    return moved


def load_asset_inventory(db: Session, workspace_root: Path) -> dict:
    """Load Asset_Inventory.xlsx from workspace root and populate Asset table.
    
    This runs on application startup to ensure the asset database is always
    synchronized with the master inventory file.
    
    Returns:
        dict: Statistics about the load operation (created, updated, skipped)
    """
    inventory_path = workspace_root / "Asset_Inventory.xlsx"
    
    if not inventory_path.exists():
        print(f"⚠️  Asset inventory not found at {inventory_path}")
        return {"created": 0, "updated": 0, "skipped": 0, "error": "File not found"}
    
    try:
        with open(inventory_path, "rb") as f:
            content = f.read()
        
        rows = parsers.parse_asset_inventory(inventory_path.name, content)
        
        created = updated = skipped = 0
        allocator = AssetCodeAllocator(db)
        # Assets queued with db.add() are invisible to a query until the
        # flush, so rows created earlier in this loop are tracked by hand.
        pending: dict[str, models.Asset] = {}

        for row in rows:
            ip = row.get("ip_address", "").strip()
            if not ip:
                skipped += 1
                continue
            
            # Check if asset exists by IP address
            existing = pending.get(ip) or db.query(models.Asset).filter(
                models.Asset.ip_address == ip
            ).first()
            
            fields = {
                "name": row.get("name") or ip,
                "type": row.get("type") or "Server",
                "scope": row.get("scope") or "Infrastructure",
                "environment": row.get("environment") or "Production",
                "site": row.get("site") or "HQ",
                "owner_team": row.get("owner_team") or "Server Team",
                "status": row.get("status") or "Active",
            }
            
            if existing:
                # Update existing asset
                for key, value in fields.items():
                    setattr(existing, key, value)
                updated += 1
            else:
                # Create new asset. The allocator guarantees the code is free,
                # so an inventory row is never silently skipped any more.
                asset = models.Asset(
                    asset_code=allocator.take(row.get("asset_code")),
                    ip_address=ip,
                    **fields
                )
                db.add(asset)
                pending[ip] = asset
                created += 1
        
        db.flush()
        relinked = relink_unmapped_findings(db)
        db.commit()
        
        print(f"✅ Asset inventory loaded: {created} created, {updated} updated, "
              f"{skipped} skipped, {relinked} finding(s) relinked")
        
        return {
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "relinked": relinked,
            "total_rows": len(rows)
        }
        
    except Exception as e:
        print(f"❌ Failed to load asset inventory: {e}")
        db.rollback()
        return {"created": 0, "updated": 0, "skipped": 0, "error": str(e)}

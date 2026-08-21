"""Startup tasks for the Assurance Platform.

This module handles application initialization tasks including loading
the Asset Inventory from Excel file on disk.
"""
import os
from pathlib import Path

from sqlalchemy.orm import Session

from . import models, parsers


def load_asset_inventory(db: Session, workspace_root: Path) -> dict:
    """Load Asset_Inventory.xlsx from workspace root and populate Asset table.
    
    This runs on application startup to ensure the asset database is always
    synchronized with the master inventory file.
    
    Returns:
        dict: Statistics about the load operation (created, updated, skipped)
    """
    inventory_path = workspace_root / "Asset_Inventory.xlsx"
    
    if not inventory_path.exists():
        print(f"Asset inventory not found at {inventory_path}")
        return {"created": 0, "updated": 0, "skipped": 0, "error": "File not found"}
    
    try:
        with open(inventory_path, "rb") as f:
            content = f.read()
        
        rows = parsers.parse_asset_inventory(inventory_path.name, content)
        
        created = updated = skipped = 0
        
        for row in rows:
            ip = row.get("ip_address", "").strip()
            if not ip:
                skipped += 1
                continue
            
            # Check if asset exists by IP address
            existing = db.query(models.Asset).filter(
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
                # Create new asset
                # Get asset code from row or auto-generate
                asset_code = row.get("asset_code") or None
                
                if asset_code:
                    # Check if this asset_code is already taken by a different IP
                    code_exists = db.query(models.Asset).filter(
                        models.Asset.asset_code == asset_code,
                        models.Asset.ip_address != ip
                    ).first()
                    
                    if code_exists:
                        # Asset code taken by different IP, auto-generate new code
                        asset_code = None
                
                if not asset_code:
                    # Auto-generate asset code
                    max_code = db.query(models.Asset.asset_code).all()
                    max_num = 0
                    for (code,) in max_code:
                        if code and code.startswith("AST-"):
                            try:
                                num = int(code.split("-")[1])
                                max_num = max(max_num, num)
                            except (ValueError, IndexError):
                                pass
                    asset_code = f"AST-{max_num + 1:04d}"
                
                asset = models.Asset(
                    asset_code=asset_code,
                    ip_address=ip,
                    **fields
                )
                db.add(asset)
                db.flush()  # Flush to catch any constraint errors early
                created += 1
        
        db.commit()
        
        print(f"Asset inventory loaded: {created} created, {updated} updated, {skipped} skipped")
        
        return {
            "created": created,
            "updated": updated,
            "skipped": skipped,
            "total_rows": len(rows)
        }
        
    except Exception as e:
        print(f"Failed to load asset inventory: {e}")
        db.rollback()
        return {"created": 0, "updated": 0, "skipped": 0, "error": str(e)}

"""Load Asset Inventory from Excel file into database"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.database import SessionLocal
from app.startup import load_asset_inventory

def main():
    db = SessionLocal()
    workspace_root = Path(__file__).parent
    
    try:
        print("Loading Asset Inventory...")
        result = load_asset_inventory(db, workspace_root)
        
        print(f"\n[+] Asset Loading Complete!")
        print(f"   Created: {result.get('created', 0)}")
        print(f"   Updated: {result.get('updated', 0)}")
        print(f"   Skipped: {result.get('skipped', 0)}")
        print(f"   Total Rows: {result.get('total_rows', 0)}")
        
        if result.get('error'):
            print(f"   Error: {result['error']}")
            return 1
        
        return 0
        
    finally:
        db.close()

if __name__ == "__main__":
    sys.exit(main())

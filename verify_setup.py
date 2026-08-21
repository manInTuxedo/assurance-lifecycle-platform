"""Quick verification script - checks assets and theme toggle"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from app.database import SessionLocal
from app.models import Asset

def main():
    print("="*60)
    print("SETUP VERIFICATION")
    print("="*60)
    
    db = SessionLocal()
    try:
        # Check assets
        assets = db.query(Asset).filter(Asset.asset_code != "AST-0000").all()
        print(f"\n[1] Assets Loaded: {len(assets)}")
        if len(assets) > 0:
            print(f"    First: {assets[0].asset_code} - {assets[0].name}")
            print(f"    Last:  {assets[-1].asset_code} - {assets[-1].name}")
            print("    Status: OK")
        else:
            print("    Status: FAILED - No assets loaded")
            print("    Run: python load_assets.py")
            return 1
        
        # Check theme toggle in base template
        print(f"\n[2] Theme Toggle Check")
        base_html = Path(__file__).parent / "app" / "templates" / "base.html"
        content = base_html.read_text(encoding='utf-8')
        
        checks = {
            "Theme init script": "Theme initialization - MUST run before",
            "localStorage.getItem": "localStorage.getItem('assurance-theme')",
            "Theme toggle button": 'id="themeToggle"',
            "Sun icon": 'id="iconSun"',
            "Moon icon": 'id="iconMoon"',
            "Toggle handler": "classList.toggle('dark')",
        }
        
        all_ok = True
        for name, check in checks.items():
            if check in content:
                print(f"    {name}: OK")
            else:
                print(f"    {name}: FAILED")
                all_ok = False
        
        if not all_ok:
            return 1
        
        # Check login page theme
        print(f"\n[3] Login Page Theme Check")
        login_html = Path(__file__).parent / "app" / "templates" / "login.html"
        login_content = login_html.read_text(encoding='utf-8')
        
        if "Theme initialization" in login_content:
            print("    Login theme init: OK")
        else:
            print("    Login theme init: FAILED")
            return 1
        
        print("\n" + "="*60)
        print("ALL CHECKS PASSED")
        print("="*60)
        print("\nServer Status:")
        print("  URL: http://localhost:8000")
        print("  Username: Assurance Head")
        print("  Password: admin")
        print("\nActions to verify:")
        print("  1. Open browser to http://localhost:8000")
        print("  2. Login with credentials above")
        print("  3. Navigate to Assets page - should see 1,208 assets")
        print("  4. Click sun/moon icon in header - theme should toggle")
        print("  5. Refresh page - theme should persist")
        print("\nReady to upload VA and CIS scans!")
        
        return 0
        
    finally:
        db.close()

if __name__ == "__main__":
    sys.exit(main())

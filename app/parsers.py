"""Excel / CSV parsers tuned for the VA_C1_2026-03-16_R1_*.xlsx scan format.

Supports:
  * VA Scan exports (.xlsx / .csv) with the classic columns:
      Plugin Name, Severity, IP Address, Protocol, Port, CVE,
      First Discovered, Last Observed, Description, Steps to Remediate,
      Plugin Output, Vulnerability Priority Rating.
  * Asset Inventory uploads (.xlsx / .csv).
"""
import io
import re
from datetime import datetime, timedelta, timezone

import pandas as pd
from dateutil import parser as dateutil_parser

# ---------------------------------------------------------------------------
# Column normalization helpers
# ---------------------------------------------------------------------------

VA_COLUMN_MAP = {
    "pluginname": "plugin_name",
    "plugin_name": "plugin_name",
    "severity": "severity",
    "ipaddress": "ip_address",
    "ip": "ip_address",
    "hostip": "ip_address",
    "protocol": "protocol",
    "port": "port",
    "cve": "cve",
    "cveid": "cve",
    "firstdiscovered": "first_discovered",
    "first_detected": "first_discovered",
    "lastobserved": "last_observed",
    "last_seen": "last_observed",
    "description": "description",
    "synopsis": "description",
    "stepstoremediate": "remediation_steps",
    "solution": "remediation_steps",
    "remediation": "remediation_steps",
    "pluginoutput": "plugin_output",
    "output": "plugin_output",
    "vulnerabilitypriorityrating": "vpr_score",
    "vpr": "vpr_score",
    "vprscore": "vpr_score",
    # Optional asset columns embedded in the scan export -------------------
    "assetname": "asset_name",
    "hostname": "asset_name",
    "dnsname": "asset_name",
    "assetcode": "asset_code",
    "assettype": "asset_type",
    "type": "asset_type",
    "scope": "asset_scope",
    "environment": "asset_environment",
    "env": "asset_environment",
    "site": "asset_site",
    "ownerteam": "asset_owner_team",
    "team": "asset_owner_team",
    "assetstatus": "asset_status",
}

ASSET_FIELDS = (
    "asset_code", "asset_name", "asset_type", "asset_scope",
    "asset_environment", "asset_site", "asset_owner_team", "asset_status",
)

ASSET_COLUMN_MAP = {
    "assetcode": "asset_code",
    "code": "asset_code",
    "name": "name",
    "assetname": "name",
    "hostname": "name",
    "applicationname": "name",
    "ipaddress": "ip_address",
    "ip": "ip_address",
    "serverip": "ip_address",
    "type": "type",
    "assettype": "type",
    "ostype": "type",
    "scope": "scope",
    "pcinpci": "scope",
    "crownjewelcjnotcj": "importance",
    "crownjewel": "importance",
    "environment": "environment",
    "site": "site",
    "location": "site",
    "ownerteam": "owner_team",
    "team": "owner_team",
    "applicationowner": "owner_team",
    "status": "status",
    "osversion": "os_version",
}


def _norm_header(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(name).lower()).strip()


def _normalize_columns(df: pd.DataFrame, mapping: dict) -> pd.DataFrame:
    """Map actual sheet headers (case/whitespace insensitive) onto canonical keys."""
    lookup = {_norm_header(k): v for k, v in mapping.items()}
    renamed = {}
    for col in df.columns:
        key = _norm_header(col)
        if key in lookup:
            renamed[col] = lookup[key]
    return df.rename(columns=renamed)


def _excel_serial_to_date(serial) -> datetime | None:
    """Excel serial date (days since 1899-12-30)."""
    try:
        serial = float(serial)
    except (TypeError, ValueError):
        return None
    if pd.isna(serial) or serial < 1:
        return None
    return datetime(1899, 12, 30) + timedelta(days=serial)


def _to_naive_utc(dt: datetime) -> datetime:
    """Normalize to naive UTC so naive/aware comparisons never crash."""
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def parse_date(value) -> datetime | None:
    """Tolerant date parsing: Timestamps, excel serials, strings.

    Always returns a NAIVE datetime (UTC-normalized) so SQLAlchemy storage
    and the SLA engine (which uses ``datetime.utcnow()``) never mix
    offset-aware and offset-naive values.
    """
    if value is None:
        return None
    if isinstance(value, pd.Timestamp):
        return _to_naive_utc(value.to_pydatetime())
    if isinstance(value, datetime):
        return _to_naive_utc(value)
    if hasattr(value, "isoformat"):  # datetime.date
        return datetime(value.year, value.month, value.day)
    if isinstance(value, (int, float)):
        return _excel_serial_to_date(value)
    s = str(value).strip()
    if not s or s.lower() in ("nan", "none", "nat", "n/a"):
        return None
    try:
        return _to_naive_utc(dateutil_parser.parse(s))
    except (ValueError, OverflowError):
        return None


def parse_port(value) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, float) and pd.isna(value):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    m = re.search(r"(\d+)", str(value))
    return int(m.group(1)) if m else 0


def parse_vpr(value) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    m = re.search(r"(\d+(?:\.\d+)?)", str(value))
    return float(m.group(1)) if m else None


def scan_date_from_filename(filename: str) -> datetime | None:
    """Extract scan date from names like VA_C1_2026-03-16_R1_...."""
    m = re.search(r"(\d{4})[-_](\d{1,2})[-_](\d{1,2})", filename)
    if m:
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None
    return None


def detect_source_type(filename: str) -> str:
    upper = filename.upper()
    if "CIS" in upper:
        return "CIS"
    if "VA" in upper:
        return "VA"
    return "VA"


def detect_report_type_from_content(rows: list[dict]) -> str:
    """Detect report type by analyzing plugin names.
    
    CIS reports have plugin names starting with numerical standards like:
    - 1.1.2 Ensure ...
    - 2.3.4 Configure ...
    
    VA reports have descriptive plugin names like:
    - OpenSSH < 9.6 Multiple Vulnerabilities
    - Apache HTTP Server ...
    """
    if not rows:
        return "VA"
    
    # Sample first 10 rows to determine type
    sample_size = min(10, len(rows))
    cis_pattern_count = 0
    
    for i in range(sample_size):
        plugin_name = rows[i].get("plugin_name", "").strip()
        # Check if starts with pattern like "1.1", "2.3.4", etc.
        if re.match(r'^\d+\.\d+', plugin_name):
            cis_pattern_count += 1
    
    # If majority of sampled rows match CIS pattern, it's a CIS report
    if cis_pattern_count >= sample_size * 0.5:
        return "CIS"
    
    return "VA"


# ---------------------------------------------------------------------------
# File readers
# ---------------------------------------------------------------------------

def _read_frame(filename: str, content: bytes) -> pd.DataFrame:
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext == "csv":
        return pd.read_csv(io.BytesIO(content))
    return pd.read_excel(io.BytesIO(content), engine="openpyxl")


def parse_va_scan(filename: str, content: bytes) -> list[dict]:
    """Parse a VA scan export into normalized row dicts.

    Missing columns are tolerated; unknown extra columns are ignored.
    """
    df = _read_frame(filename, content)
    df = _normalize_columns(df, VA_COLUMN_MAP)

    rows = []
    for _, r in df.iterrows():
        row = {k: r[k] for k in ("plugin_name", "severity", "ip_address", "protocol", "port",
                                 "cve", "first_discovered", "last_observed", "description",
                                 "remediation_steps", "plugin_output", "vpr_score") if k in r.index}
        row["plugin_name"] = str(row.get("plugin_name") or "").strip() or "Unknown Plugin"
        row["severity"] = str(row.get("severity") or "Info").strip().capitalize()
        row["ip_address"] = str(row.get("ip_address") or "").strip()
        row["protocol"] = str(row.get("protocol") or "").strip()
        row["port"] = parse_port(row.get("port"))
        row["vpr_score"] = parse_vpr(row.get("vpr_score"))
        row["cve"] = str(row.get("cve") or "").strip()
        row["description"] = str(row.get("description") or "").strip()
        row["remediation_steps"] = str(row.get("remediation_steps") or "").strip()
        row["plugin_output"] = str(row.get("plugin_output") or "").strip()
        row["first_discovered"] = parse_date(row.get("first_discovered"))
        row["last_observed"] = parse_date(row.get("last_observed"))
        for field in ASSET_FIELDS:
            row[field] = str(r[field]).strip() if field in r.index and pd.notna(r.get(field)) else ""
        if not row["ip_address"]:
            continue
        rows.append(row)
    
    # Auto-detect report type from content
    detected_type = detect_report_type_from_content(rows)
    for row in rows:
        row["detected_source"] = detected_type
    
    return rows


def check_credentialed_scan(rows: list[dict]) -> dict[str, bool]:
    """Check which IPs have credentialed scans in a VA report.
    
    Returns a dict mapping IP addresses to whether they have credentialed scans.
    Only IPs with "Nessus Scan Information" plugin that contains 
    "credentialed checks : yes" in the plugin output should be processed.
    
    Args:
        rows: List of parsed scan rows
        
    Returns:
        dict: {ip_address: is_credentialed}
    """
    credentialed_ips = {}
    
    for row in rows:
        ip = row.get("ip_address", "").strip()
        plugin_name = row.get("plugin_name", "").strip().lower()
        plugin_output = row.get("plugin_output", "").strip().lower()
        
        if not ip:
            continue
        
        # Look for "Nessus Scan Information" plugin
        if "nessus scan information" in plugin_name:
            # Check if credentialed checks were successful
            # Pattern: "credentialed checks : yes" or "Credentialed checks : yes, as 'user' via SSH"
            if "credentialed checks" in plugin_output and ": yes" in plugin_output:
                credentialed_ips[ip] = True
            else:
                credentialed_ips[ip] = False
    
    return credentialed_ips


def parse_asset_inventory(filename: str, content: bytes) -> list[dict]:
    """Parse an asset inventory upload into normalized row dicts."""
    df = _read_frame(filename, content)
    df = _normalize_columns(df, ASSET_COLUMN_MAP)

    rows = []
    for _, r in df.iterrows():
        row = {}
        for k in ("asset_code", "name", "ip_address", "type", "scope", "environment",
                  "site", "owner_team", "status", "importance", "os_version"):
            row[k] = str(r[k]).strip() if k in r.index and pd.notna(r.get(k)) else ""
        if not row["ip_address"]:
            continue
        
        # Map PCI/NPCI to scope
        if row.get("scope"):
            pci_value = row["scope"].upper()
            if pci_value == "PCI":
                row["scope"] = "PCI"
            elif pci_value == "NPCI":
                row["scope"] = "Infrastructure"
        
        # Map Crown Jewel importance
        if row.get("importance"):
            importance = row["importance"].upper()
            if "CJ" in importance or "CROWN" in importance:
                row["scope"] = "Crown Jewel"
        
        # Default values
        if not row["scope"]:
            row["scope"] = "Infrastructure"
        if not row["environment"]:
            row["environment"] = "Production"
        if not row["status"]:
            row["status"] = "Active"
        if not row["type"] and row.get("os_version"):
            row["type"] = "Server"
            
        rows.append(row)
    return rows

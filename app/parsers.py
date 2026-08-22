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
    "owner": "owner_team",
    "team": "owner_team",
    "applicationowner": "owner_team",
    "status": "status",
    "osversion": "os_version",
    # DAST and PT name a URL, never an IP, so the inventory has to say which
    # host answers which name.
    "domain": "domain",
    "domainname": "domain",
    "hostheader": "domain",
    "fqdn": "domain",
    "url": "domain",
    "applicationurl": "domain",
    # Infrastructure Inventory sheet ---------------------------------------
    "nodename": "name",
    "devicetype": "type",
    "firmwaresoftwareversion": "os_version",
    "crownjewels": "importance",
}


def _norm_header(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", str(name).lower()).strip()


def _raw_text(value) -> str:
    """One sheet cell rendered as it should read on screen."""
    if value is None:
        return ""
    try:
        if pd.isna(value):
            return ""
    except (TypeError, ValueError):
        pass
    if isinstance(value, (datetime, pd.Timestamp)):
        return value.strftime("%Y-%m-%d %H:%M").replace(" 00:00", "")
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def raw_pairs(headers: list, series) -> list:
    """Every column of the original sheet row, in the sheet's own order.

    The platform keeps this untouched so a finding can always be shown
    exactly as the assessment reported it - including columns the data model
    has no field for.
    """
    pairs = []
    for index, header in enumerate(headers):
        try:
            value = series.iloc[index]
        except (IndexError, KeyError):
            value = None
        pairs.append([str(header).strip(), _raw_text(value)])
    return pairs


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
    # Headers are captured before the rename so the untouched sheet row can be
    # stored with the finding - nothing the file carries is thrown away.
    raw_headers = [str(c) for c in df.columns]
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
        row["raw"] = raw_pairs(raw_headers, r)
        row["source_file"] = filename
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


# ---------------------------------------------------------------------------
# Application security assessments - SAST, DAST and PT
# ---------------------------------------------------------------------------
# These three share a family of layouts that has nothing in common with a
# Tenable export: no IP, no port, no plugin. What they do carry is a Finding ID
# whose prefix names the assessment, so the type is read from the content of
# the file exactly as VA and CIS are - never from the file name, never from a
# dropdown the person has to get right.

APPSEC_COLUMN_MAP = {
    "findingid": "external_ref",
    "id": "external_ref",
    "applicationname": "application_name",
    "application": "application_name",
    "vulnerabilitytitle": "title",
    "findingtitle": "title",
    "title": "title",
    "cweid": "cwe_id",
    "cwe": "cwe_id",
    "owaspcategory": "owasp_category",
    "owasp": "owasp_category",
    "severity": "severity",
    "affectedfilecomponent": "affected_location",
    "affectedfile": "affected_location",
    "affectedcomponent": "affected_location",
    "affectedurlendpoint": "affected_location",
    "affectedurl": "affected_location",
    "endpoint": "affected_location",
    "url": "affected_location",
    "description": "description",
    "recommendation": "remediation_steps",
    "remediation": "remediation_steps",
    "scandate": "scan_date",
    "assessmentdate": "scan_date",
    "dateofscan": "scan_date",
    "testdate": "scan_date",
    # Optional. When the report knows when the issue was first raised it is
    # honoured; otherwise the first scan that reported it becomes its start.
    "firstdiscovered": "first_discovered",
    "firstdetected": "first_discovered",
    "dateraised": "first_discovered",
}

APPSEC_PREFIXES = {"SAST": "SAST", "DAST": "DAST", "PT": "PT", "BT": "PT"}


def appsec_type_from_reference(value) -> str | None:
    """SAST-00042 -> SAST. Anything else -> None."""
    text = str(value or "").strip().upper()
    m = re.match(r"^([A-Z]+)[-_ ]?\d+", text)
    if not m:
        return None
    return APPSEC_PREFIXES.get(m.group(1))


def detect_appsec_type(df: pd.DataFrame) -> str | None:
    """The assessment type of a sheet, decided by its Finding ID column.

    A handful of rows is enough, but a majority is required: one stray value
    in a column of a thousand must not decide what the whole file is.
    """
    column = None
    for col in df.columns:
        if _norm_header(col) in ("findingid", "id"):
            column = col
            break
    if column is None:
        return None
    votes: dict[str, int] = {}
    checked = 0
    for value in df[column].head(50):
        kind = appsec_type_from_reference(value)
        if kind:
            votes[kind] = votes.get(kind, 0) + 1
        checked += 1
    if not votes or not checked:
        return None
    best, count = max(votes.items(), key=lambda kv: kv[1])
    return best if count >= max(1, checked * 0.5) else None


def domain_from_url(value) -> str:
    """The host out of a URL, lowercased, without scheme, port or path.

    DAST and PT name a URL and never an IP. The host in it is the only thing
    that can be matched back to the inventory, so it is extracted here rather
    than in four places that would each get it slightly wrong.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    text = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", text)
    text = text.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    text = text.rsplit("@", 1)[-1]          # strip user:pass@
    if text.startswith("["):                # IPv6 literal
        text = text[1:].split("]", 1)[0]
    else:
        text = text.split(":", 1)[0]        # strip the port
    return text.lower().strip(".")


def parse_appsec_report(filename: str, content: bytes,
                        sheet_name=None) -> list[dict]:
    """Read one SAST, DAST or PT sheet into normalised rows.

    Returns an empty list when the sheet is not one of the three, so the
    caller can fall back to the VA/CIS reader without having to guess first.
    """
    frames = _read_all_sheets(filename, content) if sheet_name is None else \
        [(sheet_name, _read_sheet(filename, content, sheet_name))]

    rows: list[dict] = []
    for name, df in frames:
        if df is None or df.empty:
            continue
        kind = detect_appsec_type(df)
        if not kind:
            continue
        raw_headers = [str(c) for c in df.columns]
        mapped = _normalize_columns(df, APPSEC_COLUMN_MAP)
        sheet_date = scan_date_from_text(name) or scan_date_from_filename(filename)

        for _, r in mapped.iterrows():
            ref = str(r.get("external_ref") or "").strip() if "external_ref" in r.index else ""
            if appsec_type_from_reference(ref) != kind:
                # A row from another family inside the same sheet is not this
                # assessment's business; skipping keeps one bad row from
                # changing what the file is.
                continue
            application = str(r.get("application_name") or "").strip() if "application_name" in r.index else ""
            title = str(r.get("title") or "").strip() if "title" in r.index else ""
            if not application or not title:
                continue
            location = str(r.get("affected_location") or "").strip() if "affected_location" in r.index else ""
            scanned = parse_date(r.get("scan_date")) if "scan_date" in r.index else None
            scanned = scanned or sheet_date
            raised = parse_date(r.get("first_discovered")) if "first_discovered" in r.index else None

            row = {
                "detected_source": kind,
                "external_ref": ref,
                "application_name": application,
                "plugin_name": title,
                "severity": str(r.get("severity") or "Info").strip().capitalize()
                            if "severity" in r.index else "Info",
                "affected_location": location,
                "cwe_id": (str(r.get("cwe_id") or "").strip() if "cwe_id" in r.index else ""),
                "owasp_category": (str(r.get("owasp_category") or "").strip()
                                   if "owasp_category" in r.index else ""),
                "description": (str(r.get("description") or "").strip()
                                if "description" in r.index else ""),
                "remediation_steps": (str(r.get("remediation_steps") or "").strip()
                                      if "remediation_steps" in r.index else ""),
                "domain": domain_from_url(location) if kind in ("DAST", "PT") else "",
                "scan_date": scanned,
                "first_discovered": raised or scanned,
                "last_observed": scanned,
                "sheet_name": name,
                "source_file": filename,
                "raw": raw_pairs(raw_headers, r),
                # Kept empty so the shared ingest code can treat every source
                # the same way; the binding step fills the address in.
                "ip_address": "",
                "protocol": "",
                "port": 0,
                "cve": "",
                "plugin_output": "",
                "vpr_score": None,
            }
            rows.append(row)
    return rows


def scan_date_from_text(text) -> datetime | None:
    """A date inside a sheet name, e.g. "SAST 2026-05-10"."""
    if not text:
        return None
    return scan_date_from_filename(str(text))


def _read_sheet(filename: str, content: bytes, sheet_name):
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext == "csv":
        return pd.read_csv(io.BytesIO(content))
    return pd.read_excel(io.BytesIO(content), engine="openpyxl", sheet_name=sheet_name)


def _read_all_sheets(filename: str, content: bytes):
    """Every sheet in the workbook, in order, as (name, frame).

    A single workbook may hold one assessment per sheet, which is how these
    reports usually arrive, so all of them are read rather than only the first.
    """
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext == "csv":
        return [(filename, pd.read_csv(io.BytesIO(content)))]
    book = pd.read_excel(io.BytesIO(content), engine="openpyxl", sheet_name=None)
    return list(book.items())


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


def assessment_coverage(rows: list[dict], source: str = "VA") -> dict[str, bool]:
    """Per IP: can this assessment prove that a finding is gone?

    Tenable writes one "Nessus Scan Information" row per host it reached, and
    its Plugin Output states ``Credentialed checks : yes ...`` or ``no``.
    Only a credentialed pass is allowed to close anything - an uncredentialed
    pass simply could not look inside the host, and an IP that never appears
    in the file was not assessed at all.

    A compliance (CIS) export can only be produced by a credentialed audit,
    so any host present in one counts as assessed even when the scan
    information row was not exported.
    """
    coverage: dict[str, bool] = {}
    for row in rows:
        ip = str(row.get("ip_address") or "").strip()
        if not ip:
            continue
        plugin = str(row.get("plugin_name") or "").strip().lower()
        if "nessus scan information" in plugin:
            output = str(row.get("plugin_output") or "").lower()
            coverage[ip] = bool(re.search(r"credentialed checks\s*:\s*yes", output))
        else:
            coverage.setdefault(ip, source == "CIS")
    return coverage


def cis_result(row: dict) -> str:
    """Compliance verdict of a single CIS row: Passed / Failed / Manual Review.

    Tenable puts ``Result: PASSED|FAILED|WARNING`` in the Plugin Output of a
    compliance check. The severity column carries the same information
    (High = failed, Medium = needs manual validation, Info = passed) and is
    used as a fallback when the output column is missing.
    """
    output = str(row.get("plugin_output") or "").lower()
    match = re.search(r"result\s*:\s*([a-z]+)", output)
    token = match.group(1) if match else ""
    if token == "passed":
        return "Passed"
    if token == "failed":
        return "Failed"
    if token in ("warning", "manual"):
        return "Manual Review"

    severity = str(row.get("severity") or "").strip().lower()
    if severity == "high":
        return "Failed"
    if severity == "medium":
        return "Manual Review"
    return "Passed"


SCOPE_UNKNOWN = "Unknown"


def build_scope(pci_value: str, cj_value: str, sheet_kind: str) -> str:
    """Build the multi-value scope string for one asset.

    The inventory keeps PCI and Crown Jewel as two independent flags, and the
    worksheet the row came from tells us whether it is infrastructure or an
    application host. All of it is preserved in one comma separated field so a
    PCI asset never loses its PCI flag just because it is also a Crown Jewel.
    """
    parts = []
    if str(cj_value or "").strip().upper() in ("CJ", "YES", "CROWN JEWEL", "TRUE", "Y"):
        parts.append("Crown Jewel")
    if str(pci_value or "").strip().upper() == "PCI":
        parts.append("PCI")
    parts.append("Infrastructure" if sheet_kind == "infrastructure" else "Application")
    return ", ".join(parts)


def _asset_rows_from_frame(df: pd.DataFrame, sheet_kind: str) -> list[dict]:
    df = _normalize_columns(df, ASSET_COLUMN_MAP)
    rows = []
    for _, r in df.iterrows():
        row = {}
        for k in ("asset_code", "name", "ip_address", "type", "scope", "environment",
                  "site", "owner_team", "status", "importance", "os_version", "domain"):
            row[k] = str(r[k]).strip() if k in r.index and pd.notna(r.get(k)) else ""
        if not row["ip_address"]:
            continue
        # The inventory may give a full URL where a host name was meant; the
        # host is what a DAST or PT report can be matched against.
        if row.get("domain"):
            row["domain"] = ",".join(
                sorted({domain_from_url(part) for part in row["domain"].split(",")
                        if domain_from_url(part)}))
        # "scope" arrives holding the raw PCI / NPCI value, "importance" the CJ flag.
        row["scope"] = build_scope(row.get("scope"), row.get("importance"), sheet_kind)
        if not row["environment"]:
            row["environment"] = SCOPE_UNKNOWN
        if not row["status"]:
            row["status"] = "Active"
        if not row["site"]:
            row["site"] = SCOPE_UNKNOWN
        if not row["type"]:
            row["type"] = "Server" if sheet_kind == "application" else "Network Device"
        rows.append(row)
    return rows


def parse_asset_inventory(filename: str, content: bytes) -> list[dict]:
    """Parse an asset inventory upload into normalized row dicts.

    Reads EVERY inventory worksheet in the workbook, not just the first one, so
    the Infrastructure Inventory (routers, firewalls, load balancers, storage,
    PAM appliances) is imported alongside the Application Inventory.
    """
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext == "csv":
        return _asset_rows_from_frame(pd.read_csv(io.BytesIO(content)), "application")

    book = pd.ExcelFile(io.BytesIO(content), engine="openpyxl")
    rows: list[dict] = []
    seen_ips: set[str] = set()
    for sheet in book.sheet_names:
        low = sheet.lower()
        if "inventory" not in low:
            continue                      # findings sheets in the same workbook are ignored
        kind = "infrastructure" if "infra" in low else "application"
        for row in _asset_rows_from_frame(book.parse(sheet), kind):
            ip = row["ip_address"]
            if ip in seen_ips:            # the sheets contain repeated IPs - first row wins
                continue
            seen_ips.add(ip)
            rows.append(row)
    if not rows:                          # workbook without an "Inventory" sheet name
        rows = _asset_rows_from_frame(book.parse(book.sheet_names[0]), "application")
    return rows

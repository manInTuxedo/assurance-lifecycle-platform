"""Ingestion & correlation parsing engine for security scan reports (JSON/XML).

Accepts Nessus v2 XML (``.nessus``), OpenVAS/Greenbone XML exports and generic
JSON exports. Every extracted item is normalized to:

    title, description, severity, cvss_score, source, affected_asset,
    cve_id, plugin_id, port

The correlation signature ``CVE + PluginID + Asset + Port`` drives the
deduplication engine: identical signatures resolve to the same persisted
Finding, so re-scans refresh ``last_seen`` instead of creating duplicates.
"""
from __future__ import annotations

import json
import logging
import re
import xml.etree.ElementTree as ET
from typing import Any, Optional

logger = logging.getLogger("assurance.parsers")

# ---------------------------------------------------------------------------
# Severity normalization
# ---------------------------------------------------------------------------

SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low")

SEVERITY_ALIASES = {
    "critical": "Critical",
    "crit": "Critical",
    "criticality": "Critical",
    "very high": "Critical",
    "catastrophic": "Critical",
    "urgent": "Critical",
    "emergency": "Critical",
    "high": "High",
    "major": "High",
    "serious": "High",
    "severe": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "med": "Medium",
    "important": "Medium",
    "low": "Low",
    "minor": "Low",
    "info": "Low",
    "informational": "Low",
    "information": "Low",
    "log": "Low",
    "none": "Low",
    "n/a": "Low",
}

NESSUS_LEVEL_TO_SEVERITY = {4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Low"}

SOURCE_HINTS = (
    ("cis", "CIS Benchmark"),
    ("hardening", "CIS Benchmark"),
    ("config", "Config Review"),
)

DEFAULT_SOURCE = "VA Scan"


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def normalize_severity(raw: Any) -> str:
    if raw is None:
        return "Low"
    if isinstance(raw, bool):
        return "Low"
    if isinstance(raw, (int, float)):
        number = float(raw)
        if number <= 5.0:
            return NESSUS_LEVEL_TO_SEVERITY.get(int(number), severity_from_cvss(number))
        return severity_from_cvss(number)
    text = str(raw).strip().lower()
    if not text:
        return "Low"
    compact = text.replace(".", "", 1).replace("-", "", 1).replace(",", "", 1)
    if compact.isdigit():
        number = float(text.replace(",", "."))
        if number <= 5.0:
            return NESSUS_LEVEL_TO_SEVERITY.get(int(number), severity_from_cvss(number))
        return severity_from_cvss(number)
    return SEVERITY_ALIASES.get(text, "Low")


def normalize_cvss(raw: Any) -> float:
    if raw is None:
        return 0.0
    if isinstance(raw, bool):
        return 0.0
    if isinstance(raw, (int, float)):
        return round(float(raw), 1)
    text = str(raw).strip().replace(",", ".")
    match = re.search(r"\d+(?:\.\d+)?", text)
    if not match:
        return 0.0
    try:
        return round(float(match.group()), 1)
    except ValueError:
        return 0.0


def normalize_cve(raw: Any) -> Optional[str]:
    """Return a canonical CVE id when the raw value contains one."""
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if raw is None or isinstance(raw, bool):
        return None
    match = re.search(r"(CVE-\d{4}-\d{4,7})", str(raw).upper())
    return match.group(1) if match else None


def normalize_port(raw: Any) -> Optional[str]:
    """Port as a plain string, or None when absent."""
    if raw is None or isinstance(raw, bool):
        return None
    text = str(raw).strip()
    match = re.search(r"\d+", text)
    return match.group(0) if match else None


def normalize_plugin_id(raw: Any) -> Optional[str]:
    if raw is None or isinstance(raw, bool):
        return None
    text = str(raw).strip()
    return text if text else None


def detect_source(raw: Optional[dict], family: Optional[str] = None) -> str:
    candidate = family or ""
    if isinstance(raw, dict):
        for key in ("source", "tool", "scan_type", "report_type", "framework", "plugin_family"):
            if raw.get(key):
                candidate = f"{candidate} {raw[key]}"
    probe = str(candidate).strip().lower()
    if not probe:
        return DEFAULT_SOURCE
    for token, label in SOURCE_HINTS:
        if token in probe:
            return label
    if probe in {"va scan", "vulnerability assessment", "vulnerability", "scan", "nessus", "openvas", "qualys", "nexpose", "tenable"}:
        return "VA Scan"
    return DEFAULT_SOURCE


# ---------------------------------------------------------------------------
# Correlation signature
# ---------------------------------------------------------------------------


def build_correlation_signature(
    cve_id: Optional[str],
    plugin_id: Optional[str],
    title: Optional[str],
    asset: Optional[str],
    port: Optional[str],
) -> str:
    """Canonical identity of a finding across scans.

    Signature = ``CVE | PluginID | Asset | Port`` (case-normalized, pipe
    delimited). When a scan export carries neither CVE nor PluginID (e.g.
    some CIS baseline outputs), the normalized title substitutes the plugin
    slot so repeated baseline scans still correlate instead of duplicating.
    """
    def norm(value: Any) -> str:
        if value is None:
            return ""
        return re.sub(r"\s+", " ", str(value)).strip().lower()

    cve = norm(cve_id)
    plugin = norm(plugin_id)
    asset_name = norm(asset)
    port_num = norm(port)
    if cve or plugin:
        return "|".join([cve, plugin, asset_name, port_num or "0"])
    return "|".join(["title", norm(title), asset_name, port_num or "0"])


# ---------------------------------------------------------------------------
# XML (Nessus v2 / OpenVAS)
# ---------------------------------------------------------------------------


def _tag(el) -> str:
    return (el.tag.rsplit("}", 1)[-1] if el.tag else "").lower()


def _attr(el, names: tuple) -> Optional[str]:
    attrib = {key.lower(): value for key, value in el.attrib.items()}
    for name in names:
        value = attrib.get(name.lower())
        if value and str(value).strip():
            return str(value).strip()
    return None


def _child_text(el, names: set) -> Optional[str]:
    for child in el:
        if _tag(child) in names:
            if child.text and child.text.strip():
                return " ".join(child.text.split())
            inner = " ".join(
                part
                for part in (sub.text.strip() for sub in child.iter() if sub is not child and sub.text)
                if part
            )
            if inner:
                return inner
    return None


def _find_nvt(item):
    for el in item.iter():
        if el is not item and _tag(el) == "nvt":
            return el
    return None


def _extract_title(item) -> Optional[str]:
    title = _child_text(item, {"plugin_name", "name", "headline", "vuln_name"})
    if title:
        return title
    title = _attr(item, ("pluginname", "title", "name"))
    if title:
        return title
    nvt = _find_nvt(item)
    if nvt is not None:
        title = _child_text(nvt, {"name"})
        if title:
            return title
    return None


def _extract_description(item) -> str:
    description = _child_text(item, {"description", "synopsis", "summary", "details", "impact"})
    if description:
        return description
    output = _child_text(item, {"plugin_output", "output"})
    return output or ""


def _extract_severity(item) -> str:
    threat = _child_text(item, {"threat"})
    if threat and threat.strip().lower() in SEVERITY_ALIASES:
        return normalize_severity(threat)
    raw = _attr(item, ("severity",)) or _child_text(item, {"severity", "risk", "score"})
    return normalize_severity(raw)


def _extract_cvss(item) -> float:
    raw = _attr(item, ("cvss", "cvss_score", "cvssbase", "cvss3base")) or _child_text(
        item, {"cvss_base_score", "cvss_base", "cvss_score", "cvss", "score"}
    )
    if raw is None:
        nvt = _find_nvt(item)
        if nvt is not None:
            raw = _child_text(nvt, {"cvss_base", "cvss", "score"})
    return normalize_cvss(raw)


def _extract_plugin_id(item) -> Optional[str]:
    raw = _attr(item, ("pluginid", "plugin_id")) or _child_text(item, {"plugin_id", "pluginid"})
    if raw is None:
        nvt = _find_nvt(item)
        if nvt is not None:
            raw = _attr(nvt, ("oid",))
    return normalize_plugin_id(raw)


def _extract_port(item) -> Optional[str]:
    raw = _attr(item, ("port",)) or _child_text(item, {"port", "port_number"})
    return normalize_port(raw)


def _extract_asset(item, parents: Optional[dict] = None) -> Optional[str]:
    if parents is not None:
        cur = parents.get(id(item))
        while cur is not None:
            if _tag(cur) == "reporthost":
                name = cur.attrib.get("name")
                if name:
                    return name.strip()
            cur = parents.get(id(cur))
    asset = _child_text(item, {"host", "hostname", "asset", "ipaddress", "ip", "dns_name"})
    return asset


def _parent_map(root) -> dict[int, Any]:
    return {id(child): parent for parent in root.iter() for child in list(parent)}


def _extract_cves(item) -> list[str]:
    cves: set[str] = set()
    for el in item.iter():
        if _tag(el) in {"cve", "cveid"} and el is not item and (el.text or "").strip():
            for part in re.split(r"[\s,;]+", el.text):
                part = part.strip().upper()
                if part.startswith("CVE-") and re.match(r"CVE-\d{4}-\d{4,7}$", part):
                    cves.add(part)
    for attr_name in ("cve", "cve_id", "cveid"):
        value = item.attrib.get(attr_name)
        if value:
            for part in re.split(r"[\s,;]+", value):
                part = part.strip().upper()
                if part.startswith("CVE-"):
                    cves.add(part)
    return sorted(cves)


FINDING_TAGS = {"reportitem", "result", "finding", "issue", "item", "vuln", "vulnerability"}


def parse_xml(content: bytes) -> list[dict]:
    """Parse Nessus v2 / OpenVAS style XML into normalized findings."""
    root = ET.fromstring(content)
    parents = _parent_map(root)
    findings: list[dict] = []
    for element in root.iter():
        if _tag(element) not in FINDING_TAGS:
            continue
        title = _extract_title(element)
        if not title:
            continue
        asset = _extract_asset(element, parents)
        if not asset:
            continue
        cves = _extract_cves(element)
        family = _child_text(element, {"plugin_family", "family"}) or _attr(element, ("pluginfamily", "plugin_family"))
        findings.append(
            {
                "title": title,
                "description": _extract_description(element),
                "severity": _extract_severity(element),
                "cvss_score": _extract_cvss(element),
                "source": detect_source(None, family),
                "affected_asset": asset,
                "cve_id": cves[0] if cves else None,
                "plugin_id": _extract_plugin_id(element),
                "port": _extract_port(element),
            }
        )
    return findings


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def _json_lookup(obj: dict, *keys) -> Any:
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return None


def _flatten_host_objects(payload: dict) -> list[dict]:
    expanded: list[dict] = []
    for host in payload.get("hosts") or payload.get("assets") or []:
        if not isinstance(host, dict):
            continue
        base_asset = _json_lookup(host, "hostname", "host", "asset", "ip_address", "ip", "dns_name", "name")
        base_asset = str(base_asset or "unknown-host").strip()
        nested = host.get("findings") or host.get("vulnerabilities") or host.get("issues") or host.get("items") or []
        if not isinstance(nested, list):
            continue
        for item in nested:
            if isinstance(item, dict):
                item = dict(item)
                item["_asset_fallback"] = base_asset
                expanded.append(item)
    return expanded


def _parse_json_item(item: dict) -> Optional[dict]:
    title = _json_lookup(item, "title", "name", "vuln_name", "plugin_name", "pluginName", "headline", "finding_title")
    if not title:
        return None
    asset = _json_lookup(item, "affected_asset", "asset", "hostname", "host", "ip_address", "ip", "dns_name")
    asset = asset or item.get("_asset_fallback")
    asset = str(asset or "unknown-host").strip()

    severity = _json_lookup(item, "severity", "risk", "threat", "criticality", "severity_level", "impact")
    cvss = _json_lookup(item, "cvss_score", "cvssScore", "cvss", "CVSS", "cvss_base_score", "cvss_base", "score")
    cve = _json_lookup(item, "cve_id", "cveId", "cve", "CVE", "cve_ids", "cveIds")
    description = _json_lookup(item, "description", "details", "desc", "summary", "synopsis", "plugin_output")
    family = _json_lookup(item, "plugin_family", "family", "pluginFamily")
    plugin_id = _json_lookup(item, "plugin_id", "pluginID", "pluginId", "plugin")
    port = _json_lookup(item, "port", "port_number", "portNumber")

    return {
        "title": str(title).strip(),
        "description": str(description or "").strip(),
        "severity": normalize_severity(severity),
        "cvss_score": normalize_cvss(cvss),
        "source": detect_source(item, str(family or "")),
        "affected_asset": asset,
        "cve_id": normalize_cve(cve),
        "plugin_id": normalize_plugin_id(plugin_id),
        "port": normalize_port(port),
    }


def parse_json(payload: Any) -> list[dict]:
    items: list[Any] = []
    if isinstance(payload, list):
        items = [x for x in payload if isinstance(x, dict)]
    elif isinstance(payload, dict):
        items = _flatten_host_objects(payload)
        if not items:
            for key in ("findings", "vulnerabilities", "issues", "results", "items", "reports", "assets"):
                if isinstance(payload.get(key), list):
                    items = [x for x in payload[key] if isinstance(x, dict)]
                    break
        if not items and _json_lookup(payload, "title", "name", "plugin_name"):
            items = [payload]

    findings: list[dict] = []
    for item in items:
        record = _parse_json_item(item)
        if record:
            findings.append(record)
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_scan_file(filename: str, content: bytes) -> dict:
    """Parse an uploaded scan file into normalized findings.

    Raises ``ValueError`` when the file cannot be parsed or contains no
    extractable findings.
    """
    text = content.decode("utf-8", errors="replace").strip()
    if not text:
        raise ValueError("Uploaded file is empty")

    if text.startswith(("{", "[")):
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON document: {exc.msg}") from exc
        findings = parse_json(payload)
    else:
        try:
            findings = parse_xml(content)
        except ET.ParseError as exc:
            raise ValueError(f"Invalid XML document: {exc}") from exc

    if not findings:
        raise ValueError(
            "No supported findings could be extracted from the file. "
            "Expected Nessus/OpenVAS XML or JSON with title/name and host/asset fields."
        )
    logger.info("Parsed %d findings from %s", len(findings), filename)
    return {"filename": filename, "findings": findings, "count": len(findings)}
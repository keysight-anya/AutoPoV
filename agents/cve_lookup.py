"""
CVE lookup via OSV.dev — replaces static advisory_db.json.

OSV (https://osv.dev) is Google's open source vulnerability database.
Free, no API key, covers PyPI / npm / Maven / crates.io / Go / RubyGems /
Packagist / NuGet. Updates within hours of new advisories.

Architecture:
  Layer 1: OSV live API (always current, always complete)
  Layer 2: Local disk cache  (fallback when network unavailable)

The cache is populated automatically on every successful OSV query.
It is never manually maintained — just a snapshot of recent responses.
"""

import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# OSV API endpoints
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

# Cache file location — lives in ./data/osv_cache.json next to where
# advisory_db.json was. Auto-created on first successful query.
_CACHE_PATH = Path(__file__).resolve().parents[1] / "data" / "osv_cache.json"

# Cache TTL: 24 hours. Old enough to avoid hammering OSV, fresh enough
# to pick up new advisories within a day.
_CACHE_TTL_S = 86_400

# OSV ecosystem names differ from internal names
_ECOSYSTEM_MAP = {
    "pip":      "PyPI",
    "pypi":     "PyPI",   # Syft outputs 'pypi', not 'pip'
    "npm":      "npm",
    "maven":    "Maven",
    "cargo":    "crates.io",
    "go":       "Go",
    "gem":      "RubyGems",
    "composer": "Packagist",
    "nuget":    "NuGet",
}


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def query_cves_for_dependencies(
    deps: List[Dict[str, str]],
    timeout_s: float = 10.0,
) -> List[Dict[str, Any]]:
    """Return CVE findings for a list of parsed dependencies.

    Tries OSV live API first. Falls back to local cache on network failure.
    Returns [] when neither is available — never raises, never blocks a scan.

    Args:
        deps: list of {name, version, ecosystem} dicts from
              _parse_dependency_versions() in recon_agent.py
        timeout_s: HTTP timeout — keep low so recon never blocks a scan

    Returns:
        List of CVE finding dicts. Each dict has the same fields that
        agent_graph._node_recon() expects when iterating known_cve_findings:
          package, ecosystem, installed_version, fix_version,
          cve, cwe, severity, cvss, description, proof_hint, proof_type,
          osv_id, aliases
    """
    if not deps:
        return []

    # Build the OSV batch request
    queries, dep_index = _build_osv_queries(deps)
    if not queries:
        return []

    # Layer 1: Try live OSV API
    raw_results = _query_osv_live(queries, timeout_s)

    if raw_results is not None:
        findings = _parse_osv_results(raw_results, dep_index)
        # Persist to cache for offline fallback
        _write_cache(deps, findings)
        logger.info(
            "cve_lookup: OSV returned %d CVEs for %d dependencies",
            len(findings), len(deps)
        )
        return findings

    # Layer 2: Fall back to local cache
    logger.warning("cve_lookup: OSV unreachable — trying local cache")
    cached = _read_cache(deps)
    if cached is not None:
        logger.info("cve_lookup: cache hit — %d CVEs", len(cached))
        return cached

    logger.warning("cve_lookup: no cache available — CVE detection skipped")
    return []


# ─────────────────────────────────────────────────────────────────────────────
# OSV API
# ─────────────────────────────────────────────────────────────────────────────

def _build_osv_queries(
    deps: List[Dict[str, str]],
) -> Tuple[List[Dict], List[Dict]]:
    """Build OSV batch query list and parallel dep_index for result mapping."""
    queries: List[Dict] = []
    dep_index: List[Dict] = []
    for dep in deps:
        name = dep.get("name", "").strip()
        ecosystem = _ECOSYSTEM_MAP.get(dep.get("ecosystem", ""), "")
        version = dep.get("version", "").strip()
        if not name or not ecosystem:
            continue
        entry: Dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
        if version:
            entry["version"] = version
        queries.append(entry)
        dep_index.append(dep)
    return queries, dep_index


def _query_osv_live(
    queries: List[Dict],
    timeout_s: float,
) -> Optional[List[Dict]]:
    """POST to OSV batch endpoint. Returns raw results list or None on error."""
    try:
        import requests
        resp = requests.post(
            OSV_BATCH_URL,
            json={"queries": queries},
            timeout=timeout_s,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        return resp.json().get("results", [])
    except Exception as exc:
        logger.debug("cve_lookup: OSV query failed: %s", exc)
        return None


def _parse_osv_results(
    results: List[Dict],
    dep_index: List[Dict],
) -> List[Dict[str, Any]]:
    """Convert raw OSV batch results into finding dicts."""
    findings: List[Dict[str, Any]] = []
    seen_cves: set = set()

    for i, result in enumerate(results):
        vulns = result.get("vulns") or []
        if not vulns:
            continue
        dep = dep_index[i] if i < len(dep_index) else {}

        for vuln in vulns:
            cve_id = _extract_cve_id(vuln)
            if not cve_id or cve_id in seen_cves:
                continue
            seen_cves.add(cve_id)

            findings.append({
                "package":           dep.get("name", ""),
                "ecosystem":         dep.get("ecosystem", ""),
                "installed_version": dep.get("version", "unknown"),
                "fix_version":       _extract_fix_version(vuln, dep.get("ecosystem", "")),
                "cve":               cve_id,
                "cwe":               _extract_cwe(vuln),
                "severity":          _extract_severity(vuln),
                "cvss":              _extract_cvss(vuln),
                "description":       _extract_description(vuln),
                "proof_hint":        _derive_proof_hint(vuln, dep),
                "proof_type":        _derive_proof_type(vuln),
                "osv_id":            vuln.get("id", ""),
                "aliases":           vuln.get("aliases") or [],
            })

    # Highest CVSS first — most critical findings get proved first
    findings.sort(key=lambda x: float(x.get("cvss") or 0), reverse=True)
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# OSV field extractors
# ─────────────────────────────────────────────────────────────────────────────

def _extract_cve_id(vuln: Dict) -> Optional[str]:
    """Extract CVE-YYYY-NNNN from vuln entry. Prefers canonical CVE over OSV ID."""
    osv_id = vuln.get("id", "")
    if osv_id.startswith("CVE-"):
        return osv_id
    for alias in (vuln.get("aliases") or []):
        if alias.startswith("CVE-"):
            return alias
    # Return OSV ID as fallback (GHSA-xxx, PYSEC-xxx, etc.)
    return osv_id or None


def _extract_severity(vuln: Dict) -> str:
    score = _extract_cvss(vuln)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _extract_cvss(vuln: Dict) -> float:
    """Extract numeric CVSS base score from any CVSS version."""
    for sev in (vuln.get("severity") or []):
        score_str = str(sev.get("score") or "")
        sev_type = sev.get("type", "")
        if sev_type.startswith("CVSS") and score_str:
            try:
                # CVSS vector strings look like "7.5" or "CVSS:3.1/AV:N/..."
                # Extract the first float-looking part
                m = re.search(r"(\d+\.\d+)", score_str)
                if m:
                    return float(m.group(1))
            except (ValueError, TypeError):
                pass
    return 0.0


def _extract_fix_version(vuln: Dict, ecosystem: str) -> str:
    """Extract the version that fixes this vulnerability."""
    osv_eco = _ECOSYSTEM_MAP.get(ecosystem, "")
    for affected in (vuln.get("affected") or []):
        pkg_eco = (affected.get("package") or {}).get("ecosystem", "")
        if osv_eco and pkg_eco != osv_eco:
            continue
        for r in (affected.get("ranges") or []):
            for event in (r.get("events") or []):
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def _extract_cwe(vuln: Dict) -> str:
    """Extract CWE ID from OSV vuln entry."""
    # OSV stores CWEs in database_specific for some ecosystems
    db_specific = vuln.get("database_specific") or {}
    cwe_ids = db_specific.get("cwe_ids") or []
    if cwe_ids:
        return str(cwe_ids[0])
    # Try references for CWE links
    for ref in (vuln.get("references") or []):
        url = str(ref.get("url") or "")
        m = re.search(r"CWE-(\d+)", url)
        if m:
            return f"CWE-{m.group(1)}"
    return "UNCLASSIFIED"


def _extract_description(vuln: Dict) -> str:
    """Extract human-readable description, preferring summary over details."""
    summary = str(vuln.get("summary") or "").strip()
    if summary:
        return summary
    details = str(vuln.get("details") or "").strip()
    return details[:300] if details else ""


# ─────────────────────────────────────────────────────────────────────────────
# Proof derivation — fully dynamic from OSV description, no hardcoding
# ─────────────────────────────────────────────────────────────────────────────

def _derive_proof_hint(vuln: Dict, dep: Dict) -> str:
    """Derive a human-readable proof hint from OSV description.

    No hardcoded CVE IDs. Derived entirely from the vulnerability text.
    """
    text = (
        (vuln.get("summary") or "") + " " +
        (vuln.get("details") or "")
    ).lower()

    # Pattern matching against description text — not CVE IDs
    if any(k in text for k in ("jndi", "log4shell", "lookup injection")):
        return "JNDI lookup injection via user-controlled log message"
    if any(k in text for k in ("remote code execution", " rce ", "code execution")):
        return f"Remote code execution via {dep.get('name', 'vulnerable component')}"
    if any(k in text for k in ("sql injection", " sqli ")):
        return "SQL injection via unsanitised user input to database query"
    if any(k in text for k in ("path traversal", "directory traversal", "zip slip")):
        return "Path traversal via unsanitised file path in attacker-controlled input"
    if "prototype pollution" in text:
        return "Prototype pollution via crafted object merge — check Object.prototype"
    if any(k in text for k in ("deserializ", "unsafe deseri")):
        return "Unsafe deserialization of attacker-controlled data"
    if any(k in text for k in ("command injection", "os command", "shell injection")):
        return "OS command injection via unsanitised parameter passed to shell"
    if any(k in text for k in ("xxe", "xml external entity")):
        return "XXE injection via crafted XML with DOCTYPE external entity"
    if any(k in text for k in ("ssrf", "server-side request forgery")):
        return "SSRF via attacker-controlled URL parameter making internal requests"
    if any(k in text for k in ("open redirect",)):
        return "Open redirect via unvalidated URL in redirect parameter"
    if any(k in text for k in ("buffer overflow", "heap overflow", "stack overflow",
                                "out-of-bounds write")):
        return "Memory corruption via oversized or malformed input buffer"
    if any(k in text for k in ("use-after-free", "use after free")):
        return "Use-after-free via crafted sequence of alloc/free/access operations"
    if any(k in text for k in ("integer overflow", "integer underflow")):
        return "Integer overflow leading to undersized allocation and heap corruption"
    if any(k in text for k in ("redos", "regular expression denial", "catastrophic backtracking")):
        return "ReDoS via crafted input string triggering catastrophic regex backtracking"
    if any(k in text for k in ("template injection", "ssti")):
        return "Server-side template injection via unsanitised template variable"
    if any(k in text for k in ("ldap injection",)):
        return "LDAP injection via unsanitised input in LDAP filter"
    if any(k in text for k in ("xss", "cross-site scripting")):
        return "XSS via unsanitised user input reflected in HTML response"
    if any(k in text for k in ("csrf", "cross-site request forgery")):
        return "CSRF — missing or bypassable anti-forgery token on state-changing request"
    if any(k in text for k in ("authentication bypass", "improper authentication")):
        return "Authentication bypass — access protected resource without valid credentials"
    if any(k in text for k in ("authorization bypass", "privilege escalation",
                                "access control")):
        return "Authorization bypass — access resource with insufficient privilege"
    if any(k in text for k in ("memory leak", "resource leak")):
        return "Memory leak — repeated allocation without corresponding free"
    if any(k in text for k in ("denial of service", " dos ", "crash")):
        return "Denial of service via crafted input triggering crash or resource exhaustion"

    # Generic fallback: use whatever OSV summary says
    return vuln.get("summary") or f"Known vulnerability in {dep.get('name', 'dependency')}"


def _derive_proof_type(vuln: Dict) -> str:
    """Derive the correct proof_type from OSV description.

    Maps vulnerability class to the oracle evaluation strategy.
    No hardcoded CVE IDs — derived from description keywords.
    """
    text = (
        (vuln.get("summary") or "") + " " +
        (vuln.get("details") or "")
    ).lower()

    # Memory corruption — crash_signal is the right oracle (ASan/UBSan output)
    if any(k in text for k in ("buffer overflow", "heap overflow", "stack overflow",
                                "use-after-free", "use after free", "memory corruption",
                                "out-of-bounds write", "out-of-bounds read",
                                "integer overflow", "double free", "heap spray")):
        return "crash_signal"

    # RCE and code execution — state_change (file/command side effect is the proof)
    if any(k in text for k in ("remote code execution", " rce ", "code execution",
                                "jndi", "deserialization", "deserializ",
                                "command injection", "template injection", "ssti",
                                "unsafe eval", "unsafe exec")):
        return "state_change"

    # Information disclosure — oracle checks for content in response
    if any(k in text for k in ("information disclosure", "data exposure",
                                "ssrf", "xxe", "path traversal", "directory traversal",
                                "zip slip", "ldap injection", "sensitive data")):
        return "information_disclosure"

    # Observable output in HTTP response (injection attacks with error/data in output)
    if any(k in text for k in ("sql injection", "sqli", "xss",
                                "cross-site scripting", "open redirect",
                                "header injection", "log injection")):
        return "observable_output"

    # Behavioural deviation (logic bugs, auth bypass, prototype pollution)
    if any(k in text for k in ("prototype pollution", "authentication bypass",
                                "authorization bypass", "privilege escalation",
                                "access control", "improper authentication",
                                "csrf", "cross-site request forgery",
                                "improper validation", "logic")):
        return "behavioral_deviation"

    # Resource exhaustion (DoS, ReDoS, memory leak)
    if any(k in text for k in ("denial of service", " dos ", "redos",
                                "catastrophic backtracking", "memory exhaustion",
                                "memory leak", "resource leak", "resource exhaustion")):
        return "resource_exhaustion"

    # Generic safe fallback
    return "observable_output"


# ─────────────────────────────────────────────────────────────────────────────
# Local cache
# ─────────────────────────────────────────────────────────────────────────────

def _cache_key(deps: List[Dict[str, str]]) -> str:
    """Stable cache key from sorted dep list, hashed for compact storage."""
    import hashlib
    parts = sorted(
        f"{d.get('name', '')}:{d.get('version', '')}:{d.get('ecosystem', '')}"
        for d in deps
    )
    return hashlib.md5("|".join(parts).encode()).hexdigest()


def _write_cache(deps: List[Dict[str, str]], findings: List[Dict]) -> None:
    """Write findings to local cache keyed by dep fingerprint."""
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        cache: Dict = {}
        if _CACHE_PATH.is_file():
            try:
                cache = json.loads(_CACHE_PATH.read_text())
            except Exception:
                cache = {}
        key = _cache_key(deps)
        cache[key] = {"findings": findings, "ts": time.time()}
        # Keep cache from growing forever — evict entries older than TTL
        now = time.time()
        cache = {
            k: v for k, v in cache.items()
            if now - float(v.get("ts", 0)) < _CACHE_TTL_S * 7  # keep 1 week
        }
        _CACHE_PATH.write_text(json.dumps(cache, indent=2))
    except Exception as exc:
        logger.debug("cve_lookup: cache write failed: %s", exc)


def _read_cache(deps: List[Dict[str, str]]) -> Optional[List[Dict]]:
    """Read findings from local cache. Returns None on miss or expired entry."""
    try:
        if not _CACHE_PATH.is_file():
            return None
        cache = json.loads(_CACHE_PATH.read_text())
        key = _cache_key(deps)
        entry = cache.get(key)
        if not entry:
            return None
        age_s = time.time() - float(entry.get("ts", 0))
        if age_s > _CACHE_TTL_S:
            return None  # expired
        return entry.get("findings") or []
    except Exception as exc:
        logger.debug("cve_lookup: cache read failed: %s", exc)
        return None

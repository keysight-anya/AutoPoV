"""
CVE Enricher Module
===================
Enriches findings with CVE/vulnerability intelligence from public databases.

Uses OSV.dev API (free, no auth required) as primary source.
Can be extended with firecrawl or NVD API when available.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# OSV.dev API endpoint
_OSV_API = 'https://api.osv.dev/v1'


def enrich_finding_with_cve(
    finding: Dict[str, Any],
    exploit_contract: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Enrich a finding with CVE details from public vulnerability databases.

    Queries OSV.dev for:
    - CVE description and severity
    - Affected versions
    - Fix version
    - Proof hints (from advisory text)

    Returns the enriched exploit_contract dict.
    """
    ec = dict(exploit_contract or finding.get('exploit_contract') or {})
    cve_id = str(finding.get('cve_id') or ec.get('cve_id') or '').strip()

    if not cve_id or not cve_id.startswith('CVE-'):
        return ec

    # Skip if already enriched
    if ec.get('cve_enriched'):
        return ec

    try:
        import requests
    except ImportError:
        logger.debug('requests not available for CVE enrichment')
        return ec

    try:
        # Query OSV.dev by CVE alias
        resp = requests.post(
            f'{_OSV_API}/query',
            json={'aliases': [cve_id]},
            timeout=10,
        )
        if resp.status_code != 200:
            logger.debug('OSV query failed for %s: HTTP %d', cve_id, resp.status_code)
            return ec

        data = resp.json()
        vulns = data.get('vulns', [])
        if not vulns:
            logger.debug('No OSV results for %s', cve_id)
            return ec

        vuln = vulns[0]  # Take the first match

        # Extract key fields
        ec['cve_id'] = cve_id
        ec['cve_enriched'] = True
        ec['cve_osv_id'] = vuln.get('id', '')

        # Summary/description
        summary = vuln.get('summary', '') or vuln.get('details', '')
        if summary:
            ec['cve_summary'] = summary[:500]

        # Severity (CVSS)
        severity = vuln.get('severity', [])
        if severity:
            for sev in severity:
                if sev.get('type') == 'CVSS_V3':
                    ec['cve_cvss_vector'] = sev.get('score', '')
                    break

        # Database-specific severity
        db_specific = vuln.get('database_specific', {})
        if db_specific.get('severity'):
            ec['cve_severity'] = db_specific['severity']
        if db_specific.get('cvss', {}).get('score'):
            ec['cve_cvss'] = db_specific['cvss']['score']

        # Affected versions and fix
        affected = vuln.get('affected', [])
        for aff in affected:
            ranges = aff.get('ranges', [])
            for r in ranges:
                events = r.get('events', [])
                for ev in events:
                    if ev.get('fixed'):
                        ec['cve_fix_version'] = ev['fixed']
                        break

        # Extract proof hints from description
        _proof_hint = _extract_proof_hint(summary, cve_id)
        if _proof_hint:
            # Inject into proof_strategy
            ps = dict(ec.get('proof_strategy') or {})
            ps['cve_proof_hint'] = _proof_hint
            ec['proof_strategy'] = ps

        logger.info('CVE enriched: %s (OSV: %s, CVSS: %s)',
                     cve_id, ec.get('cve_osv_id'), ec.get('cve_cvss'))

    except Exception as e:
        logger.warning('CVE enrichment failed for %s: %s', cve_id, e)

    return ec


def _extract_proof_hint(description: str, cve_id: str) -> str:
    """Extract actionable proof hint from CVE description."""
    if not description:
        return ''

    desc_lower = description.lower()

    # Common vulnerability patterns → proof hints
    _PATTERNS = [
        ('buffer overflow', f'Trigger buffer overflow in {cve_id} by sending oversized input'),
        ('heap-based buffer', f'Trigger heap buffer overflow by crafting input that exceeds allocation'),
        ('stack-based buffer', f'Trigger stack buffer overflow with oversized local buffer input'),
        ('use-after-free', f'Trigger use-after-free by creating/destroying objects in specific sequence'),
        ('double free', f'Trigger double-free by manipulating object lifecycle'),
        ('integer overflow', f'Trigger integer overflow with large numeric values causing wraparound'),
        ('null pointer', f'Trigger null pointer dereference with crafted empty/missing input'),
        ('out-of-bounds read', f'Trigger out-of-bounds read with malformed container/header data'),
        ('out-of-bounds write', f'Trigger out-of-bounds write with oversized payload fields'),
        ('denial of service', f'Trigger resource exhaustion/crash via malformed input'),
        ('sql injection', f'Inject SQL via user-controlled input parameter'),
        ('cross-site scripting', f'Inject script payload that reflects in output'),
        ('path traversal', f'Access files outside intended directory via ../ sequences'),
        ('remote code execution', f'Execute arbitrary code via crafted input'),
    ]

    for pattern, hint in _PATTERNS:
        if pattern in desc_lower:
            return hint

    return f'Exploit {cve_id} as described: {description[:200]}'


def batch_enrich_findings(
    findings: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Enrich all findings that have CVE IDs."""
    enriched = []
    for finding in findings:
        cve_id = str(finding.get('cve_id') or '').strip()
        if cve_id and cve_id.startswith('CVE-'):
            ec = enrich_finding_with_cve(finding)
            finding = dict(finding)
            finding['exploit_contract'] = ec
        enriched.append(finding)
    return enriched


# ── Seed PoC fetching ──────────────────────────────────────────────
_POC_CACHE_DIR = Path(os.environ.get('AUTOPOV_DATA_DIR', '/app/data')) / 'poc_cache'
_MAX_POC_SIZE = 30_000  # bytes

# URL patterns likely to contain PoC / exploit code
_POC_URL_PATTERNS = [
    re.compile(r'github\.com/.+/commit/[0-9a-f]+', re.I),
    re.compile(r'github\.com/.+/(blob|raw)/.+\.(c|py|rb|go|js|sh|pl|java)', re.I),
    re.compile(r'exploit-db\.com/exploits/\d+', re.I),
    re.compile(r'packetstormsecurity\.com/files/\d+', re.I),
    re.compile(r'gist\.github\.com/', re.I),
]


def _poc_cache_path(cve_id: str) -> Path:
    """Return the on-disk cache path for a CVE PoC."""
    _POC_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe = hashlib.sha256(cve_id.encode()).hexdigest()[:16]
    return _POC_CACHE_DIR / f'{cve_id}_{safe}.json'


def _looks_like_poc_url(url: str) -> bool:
    return any(p.search(url) for p in _POC_URL_PATTERNS)


def _github_commit_to_raw(url: str) -> Optional[str]:
    """Convert a GitHub commit URL to a .patch URL for fetching."""
    m = re.search(r'github\.com/([^/]+/[^/]+)/commit/([0-9a-f]+)', url)
    if m:
        return f'https://github.com/{m.group(1)}/commit/{m.group(2)}.patch'
    return None


def _fetch_url_text(url: str, timeout: int = 10) -> str:
    """Fetch raw text from a URL with size limit."""
    try:
        import requests
    except ImportError:
        return ''
    try:
        resp = requests.get(url, timeout=timeout, stream=True,
                            headers={'Accept': 'text/plain, text/html'})
        if resp.status_code != 200:
            return ''
        chunks = []
        total = 0
        for chunk in resp.iter_content(chunk_size=4096):
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_POC_SIZE:
                break
        return b''.join(chunks).decode('utf-8', errors='replace')
    except Exception as e:
        logger.debug('Failed to fetch %s: %s', url, e)
        return ''


def fetch_existing_poc(cve_id: str) -> str:
    """Fetch an existing PoC / exploit snippet for a CVE from public references.

    Uses cached data when available.  Queries OSV.dev references for GitHub
    commit patches, exploit-db, and other known PoC sources.

    Returns the PoC code string (may be empty).
    """
    if not cve_id or not cve_id.startswith('CVE-'):
        return ''

    # 1. Check cache
    cache_path = _poc_cache_path(cve_id)
    if cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text())
            return cached.get('poc', '')
        except Exception:
            pass

    try:
        import requests
    except ImportError:
        return ''

    poc_text = ''
    try:
        # 2. Query OSV for references
        resp = requests.post(
            f'{_OSV_API}/query',
            json={'aliases': [cve_id]},
            timeout=10,
        )
        if resp.status_code != 200:
            return ''

        vulns = resp.json().get('vulns', [])
        if not vulns:
            return ''

        vuln = vulns[0]
        references = vuln.get('references', [])

        # 3. Iterate references looking for PoC-like URLs
        for ref in references:
            url = ref.get('url', '')
            if not url or not _looks_like_poc_url(url):
                continue

            # Convert GitHub commit URL to .patch
            raw_url = _github_commit_to_raw(url)
            if raw_url:
                text = _fetch_url_text(raw_url)
                if text and len(text) > 50:
                    poc_text = f'# Source: {url}\n# (commit patch)\n\n{text[:_MAX_POC_SIZE]}'
                    break

            # Direct fetch for exploit-db / gist / raw links
            text = _fetch_url_text(url)
            if text and len(text) > 50:
                poc_text = f'# Source: {url}\n\n{text[:_MAX_POC_SIZE]}'
                break

    except Exception as e:
        logger.warning('PoC fetch failed for %s: %s', cve_id, e)

    # 4. Cache result (even empty — avoids repeated lookups)
    try:
        cache_path.write_text(json.dumps({'cve_id': cve_id, 'poc': poc_text}))
    except Exception:
        pass

    if poc_text:
        logger.info('Fetched seed PoC for %s (%d chars)', cve_id, len(poc_text))
    return poc_text


# ── PoC analysis ──────────────────────────────────────────────────────────────

def analyze_poc(
    poc_text: str,
    cve_id: str = '',
    cve_summary: str = '',
    llm_invoke=None,
) -> Dict[str, Any]:
    """Analyze PoC/patch text and extract structured exploit intelligence.

    Tries fast static analysis first; if an LLM callable is provided and static
    analysis yields weak results, asks the LLM for deeper analysis.

    Returns:
        {
          "trigger_input": str,            # the payload / input that triggers the bug
          "preconditions": [str, ...],     # setup steps before triggering
          "observable_evidence": [str, ..],# what output confirms the exploit fired
          "target_function": str,          # vulnerable function or entrypoint name
          "exploit_pattern": str,          # e.g. "heap buffer overflow via oversized key"
          "analysis_source": str,          # "static" | "llm" | "cached"
        }
    """
    if not poc_text:
        return {}

    # Check if analysis is already cached in the POC cache file
    try:
        cache_path = _poc_cache_path(cve_id) if cve_id else None
    except Exception:
        cache_path = None
    if cache_path and cache_path.exists():
        try:
            cached = json.loads(cache_path.read_text())
            if cached.get('poc_analysis'):
                return dict(cached['poc_analysis'])
        except Exception:
            pass

    analysis = _static_analyze_poc(poc_text, cve_id, cve_summary)

    # Use LLM if available and static analysis is sparse
    if llm_invoke and _static_analysis_is_sparse(analysis):
        try:
            llm_analysis = _llm_analyze_poc(poc_text, cve_id, cve_summary, llm_invoke)
            if llm_analysis:
                # Merge: LLM fills gaps that static left empty
                for k, v in llm_analysis.items():
                    if v and not analysis.get(k):
                        analysis[k] = v
                analysis['analysis_source'] = 'llm'
        except Exception as e:
            logger.debug('LLM PoC analysis failed: %s', e)

    if analysis:
        analysis.setdefault('analysis_source', 'static')
        # Cache alongside the PoC
        if cache_path and cache_path.exists():
            try:
                cached = json.loads(cache_path.read_text())
                cached['poc_analysis'] = analysis
                cache_path.write_text(json.dumps(cached))
            except Exception:
                pass

    return analysis


def _static_analyze_poc(poc_text: str, cve_id: str, cve_summary: str) -> Dict[str, Any]:
    """Extract exploit intelligence from PoC text using regex/heuristics."""
    result: Dict[str, Any] = {}
    text = poc_text
    text_lower = text.lower()

    # ── Target function: from patch hunks or common call patterns ──
    fn_names = re.findall(r'@@[^@]+@@[^\n]*\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', text)
    if not fn_names:
        # function definitions or direct calls
        fn_names = re.findall(
            r'(?:^|\n)\s*(?:static\s+)?(?:\w+\s+)+([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]{0,80}\)\s*\{',
            text, re.MULTILINE
        )
    if fn_names:
        result['target_function'] = fn_names[0]

    # ── Trigger input: file args, string literals, byte arrays, URL params ──
    # Path traversal payloads
    traversal_m = re.search(r'["\']([./\\]{2,}(?:etc/passwd|etc/shadow|windows/win.ini|[./\\]+)[^"\']{0,60})["\']', text)
    if traversal_m:
        result['trigger_input'] = f'path traversal: {traversal_m.group(1)}'
    else:
        # HTTP requests (requests.get/post, curl-style)
        http_m = re.search(
            r'(?:requests\.[a-z]+|curl|GET|POST|PUT|DELETE)\s*\(\s*[^,\n)]{0,30}["\']([^"\']{5,120})["\']',
            text
        )
        if http_m:
            result['trigger_input'] = f'HTTP request: {http_m.group(1)}'
        else:
            # fopen/open with explicit path
            file_args = re.findall(r'(?:fopen|open|load|parse|read)\s*\(\s*["\']([^"\']+)["\']', text)
            if file_args:
                result['trigger_input'] = f'file: {file_args[0]}'
            else:
                # Buffer copy functions with literal
                buf_args = re.findall(
                    r'(?:strcpy|sprintf|memcpy|strcat|gets)\s*\([^,]+,\s*["\']([^"\']{1,80})["\']',
                    text
                )
                if buf_args:
                    result['trigger_input'] = f'string: "{buf_args[0]}"'
                else:
                    # Raw HTTP request lines
                    http_line = re.search(r'(GET|POST|PUT|DELETE)\s+([^\s"\'\\]{1,80})', text)
                    if http_line:
                        result['trigger_input'] = f'HTTP {http_line.group(1)} {http_line.group(2)}'
                    else:
                        # Large repeated-byte buffers (e.g. 'A' * N)
                        repeat_m = re.search(r'["\']([A-Za-z])["\'\s]*\*\s*(\d+)', text)
                        if repeat_m:
                            result['trigger_input'] = f'repeated byte 0x{ord(repeat_m.group(1)):02X} x{repeat_m.group(2)}'

    # ── Observable evidence: what does the PoC print/check? ──
    evidence = []
    # Crash / abort markers
    if any(kw in text_lower for kw in ('segfault', 'sigsegv', 'sigabrt', 'abort(', 'assert(')):
        evidence.append('crash (SIGSEGV/SIGABRT)')
    if any(kw in text_lower for kw in ('addresssanitizer', 'heap-buffer-overflow', 'stack-buffer-overflow')):
        evidence.append('ASan heap/stack buffer overflow report')
    if any(kw in text_lower for kw in ('use-after-free', 'use after free')):
        evidence.append('ASan use-after-free report')
    if any(kw in text_lower for kw in ('double-free', 'double free')):
        evidence.append('ASan double-free report')
    # Explicit markers in the PoC itself (C printf / Python print / shell echo)
    custom_markers = re.findall(
        r'(?:print(?:f|ln)?\s*\(|puts\s*\(|fprintf\s*\([^,]+,|echo\s+|console\.log\s*\()'
        r'\s*["\']([^"\']{5,120})["\']',
        text
    )
    for m in custom_markers:
        m_lower = m.lower()
        if any(kw in m_lower for kw in ('vuln', 'exploit', 'success', 'poc', 'trigger',
                                         'overflow', 'error', 'crash', 'confirm', 'traversal')):
            evidence.append(m.strip())
    if not evidence:
        # Non-zero exit or exception as fallback
        if any(kw in text_lower for kw in ('exit(1)', 'sys.exit', 'raise ', 'exception', 'error')):
            evidence.append('non-zero exit or exception')
    if evidence:
        result['observable_evidence'] = evidence

    # ── Preconditions: setup steps ──
    preconditions = []
    if any(kw in text_lower for kw in ('malloc', 'calloc', 'new ', 'alloc')):
        preconditions.append('allocate memory buffer')
    if 'fopen' in text_lower or 'open(' in text_lower:
        preconditions.append('create/open input file')
    if any(kw in text_lower for kw in ('socket', 'connect', 'listen', 'bind')):
        preconditions.append('establish network connection')
    if any(kw in text_lower for kw in ('keygen', 'genkey', 'generate.*key', 'create.*key')):
        preconditions.append('generate cryptographic key')
    if preconditions:
        result['preconditions'] = preconditions

    # ── Exploit pattern: from CWE description or summary ──
    if cve_summary:
        _SUMMARY_PATTERNS = [
            (r'heap.{0,20}buffer.{0,20}overflow', 'heap buffer overflow'),
            (r'stack.{0,20}buffer.{0,20}overflow', 'stack buffer overflow'),
            (r'use.after.free', 'use-after-free'),
            (r'double.free', 'double-free'),
            (r'integer.{0,10}overflow', 'integer overflow'),
            (r'null.pointer', 'null pointer dereference'),
            (r'out.of.bounds.{0,10}read', 'out-of-bounds read'),
            (r'out.of.bounds.{0,10}write', 'out-of-bounds write'),
            (r'path.traversal', 'path traversal'),
            (r'sql.injection', 'SQL injection'),
            (r'command.injection', 'command injection'),
            (r'format.string', 'format string'),
            (r'denial.of.service|resource.exhaustion', 'resource exhaustion / denial of service'),
        ]
        for pat, label in _SUMMARY_PATTERNS:
            if re.search(pat, cve_summary, re.IGNORECASE):
                fn = result.get('target_function', '')
                result['exploit_pattern'] = f'{label} in {fn}' if fn else label
                break

    return result


def _static_analysis_is_sparse(analysis: Dict[str, Any]) -> bool:
    """Return True when static analysis didn't find enough useful fields."""
    filled = sum(1 for v in analysis.values() if v)
    return filled < 3


_POC_ANALYSIS_PROMPT = """\
You are a security researcher. Analyze the following PoC / exploit code and extract structured information as compact JSON.

CVE: {cve_id}
Summary: {summary}

PoC code (truncated to 4000 chars):
```
{poc_snippet}
```

Respond with ONLY a JSON object — no explanation, no markdown fences. Use null for unknown fields.
{{
  "trigger_input": "<the input, payload, or argument that triggers the bug>",
  "preconditions": ["<setup step 1>", "<setup step 2>"],
  "observable_evidence": ["<what output or behavior confirms exploitation>"],
  "target_function": "<the vulnerable function or command entrypoint>",
  "exploit_pattern": "<brief exploit technique, e.g. heap buffer overflow via oversized JSON key>"
}}"""


def _llm_analyze_poc(
    poc_text: str,
    cve_id: str,
    cve_summary: str,
    llm_invoke,
) -> Dict[str, Any]:
    """Ask the LLM to extract structured exploit intelligence from PoC text."""
    snippet = poc_text[:4000]
    prompt = _POC_ANALYSIS_PROMPT.format(
        cve_id=cve_id or 'unknown',
        summary=cve_summary[:300] if cve_summary else 'n/a',
        poc_snippet=snippet,
    )
    raw = llm_invoke(prompt)
    if not raw:
        return {}

    # Extract JSON from the response — be tolerant of markdown fences
    json_str = raw.strip()
    m = re.search(r'\{[\s\S]+\}', json_str)
    if m:
        json_str = m.group(0)
    try:
        data = json.loads(json_str)
        # Normalise: filter nulls, ensure lists are lists
        result = {}
        for k, v in data.items():
            if v is None:
                continue
            if k in ('preconditions', 'observable_evidence') and isinstance(v, str):
                v = [v]
            result[k] = v
        return result
    except (json.JSONDecodeError, ValueError) as e:
        logger.debug('LLM PoC analysis JSON parse failed: %s | raw=%s', e, raw[:200])
        return {}

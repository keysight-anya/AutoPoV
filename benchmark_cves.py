#!/usr/bin/env python3
"""CVE Benchmark — validate AutoPoV against known-vulnerable repos.

Usage:
    python3 benchmark_cves.py [--cve CVE-ID] [--dry-run]

Each entry in CVE_BENCHMARKS defines a real CVE with:
  - repo_url: git clone URL of the vulnerable project
  - commit: the exact vulnerable commit hash (pre-patch)
  - cve_id: CVE identifier
  - cwe_type: expected vulnerability class
  - filepath: path within repo where the bug lives (hint)
  - expected_proof_type: what proof_type the system should select
  - description: human-readable description for the report

The script clones each repo at the vulnerable commit, submits it to the
AutoPoV API, polls until complete, then reports confirmed vs missed.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional

# ── Known-vulnerable CVE test cases ────────────────────────────────────────
# Each entry is a ground-truth case with a specific vulnerable commit.
# The system must independently identify and confirm the vulnerability.
CVE_BENCHMARKS: List[Dict] = [
    {
        "cve_id": "CVE-2021-3048",
        "cwe_type": "CWE-120",
        "repo_url": "https://github.com/libjpeg-turbo/libjpeg-turbo.git",
        "commit": "2.0.6",
        "filepath": "jdcoefct.c",
        "expected_proof_type": "crash_signal",
        "description": "libjpeg-turbo buffer overflow in jdcoefct.c",
    },
    {
        "cve_id": "CVE-2019-17595",
        "cwe_type": "CWE-125",
        "repo_url": "https://github.com/openssh/openssh-portable.git",
        "commit": "V_8_1_P1",
        "filepath": "ncurses",
        "expected_proof_type": "crash_signal",
        "description": "ncurses out-of-bounds read",
    },
    {
        "cve_id": "CVE-2022-1586",
        "cwe_type": "CWE-125",
        "repo_url": "https://github.com/PCRE2Project/pcre2.git",
        "commit": "3ee2b4d",
        "filepath": "src/pcre2_match.c",
        "expected_proof_type": "crash_signal",
        "description": "PCRE2 out-of-bounds read in match.c",
    },
    {
        "cve_id": "CVE-2021-3156",
        "cwe_type": "CWE-122",
        "repo_url": "https://github.com/sudo-project/sudo.git",
        "commit": "SUDO_1_9_4p2",
        "filepath": "src/set_perms.c",
        "expected_proof_type": "crash_signal",
        "description": "sudo heap buffer overflow (Baron Samedit)",
    },
    {
        "cve_id": "CVE-2018-20685",
        "cwe_type": "CWE-78",
        "repo_url": "https://github.com/openssh/openssh-portable.git",
        "commit": "V_7_9_P1",
        "filepath": "scp.c",
        "expected_proof_type": "command_injection",
        "description": "OpenSSH scp command injection via crafted filename",
    },
]

API_BASE = os.environ.get("AUTOPOV_API_BASE", "http://localhost:8000")
API_KEY = os.environ.get("AUTOPOV_API_KEY", "")


def api_headers():
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["Authorization"] = f"Bearer {API_KEY}"
    return h


def clone_repo(repo_url: str, commit: str, dest: str) -> bool:
    try:
        subprocess.run(["git", "clone", "--depth=1", f"--branch={commit}", repo_url, dest],
                       check=True, capture_output=True, timeout=120)
        return True
    except subprocess.CalledProcessError:
        # Try full clone then checkout
        try:
            subprocess.run(["git", "clone", repo_url, dest], check=True, capture_output=True, timeout=300)
            subprocess.run(["git", "-C", dest, "checkout", commit], check=True, capture_output=True)
            return True
        except Exception as e:
            print(f"  Clone failed: {e}")
            return False


def submit_scan(codebase_path: str, cve: Dict) -> Optional[str]:
    import urllib.request
    data = json.dumps({
        "codebase_path": codebase_path,
        "scan_label": f"benchmark-{cve['cve_id']}",
        "model_name": os.environ.get("AUTOPOV_MODEL", ""),
    }).encode()
    try:
        req = urllib.request.Request(f"{API_BASE}/api/scans", data=data, headers=api_headers(), method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
            return result.get("scan_id")
    except Exception as e:
        print(f"  Submit failed: {e}")
        return None


def poll_scan(scan_id: str, timeout_s: int = 600) -> Optional[Dict]:
    import urllib.request
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            req = urllib.request.Request(f"{API_BASE}/api/scans/{scan_id}", headers=api_headers())
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                status = result.get("status", "")
                if status in ("completed", "failed", "error"):
                    return result
                print(f"  [{scan_id[:8]}] status={status} ...")
        except Exception as e:
            print(f"  Poll error: {e}")
        time.sleep(15)
    return None


def check_cve_confirmed(scan_result: Dict, cve: Dict) -> Dict:
    findings = scan_result.get("findings") or []
    confirmed = [f for f in findings if f.get("final_status") == "confirmed"]
    cwe_match = [f for f in confirmed if str(f.get("cwe_type") or "").upper() == cve["cwe_type"].upper()]
    file_match = [f for f in confirmed if cve.get("filepath", "").lower() in str(f.get("filepath") or "").lower()]
    return {
        "total_findings": len(findings),
        "confirmed_count": len(confirmed),
        "cwe_matched": len(cwe_match) > 0,
        "file_matched": len(file_match) > 0,
        "proved": len(cwe_match) > 0 or len(file_match) > 0,
        "confidence": (confirmed[0].get("confirmation_confidence") or "unknown") if confirmed else "none",
    }


def run_benchmark(filter_cve: Optional[str] = None, dry_run: bool = False):
    cases = CVE_BENCHMARKS
    if filter_cve:
        cases = [c for c in cases if c["cve_id"] == filter_cve]
    if not cases:
        print("No matching CVE cases found.")
        return

    results = []
    with tempfile.TemporaryDirectory(prefix="autopov_bench_") as workdir:
        for cve in cases:
            print(f"\n{'='*60}")
            print(f"Testing {cve['cve_id']}: {cve['description']}")
            if dry_run:
                print("  [dry-run] skipping execution")
                results.append({"cve_id": cve["cve_id"], "proved": None, "dry_run": True})
                continue

            repo_dir = os.path.join(workdir, cve["cve_id"].replace("-", "_"))
            print(f"  Cloning {cve['repo_url']} @ {cve['commit']} ...")
            if not clone_repo(cve["repo_url"], cve["commit"], repo_dir):
                results.append({"cve_id": cve["cve_id"], "proved": False, "error": "clone_failed"})
                continue

            print(f"  Submitting scan ...")
            scan_id = submit_scan(repo_dir, cve)
            if not scan_id:
                results.append({"cve_id": cve["cve_id"], "proved": False, "error": "submit_failed"})
                continue

            print(f"  Polling scan {scan_id} ...")
            scan_result = poll_scan(scan_id)
            if not scan_result:
                results.append({"cve_id": cve["cve_id"], "proved": False, "error": "timeout"})
                continue

            check = check_cve_confirmed(scan_result, cve)
            print(f"  Result: proved={check['proved']} confirmed={check['confirmed_count']} "
                  f"cwe_match={check['cwe_matched']} confidence={check['confidence']}")
            results.append({
                "cve_id": cve["cve_id"],
                "cwe_type": cve["cwe_type"],
                "proved": check["proved"],
                "check": check,
            })

    # Summary
    print(f"\n{'='*60}")
    print("BENCHMARK RESULTS")
    print(f"{'='*60}")
    tested = [r for r in results if r.get("proved") is not None and not r.get("dry_run")]
    proved = [r for r in tested if r.get("proved")]
    print(f"Total tested: {len(tested)}")
    print(f"Proved:       {len(proved)}")
    print(f"Missed:       {len(tested) - len(proved)}")
    if tested:
        print(f"True positive rate: {len(proved)/len(tested)*100:.1f}%")
    print()
    for r in results:
        icon = "v" if r.get("proved") else ("~" if r.get("dry_run") else "x")
        print(f"  {icon} {r['cve_id']} {r.get('error', '')}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AutoPoV CVE Benchmark")
    parser.add_argument("--cve", help="Test only this CVE (e.g. CVE-2021-3156)")
    parser.add_argument("--dry-run", action="store_true", help="List cases without running")
    args = parser.parse_args()
    run_benchmark(filter_cve=args.cve, dry_run=args.dry_run)

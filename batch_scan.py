"""
batch_scan.py — Strictly sequential offline-model scan runner.

Rules:
  - ONE scan at a time, start to finish, before moving to the next.
  - If a scan times out (exceeds --timeout) it is recorded as 'timeout' and
    the batch CONTINUES to the next scan (skip-and-continue behaviour).
  - If the backend is unreachable after repeated retries, the run STOPS.
  - Use --resume to skip scans already recorded as completed or timed-out.
  - State is saved after every scan so --resume works correctly.

Usage:
    python3 batch_scan.py --key <KEY>                    # all repos, round-robin models
    python3 batch_scan.py --key <KEY> --model qwen3      # all repos, single model
    python3 batch_scan.py --key <KEY> --mode all         # each repo x every model
    python3 batch_scan.py --key <KEY> --resume           # continue from last save
    python3 batch_scan.py --dry-run                      # print plan, no API calls

    --api     BASE_URL  (default: http://localhost:8000)
    --key     API_KEY   (required)
    --poll    SECONDS   (default: 30)
    --timeout SECONDS   (default: 3600  = 1 hour per scan)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional
from urllib import request as urllib_request
from urllib.error import URLError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OFFLINE_MODELS: List[str] = [
    "qwen3",
    "qwen3.6",
    "glm-4.7-flash",
    "llama4",
]

REPOS: List[str] = [
    # ── C/C++ targets with confirmed CVEs (validated + 25k-50k LOC range) ──────
    "https://github.com/skeeto/enchive",              # CWE-120/786 — validated anchor
    "https://github.com/libexpat/libexpat",           # CVE-2021-45960, CVE-2022-40674 — heap overflow
    "https://github.com/DaveGamble/cJSON",            # CVE-2019-11835 — buffer overflow
    "https://github.com/the-tcpdump-group/tcpdump",  # CVE-2020-8037 — heap overread
    "https://github.com/tats/w3m",                    # CVE-2022-38223 — stack overflow
    "https://github.com/libarchive/libarchive",       # CVE-2022-26280 — path traversal
    "https://github.com/leethomason/tinyxml2",        # CVE-2021-42260 — infinite loop/DoS
    "https://github.com/curl/curl",                   # CVE-2023-23914 — use-after-free
    "https://github.com/the-tcpdump-group/libpcap",  # CVE-2019-15165 — buffer overflow
    "https://github.com/Matthias-Wandel/jhead",       # CWE-120/125 — validated anchor
    # ── Existing targets ──────────────────────────────────────────────────────
    "https://github.com/jorisvink/kore",
    "https://github.com/madler/zlib",
    "https://github.com/jgarzik/picocoin",
    "https://github.com/libusb/libusb",
    "https://github.com/google/leveldb",
    "https://github.com/chenshuo/muduo",
    "https://github.com/google/re2",
    "https://github.com/jankotek/mapdb",
    "https://github.com/KaTeX/KaTeX",
    "https://github.com/axios/axios",
    "https://github.com/markedjs/marked",
    "https://github.com/expressjs/express",
    "https://github.com/cherrypy/cherrypy",
    "https://github.com/pallets/flask",
    "https://github.com/Supervisor/supervisor",
    "https://github.com/httpie/httpie",
]

DEFAULT_API   = "http://localhost:8000"
DEFAULT_POLL  = 30
DEFAULT_TIMEOUT = 4600   # 1 hour per scan; offline models are slow on large repos
DEFAULT_STATE   = "batch_offline_state.json"

TERMINAL_STATUSES = {"completed", "failed", "cancelled", "stopped"}

# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _api(base: str, method: str, path: str, api_key: str, body: Optional[Dict] = None) -> Dict[str, Any]:
    url = base.rstrip("/") + path
    data = json.dumps(body).encode() if body else None
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    req = urllib_request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except URLError as exc:
        raise RuntimeError(f"API call failed [{method} {url}]: {exc}") from exc


def submit_scan(base: str, api_key: str, repo_url: str, model: str) -> str:
    result = _api(base, "POST", "/api/scan/git", api_key, {"url": repo_url, "model": model})
    scan_id = result.get("scan_id")
    if not scan_id:
        raise RuntimeError(f"No scan_id in response: {result}")
    return scan_id


def get_status(base: str, api_key: str, scan_id: str) -> Dict[str, Any]:
    return _api(base, "GET", f"/api/scan/{scan_id}", api_key)


def cancel_scan(base: str, api_key: str, scan_id: str) -> None:
    """Cancel a running scan on the backend so it does not stay active forever."""
    try:
        _api(base, "POST", f"/api/scan/{scan_id}/cancel", api_key)
        print(f"    [cancelled] {scan_id}")
    except Exception as exc:
        print(f"    [warn] Failed to cancel scan {scan_id}: {exc}")


def poll_until_done(base: str, api_key: str, scan_id: str, poll: int, timeout: int, label: str) -> Dict[str, Any]:
    """Block until scan reaches a terminal status or timeout.  Returns final status dict."""
    elapsed = 0
    consecutive_errors = 0
    _last_status = None
    _stuck_at_100_count = 0
    _STUCK_AT_100_LIMIT = 5
    while elapsed < timeout:
        try:
            info = get_status(base, api_key, scan_id)
            consecutive_errors = 0
        except RuntimeError as exc:
            consecutive_errors += 1
            print(f"    [warn] status check failed ({consecutive_errors}): {exc}")
            if consecutive_errors >= 5:
                print(f"    [ERROR] 5 consecutive status-check failures — backend may be down.")
                cancel_scan(base, api_key, scan_id)
                return {"status": "error", "scan_id": scan_id,
                        "error": "consecutive status-check failures"}
            time.sleep(poll)
            elapsed += poll
            continue

        status   = info.get("status", "unknown")
        progress = info.get("progress", 0)
        result   = info.get("result") or {}
        findings = result.get("total_findings", info.get("findings_count", "?"))
        print(f"    [{elapsed:>5}s]  {label}  status={status}  progress={progress}%  findings={findings}")

        if status in TERMINAL_STATUSES:
            return info

        # Safety: if stuck at 100% with same non-terminal status, treat as completed
        if progress >= 100 and status == _last_status:
            _stuck_at_100_count += 1
            if _stuck_at_100_count >= _STUCK_AT_100_LIMIT:
                print(f"    [warn] Scan stuck at {status}/100% for {_stuck_at_100_count} polls — treating as completed")
                info["status"] = "completed"
                return info
        else:
            _stuck_at_100_count = 0
        _last_status = status

        time.sleep(poll)
        elapsed += poll

    print(f"    [TIMEOUT] {label} did not finish within {timeout}s")
    cancel_scan(base, api_key, scan_id)
    return {"status": "timeout", "scan_id": scan_id}


# ---------------------------------------------------------------------------
# State persistence (resume support)
# ---------------------------------------------------------------------------

def load_state(state_file: str) -> Dict[str, Any]:
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_state(state_file: str, data: Dict[str, Any]) -> None:
    try:
        with open(state_file, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as exc:
        print(f"    [warn] Could not save state: {exc}")

# ---------------------------------------------------------------------------
# Build scan plan
# ---------------------------------------------------------------------------

def build_plan(repos: List[str], models: List[str], mode: str) -> List[Dict[str, str]]:
    """
    mode='roundrobin'  — each repo gets one model, cycling through models list
    mode='all'         — each repo is scanned by EVERY model
    mode='single'      — models list has exactly one entry; all repos use it
    """
    plan: List[Dict[str, str]] = []
    if mode == "all":
        for repo in repos:
            for model in models:
                plan.append({"repo": repo, "model": model})
    elif mode in ("roundrobin", "single"):
        for i, repo in enumerate(repos):
            model = models[i % len(models)]
            plan.append({"repo": repo, "model": model})
    return plan

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="AutoPoV batch offline scan runner")
    parser.add_argument("--repos",   default=None, nargs="+",
                        help="Override repo list. Pass one or more full GitHub URLs.")
    parser.add_argument("--api",     default=DEFAULT_API,     help="Backend base URL")
    parser.add_argument("--poll",    type=int, default=DEFAULT_POLL,    help="Poll interval (s)")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-scan timeout (s, default 3600)")
    parser.add_argument("--key",     default=None, help="API key; generate with: docker exec autopov-backend python3 /app/generate_key.py")
    parser.add_argument("--model",   default=None, help="Force a single model for all scans")
    parser.add_argument("--mode",    default="roundrobin",
                        choices=["roundrobin", "all"],
                        help="roundrobin: one model per repo cycling; all: every model on every repo")
    parser.add_argument("--resume",  action="store_true", help="Skip scans already recorded as completed")
    parser.add_argument("--state",   default=DEFAULT_STATE, help="State file for resume support")
    parser.add_argument("--dry-run", action="store_true", help="Print plan only, no API calls")
    args = parser.parse_args()

    repos  = args.repos if args.repos else REPOS
    models = [args.model] if args.model else OFFLINE_MODELS
    mode   = "single" if args.model else args.mode
    plan   = build_plan(repos, models, mode)

    # Print plan summary
    print(f"\n{'='*70}")
    print(f"  AutoPoV Batch Scan (OFFLINE) — {len(plan)} scans queued")
    print(f"  Models  : {', '.join(models)}")
    print(f"  Mode    : {mode}")
    print(f"  API     : {args.api}")
    print(f"  Poll    : {args.poll}s   Timeout: {args.timeout}s per scan")
    print(f"  State   : {args.state}")
    print(f"{'='*70}")
    for i, entry in enumerate(plan):
        repo_short = entry['repo'].replace("https://github.com/", "")
        print(f"  [{i+1:>2}]  {entry['model']:<20}  {repo_short}")
    print(f"{'='*70}\n")

    if args.dry_run:
        print("[dry-run] Exiting without submitting any scans.")
        return 0

    api_key = args.key
    if not api_key:
        print("[ERROR] --key is required. Generate one with:")
        print("        docker exec autopov-backend python3 /app/generate_key.py")
        return 1

    # ---- Resume support ----
    state_data = {}
    completed_set: set = set()
    if args.resume:
        state_data = load_state(args.state)
        for r in state_data.get("results", []):
            if r.get("status") in {"completed", "failed", "cancelled", "stopped", "timeout"}:
                completed_set.add((r["repo"], r["model"]))
        if completed_set:
            print(f"  Resuming — {len(completed_set)} completed/timed-out scans will be skipped.\n")

    results: List[Dict[str, Any]] = list(state_data.get("results", []))
    stop_reason: Optional[str] = None
    stopped_at: Optional[int] = None
    timeout_scans: List[str] = []

    # ---- Run scans — strictly one at a time, skip timeouts, stop on backend errors ----
    for i, entry in enumerate(plan):
        repo  = entry["repo"]
        model = entry["model"]
        key   = (repo, model)
        repo_short = repo.replace("https://github.com/", "")
        label = f"{repo_short} / {model}"

        if key in completed_set:
            print(f"[{i+1}/{len(plan)}]  SKIP (already completed/timed-out): {label}")
            continue

        print(f"\n[{i+1}/{len(plan)}]  Submitting: {label}")
        try:
            scan_id = submit_scan(args.api, api_key, repo, model)
        except RuntimeError as exc:
            print(f"    [ERROR] Failed to submit scan: {exc}")
            results.append({"repo": repo, "model": model, "scan_id": None,
                            "status": "submit_failed"})
            save_state(args.state, {"results": results})
            stop_reason = f"Scan submission failed for {label}: {exc}"
            stopped_at = i + 1
            print(f"\n  ╔══ STOPPED — SUBMISSION FAILURE ════════════════════════════════╗")
            print(f"  ║  {stop_reason}")
            print(f"  ║  Check backend logs. Re-run with --resume after fixing.")
            print(f"  ╚════════════════════════════════════════════════════════════════╝\n")
            break

        print(f"    scan_id = {scan_id}")

        # ── Wait for this scan to fully complete before proceeding ──
        final  = poll_until_done(args.api, api_key, scan_id, args.poll, args.timeout, label)
        status = final.get("status", "unknown")

        result_dict   = final.get("result") or {}
        findings_list = final.get("findings") or []
        findings  = result_dict.get("total_findings",
                     result_dict.get("findings_count",
                     len(findings_list) if findings_list else "?"))
        confirmed = result_dict.get("confirmed_vulns",
                     result_dict.get("proven",
                     result_dict.get("confirmed", "?")))
        failed_cnt = result_dict.get("failed", result_dict.get("failed_count", "?"))

        results.append({
            "repo": repo, "model": model, "scan_id": scan_id,
            "status": status, "total_findings": findings,
            "confirmed": confirmed, "failed": failed_cnt,
        })
        save_state(args.state, {"results": results})
        print(f"    DONE  status={status}  findings={findings}  confirmed={confirmed}  failed={failed_cnt}")

        # ── On timeout — record, warn, and continue to next scan ──
        if status == "timeout":
            timeout_scans.append(label)
            print(f"  ⚠️  [{i+1}/{len(plan)}] TIMEOUT (skipping): {label}")
            print(f"       scan_id: {scan_id} — may still be running in backend")
            continue

        # ── Stop on backend error ──
        if status == "error":
            stop_reason = f"Backend error during scan: {label}. Check backend logs."
            stopped_at = i + 1
            print(f"\n  ╔══ STOPPED — BACKEND ERROR ══════════════════════════════════════╗")
            print(f"  ║  {stop_reason}")
            print(f"  ╚═════════════════════════════════════════════════════════════════╝\n")
            break

    # Final summary table
    print(f"\n{'='*70}")
    print("  BATCH COMPLETE — Summary")
    print(f"{'='*70}")
    print(f"  {'Repo':<35}  {'Model':<20}  {'Status':<12}  {'F':<4}  {'OK':<4}  {'Fail'}")
    print(f"  {'-'*35}  {'-'*20}  {'-'*12}  {'-'*4}  {'-'*4}  ----")
    for r in results:
        rs = r["repo"].replace("https://github.com/", "")
        print(f"  {rs:<35}  {r['model']:<20}  {r['status']:<12}  "
              f"{str(r.get('total_findings','?')):<4}  {str(r.get('confirmed','?')):<4}  {r.get('failed','?')}")
    print(f"{'='*70}")
    if stop_reason:
        print(f"\n  ❌  Run stopped early at scan {stopped_at}/{len(plan)}.")
        print(f"  Reason: {stop_reason}")
        print(f"  Re-run with --resume once the issue is resolved.")
    elif timeout_scans:
        print(f"\n  ⚠️  All {len(plan)} scans attempted. {len(timeout_scans)} timed out:")
        for ts in timeout_scans:
            print(f"       - {ts}")
        print(f"  Re-run with --resume to retry timed-out scans.")
    else:
        print(f"\n  ✅  All {len(plan)} scans completed successfully.")
    print(f"{'='*70}\n")

    return 0 if not stop_reason else 2


if __name__ == "__main__":
    sys.exit(main())

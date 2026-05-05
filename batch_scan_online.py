"""
batch_scan_online.py — Strictly sequential online-model scan runner with balance tracking.

Rules:
  - ONE scan at a time, start to finish, before moving to the next.
  - Balance is checked BEFORE each scan.  If balance < --min-balance the run
    STOPS immediately with a clear explanation — no partial scan is started.
  - If a scan times out (exceeds --timeout) it is recorded as 'timeout' and
    the run STOPS — do not silently skip to the next repo.
  - The state file records every completed scan so --resume can skip them.

Usage:
    python3 batch_scan_online.py --key <autopov_key>
    python3 batch_scan_online.py --key <autopov_key> --mode all
    python3 batch_scan_online.py --key <autopov_key> --resume
    python3 batch_scan_online.py --dry-run

    --api         BASE_URL      (default: http://localhost:8000)
    --key         AUTOPOV_KEY   AutoPoV API key (required)
    --model       MODEL_NAME    Force a single online model
    --mode        roundrobin|all  (default: roundrobin)
    --poll        SECONDS       (default: 30)
    --timeout     SECONDS       (default: 7200)  2 h — large repos can take a while
    --resume                    Resume from saved state file
    --state       FILE          State file path (default: batch_online_state.json)
    --min-balance FLOAT         Stop when balance drops below this USD (default: 1.00)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional
from urllib import request as urllib_request
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ONLINE_MODELS: List[str] = [
    "openai/gpt-5.2",
    "anthropic/claude-opus-4.6",
]

REPOS: List[str] = [
    # ── C/C++ targets with confirmed CVEs (validated + 25k-50k LOC range) ──────
    "https://github.com/skeeto/enchive",              # CWE-120/786 — validated anchor
    "https://github.com/Matthias-Wandel/jhead",       # CWE-120/125 — validated anchor
    "https://github.com/libexpat/libexpat",           # CVE-2021-45960, CVE-2022-40674 — heap overflow
    "https://github.com/DaveGamble/cJSON",            # CVE-2019-11835 — buffer overflow
    "https://github.com/the-tcpdump-group/tcpdump",  # CVE-2020-8037 — heap overread
    "https://github.com/tats/w3m",                    # CVE-2022-38223 — stack overflow
    "https://github.com/libarchive/libarchive",       # CVE-2022-26280 — path traversal
    "https://github.com/leethomason/tinyxml2",        # CVE-2021-42260 — infinite loop/DoS
    "https://github.com/curl/curl",                   # CVE-2023-23914 — use-after-free
    "https://github.com/the-tcpdump-group/libpcap",  # CVE-2019-15165 — buffer overflow
    # ── Existing targets ──────────────────────────────────────────────────────
    "https://github.com/jorisvink/kore",
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

DEFAULT_API      = "http://localhost:8000"
DEFAULT_POLL     = 30
DEFAULT_TIMEOUT  = 7200   # 2 hours per scan — large C repos with 100+ findings need it
DEFAULT_STATE    = "batch_online_state.json"
DEFAULT_MIN_BAL  = 1.00   # stop if balance drops below $1.00 (not worth starting a scan)

TERMINAL_STATUSES = {"completed", "failed", "cancelled", "stopped"}


# ---------------------------------------------------------------------------
# API helpers
# ---------------------------------------------------------------------------

def _api(base: str, method: str, path: str, api_key: str,
         body: Optional[Dict] = None) -> Dict[str, Any]:
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
    except HTTPError as exc:
        body_text = ""
        try:
            body_text = exc.read().decode()[:200]
        except Exception:
            pass
        raise RuntimeError(
            f"API call failed [{method} {url}]: HTTP {exc.code} — {body_text}"
        ) from exc
    except URLError as exc:
        raise RuntimeError(f"API call failed [{method} {url}]: {exc}") from exc


def get_balance(base: str, api_key: str) -> Optional[float]:
    """Fetch OpenRouter credit balance via the backend /api/balance endpoint."""
    try:
        resp = _api(base, "GET", "/api/balance", api_key)
        bal = resp.get("balance_usd")
        if bal is not None:
            return float(bal)
        err = resp.get("error", "")
        if err:
            print(f"    [warn] Balance check: {err}")
        return None
    except RuntimeError as exc:
        print(f"    [warn] Could not fetch balance: {exc}")
        return None


def submit_scan(base: str, api_key: str, repo_url: str, model: str) -> str:
    result = _api(base, "POST", "/api/scan/git", api_key,
                  {"url": repo_url, "model": model})
    scan_id = result.get("scan_id")
    if not scan_id:
        raise RuntimeError(f"No scan_id in response: {result}")
    return scan_id


def get_status(base: str, api_key: str, scan_id: str) -> Dict[str, Any]:
    return _api(base, "GET", f"/api/scan/{scan_id}", api_key)


def poll_until_done(
    base: str, api_key: str, scan_id: str, poll: int, timeout: int, label: str
) -> Dict[str, Any]:
    """Poll until the scan reaches a terminal status or the timeout expires.

    Returns the final status dict.  On timeout, returns {"status": "timeout"}.
    The caller is responsible for deciding whether to continue or stop.
    """
    elapsed = 0
    consecutive_errors = 0
    while elapsed < timeout:
        try:
            info = get_status(base, api_key, scan_id)
            consecutive_errors = 0
        except RuntimeError as exc:
            consecutive_errors += 1
            print(f"    [warn] status check failed ({consecutive_errors}): {exc}")
            if consecutive_errors >= 5:
                print(f"    [ERROR] 5 consecutive status-check failures — backend may be down.")
                return {"status": "error", "scan_id": scan_id,
                        "error": "consecutive status-check failures"}
            time.sleep(poll)
            elapsed += poll
            continue

        status   = info.get("status", "unknown")
        result   = info.get("result") or {}
        findings = result.get("total_findings", info.get("findings_count", "?"))
        progress = info.get("progress", 0)
        cost_so_far = float(result.get("total_cost_usd") or 0.0)
        print(f"    [{elapsed:>5}s]  {label}  "
              f"status={status}  progress={progress}%  "
              f"findings={findings}  cost=${cost_so_far:.4f}")

        if status in TERMINAL_STATUSES:
            return info

        time.sleep(poll)
        elapsed += poll

    print(f"    [TIMEOUT] {label} did not finish within {timeout}s")
    return {"status": "timeout", "scan_id": scan_id}


# ---------------------------------------------------------------------------
# Plan builder
# ---------------------------------------------------------------------------

def build_plan(repos: List[str], models: List[str], mode: str) -> List[Dict[str, str]]:
    plan: List[Dict[str, str]] = []
    if mode == "all":
        for repo in repos:
            for model in models:
                plan.append({"repo": repo, "model": model})
    else:  # roundrobin / single
        for i, repo in enumerate(repos):
            model = models[i % len(models)]
            plan.append({"repo": repo, "model": model})
    return plan


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
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="AutoPoV batch online scan runner with balance tracking"
    )
    parser.add_argument("--api",         default=DEFAULT_API,
                        help="Backend base URL")
    parser.add_argument("--key",         default=None,
                        help="AutoPoV API key")
    parser.add_argument("--model",       default=None,
                        help="Force a single online model")
    parser.add_argument("--mode",        default="roundrobin",
                        choices=["roundrobin", "all"])
    parser.add_argument("--poll",        type=int, default=DEFAULT_POLL,
                        help="Poll interval in seconds")
    parser.add_argument("--timeout",     type=int, default=DEFAULT_TIMEOUT,
                        help="Per-scan timeout in seconds (default: 7200 = 2h)")
    parser.add_argument("--resume",      action="store_true",
                        help="Resume: skip scans already recorded as completed")
    parser.add_argument("--state",       default=DEFAULT_STATE,
                        help="State file for resume support")
    parser.add_argument("--min-balance", type=float, default=DEFAULT_MIN_BAL,
                        help="Stop when OpenRouter balance drops below this USD (default: $1.00)")
    parser.add_argument("--dry-run",     action="store_true",
                        help="Print plan only, no API calls")
    args = parser.parse_args()

    models = [args.model] if args.model else ONLINE_MODELS
    mode   = "single" if args.model else args.mode
    plan   = build_plan(REPOS, models, mode)

    # ---- Print plan ----
    print(f"\n{'='*70}")
    print(f"  AutoPoV Batch Scan (ONLINE) — {len(plan)} scans queued")
    print(f"  Models  : {', '.join(models)}")
    print(f"  Mode    : {mode}")
    print(f"  API     : {args.api}")
    print(f"  Poll    : {args.poll}s   Timeout: {args.timeout}s")
    print(f"  Min bal : ${args.min_balance:.2f}   State: {args.state}")
    print(f"{'='*70}")
    for i, entry in enumerate(plan):
        repo_short = entry["repo"].replace("https://github.com/", "")
        print(f"  [{i+1:>2}]  {entry['model']:<35}  {repo_short}")
    print(f"{'='*70}\n")

    if args.dry_run:
        print("[dry-run] Exiting without submitting any scans.")
        return 0

    if not args.key:
        print("[ERROR] --key is required (AutoPoV API key).")
        return 1

    # ---- Show initial balance ----
    initial_balance = get_balance(args.api, args.key)
    if initial_balance is not None:
        print(f"  OpenRouter balance: ${initial_balance:.4f}\n")
    else:
        print("  [warn] Could not determine OpenRouter balance\n")

    # ---- Resume support ----
    state_data = {}
    completed_set: set = set()
    if args.resume:
        state_data = load_state(args.state)
        for r in state_data.get("results", []):
            # Only skip scans that fully completed — not timeouts or errors
            if r.get("status") in {"completed", "failed", "cancelled", "stopped"}:
                completed_set.add((r["repo"], r["model"]))
        if completed_set:
            print(f"  Resuming — {len(completed_set)} completed scans will be skipped.\n")

    results: List[Dict[str, Any]] = list(state_data.get("results", []))
    total_cost = float(state_data.get("total_cost_usd", 0.0))
    stop_reason: Optional[str] = None
    stopped_at: Optional[int] = None

    # ---- Run scans — strictly one at a time, full stop on any problem ----
    for i, entry in enumerate(plan):
        repo  = entry["repo"]
        model = entry["model"]
        key   = (repo, model)
        repo_short = repo.replace("https://github.com/", "")
        label = f"{repo_short} / {model}"

        if key in completed_set:
            print(f"[{i+1}/{len(plan)}]  SKIP (already completed): {label}")
            continue

        # ── Balance check — MUST pass before we start any scan ──────────────
        print(f"\n[{i+1}/{len(plan)}]  Checking balance before: {label}")
        bal_before = get_balance(args.api, args.key)

        if bal_before is None:
            stop_reason = (
                "Could not read OpenRouter balance. Backend may be unreachable or "
                "the API key may be invalid. Not safe to proceed."
            )
            stopped_at = i + 1
            print(f"\n  ╔══ STOPPED ══════════════════════════════════════════════════════╗")
            print(f"  ║  {stop_reason}")
            print(f"  ║  Stopped at scan [{i+1}/{len(plan)}]: {label}")
            print(f"  ╚════════════════════════════════════════════════════════════════╝\n")
            break

        print(f"  OpenRouter balance: ${bal_before:.4f}  (minimum required: ${args.min_balance:.2f})")

        if bal_before < args.min_balance:
            stop_reason = (
                f"Insufficient OpenRouter credits: balance ${bal_before:.4f} is below "
                f"the minimum ${args.min_balance:.2f} required to start a scan.\n"
                f"  Fund your OpenRouter account at https://openrouter.ai/settings/credits\n"
                f"  then re-run with --resume to continue from this point."
            )
            stopped_at = i + 1
            print(f"\n  ╔══ STOPPED — INSUFFICIENT CREDITS ══════════════════════════════╗")
            print(f"  ║  Balance:  ${bal_before:.4f}")
            print(f"  ║  Required: ${args.min_balance:.2f} minimum to start scan [{i+1}/{len(plan)}]")
            print(f"  ║  Repo:     {label}")
            print(f"  ║")
            print(f"  ║  Add credits at: https://openrouter.ai/settings/credits")
            print(f"  ║  Then re-run:    python3 batch_scan_online.py --key <KEY> --resume")
            print(f"  ╚════════════════════════════════════════════════════════════════╝\n")
            break

        # ── Submit scan ──────────────────────────────────────────────────────
        print(f"  Submitting: {label}")
        try:
            scan_id = submit_scan(args.api, args.key, repo, model)
        except RuntimeError as exc:
            print(f"    [ERROR] Failed to submit scan: {exc}")
            results.append({
                "repo": repo, "model": model, "scan_id": None,
                "status": "submit_failed", "cost_usd": 0.0,
            })
            save_state(args.state, {"results": results, "total_cost_usd": total_cost})
            stop_reason = f"Scan submission failed for {label}: {exc}"
            stopped_at = i + 1
            print(f"\n  ╔══ STOPPED — SUBMISSION FAILURE ════════════════════════════════╗")
            print(f"  ║  {stop_reason}")
            print(f"  ║  Check backend logs. Re-run with --resume after fixing.")
            print(f"  ╚════════════════════════════════════════════════════════════════╝\n")
            break

        print(f"    scan_id = {scan_id}")

        # ── Wait for this scan to fully complete ─────────────────────────────
        final  = poll_until_done(args.api, args.key, scan_id, args.poll, args.timeout, label)
        status = final.get("status", "unknown")

        # Extract result metrics
        result_dict   = final.get("result") or {}
        findings_list = final.get("findings") or []
        findings  = result_dict.get("total_findings",
                     result_dict.get("findings_count",
                     len(findings_list) if findings_list else 0))
        confirmed = result_dict.get("confirmed_vulns",
                     result_dict.get("proven",
                     result_dict.get("confirmed", 0)))
        failed    = result_dict.get("failed", result_dict.get("failed_count", 0))
        scan_cost = float(result_dict.get("total_cost_usd") or 0.0)

        # Prefer balance-delta cost (more accurate than scan's own tracking)
        bal_after = get_balance(args.api, args.key)
        if bal_before is not None and bal_after is not None:
            delta = max(0.0, bal_before - bal_after)
            if delta > 0:
                scan_cost = delta
        total_cost += scan_cost

        print(f"    DONE  status={status}  findings={findings}  "
              f"confirmed={confirmed}  failed={failed}  cost=${scan_cost:.4f}")
        if bal_after is not None:
            print(f"    Balance after: ${bal_after:.4f}  |  Total spent this run: ${total_cost:.4f}")

        results.append({
            "repo": repo, "model": model, "scan_id": scan_id, "status": status,
            "total_findings": findings, "confirmed": confirmed, "failed": failed,
            "cost_usd": scan_cost,
        })
        save_state(args.state, {"results": results, "total_cost_usd": total_cost})

        # ── Stop if this scan timed out — do not silently skip to next repo ──
        if status == "timeout":
            stop_reason = (
                f"Scan timed out after {args.timeout}s: {label}\n"
                f"  The scan is still running in the backend (scan_id={scan_id}).\n"
                f"  Wait for it to finish, then re-run with --resume."
            )
            stopped_at = i + 1
            print(f"\n  ╔══ STOPPED — SCAN TIMEOUT ══════════════════════════════════════╗")
            print(f"  ║  Scan timed out: {label}")
            print(f"  ║  scan_id: {scan_id}")
            print(f"  ║  The backend scan may still be running. Check its status:")
            print(f"  ║    GET /api/scan/{scan_id}")
            print(f"  ║  Once it completes, re-run with --resume to continue.")
            print(f"  ╚════════════════════════════════════════════════════════════════╝\n")
            break

        # ── Stop if backend reported an error ────────────────────────────────
        if status == "error":
            stop_reason = f"Backend error during scan: {label}. Check logs."
            stopped_at = i + 1
            print(f"\n  ╔══ STOPPED — BACKEND ERROR ══════════════════════════════════════╗")
            print(f"  ║  {stop_reason}")
            print(f"  ╚═════════════════════════════════════════════════════════════════╝\n")
            break

    # ---- Final summary ----
    print(f"\n{'='*70}")
    print("  BATCH COMPLETE — Summary")
    print(f"{'='*70}")
    hdr = f"  {'Repo':<35}  {'Model':<35}  {'Status':<12}  {'F':>4}  {'OK':>4}  {'Fail':>4}  {'Cost':>8}"
    print(hdr)
    print(f"  {'-'*35}  {'-'*35}  {'-'*12}  {'-'*4}  {'-'*4}  {'-'*4}  {'-'*8}")
    for r in results:
        rs       = r["repo"].replace("https://github.com/", "")
        cost_str = f"${r.get('cost_usd', 0.0):.4f}"
        print(f"  {rs:<35}  {r['model']:<35}  {r['status']:<12}  "
              f"{str(r.get('total_findings', '?')):>4}  {str(r.get('confirmed', '?')):>4}  "
              f"{str(r.get('failed', '?')):>4}  {cost_str:>8}")
    print(f"{'='*70}")
    print(f"  Total cost this run: ${total_cost:.4f}")
    final_balance = get_balance(args.api, args.key)
    if final_balance is not None:
        print(f"  Final OpenRouter balance: ${final_balance:.4f}")
    if stop_reason:
        print(f"\n  ⚠️  Run did not complete all {len(plan)} scans.")
        print(f"  Stopped at scan {stopped_at}/{len(plan)}.")
        print(f"  Reason: {stop_reason}")
        print(f"  Re-run with --resume once the issue is resolved.")
    else:
        print(f"\n  ✅  All {len(plan)} scans completed successfully.")
    print(f"{'='*70}\n")

    return 0 if not stop_reason else 2


if __name__ == "__main__":
    sys.exit(main())

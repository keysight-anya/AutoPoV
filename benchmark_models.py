#!/usr/bin/env python3
"""
AutoPoV Model Benchmark — Compare qwen3 vs openai/gpt-5.2 across 7 repos.

Repos cover 5 languages (C, C++, Python, Java, JavaScript) plus libyaml and enchive.
Each repo is scanned with both models sequentially.
Results are collected and printed as a comparison table.

Usage:
    python3 benchmark_models.py                    # run all 14 scans
    python3 benchmark_models.py --models qwen3     # run only qwen3
    python3 benchmark_models.py --repos enchive libyaml  # run only selected repos
    python3 benchmark_models.py --timeout 5400     # 90min per scan (default 3600)
"""
import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Configuration ──────────────────────────────────────────────────────────────
API_KEY = "apov_7ZcziTB7veZ2eUxSvmLdm1NHRlvGD0s9Js5ji6xI8PU"
BASE_URL = "http://localhost:8000"
POLL_INTERVAL = 20  # seconds between status checks

MODELS = ["qwen3", "openai/gpt-5.2"]

# 7 repos: 5 languages + libyaml + enchive
REPOS = [
    # tag,        language,     github URL
    ("enchive",    "C",         "https://github.com/skeeto/enchive"),
    ("libyaml",    "C",         "https://github.com/yaml/libyaml"),
    ("tinyxml2",   "C++",       "https://github.com/leethomason/tinyxml2"),
    ("pyyaml",     "Python",    "https://github.com/yaml/pyyaml"),
    ("commons-text","Java",     "https://github.com/apache/commons-text"),
    ("node-serialize","JavaScript","https://github.com/luin/serialize"),
    ("minimist",   "JavaScript","https://github.com/minimistjs/minimist"),
]

TERMINAL_STATUSES = {"completed", "failed", "cancelled", "stopped"}

# ── API helpers ────────────────────────────────────────────────────────────────

def api_request(method: str, path: str, body: Optional[Dict] = None) -> Dict[str, Any]:
    url = BASE_URL.rstrip("/") + path
    data = json.dumps(body).encode() if body else None
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {API_KEY}",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"API {method} {path}: {exc}") from exc


def submit_scan(repo_url: str, model: str) -> str:
    result = api_request("POST", "/api/scan/git", {"url": repo_url, "model": model})
    scan_id = result.get("scan_id")
    if not scan_id:
        raise RuntimeError(f"No scan_id: {result}")
    return scan_id


def poll_scan(scan_id: str, timeout: int, label: str) -> Dict[str, Any]:
    elapsed = 0
    errors = 0
    last_status = None
    stuck_count = 0

    while elapsed < timeout:
        try:
            info = api_request("GET", f"/api/scan/{scan_id}")
            errors = 0
        except RuntimeError as exc:
            errors += 1
            print(f"    [warn] poll error ({errors}): {exc}")
            if errors >= 5:
                return {"status": "error", "scan_id": scan_id}
            time.sleep(POLL_INTERVAL)
            elapsed += POLL_INTERVAL
            continue

        status = info.get("status", "unknown")
        progress = info.get("progress", 0)
        result = info.get("result") or {}
        findings = result.get("total_findings", info.get("findings_count", "?"))
        print(f"    [{elapsed:>5}s] {label}  {status}  {progress}%  findings={findings}")

        if status in TERMINAL_STATUSES:
            return info

        # stuck-at-100 safety
        if progress >= 100 and status == last_status:
            stuck_count += 1
            if stuck_count >= 5:
                info["status"] = "completed"
                return info
        else:
            stuck_count = 0
        last_status = status

        time.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL

    return {"status": "timeout", "scan_id": scan_id}


def extract_results(info: Dict[str, Any]) -> Dict[str, Any]:
    """Pull confirmed/findings/duration from the API response."""
    result = info.get("result") or {}
    findings_list = info.get("findings") or []
    return {
        "status": info.get("status", "?"),
        "scan_id": info.get("scan_id", "?"),
        "findings": result.get("total_findings",
                       result.get("findings_count",
                       len(findings_list) if findings_list else "?")),
        "confirmed": result.get("confirmed_vulns",
                        result.get("proven",
                        result.get("confirmed", 0))),
        "failed": result.get("failed", result.get("failed_count", "?")),
        "duration_s": result.get("duration_s", info.get("duration_s", "?")),
    }


# ── Single scan runner ─────────────────────────────────────────────────────────

def run_one(tag: str, lang: str, repo_url: str, model: str, timeout: int) -> Dict[str, Any]:
    """Run a single scan and return results dict."""
    label = f"{tag}/{model}"
    short_model = model.split("/")[-1]  # gpt-5.2 from openai/gpt-5.2
    print(f"\n{'─'*70}")
    print(f"  [{datetime.now().strftime('%H:%M:%S')}] START  {tag} ({lang}) × {short_model}")
    print(f"{'─'*70}")

    t0 = time.time()
    try:
        scan_id = submit_scan(repo_url, model)
        print(f"    scan_id = {scan_id}")
    except RuntimeError as exc:
        print(f"    [ERROR] Submit failed: {exc}")
        return {
            "tag": tag, "lang": lang, "model": model,
            "status": "submit_error", "scan_id": "", "findings": 0,
            "confirmed": 0, "failed": 0, "duration_s": 0, "wall_s": 0,
        }

    info = poll_scan(scan_id, timeout, label)
    wall = round(time.time() - t0, 1)
    res = extract_results(info)

    print(f"    ──> {res['status']}  findings={res['findings']}  "
          f"confirmed={res['confirmed']}  wall={wall}s")

    return {
        "tag": tag, "lang": lang, "model": model,
        "status": res["status"], "scan_id": res["scan_id"],
        "findings": res["findings"], "confirmed": res["confirmed"],
        "failed": res["failed"], "duration_s": res["duration_s"],
        "wall_s": wall,
    }


# ── Summary table ──────────────────────────────────────────────────────────────

def print_summary(results: List[Dict[str, Any]], models: List[str]):
    """Print a comparison table."""
    print(f"\n{'='*90}")
    print("  BENCHMARK RESULTS")
    print(f"{'='*90}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Models: {', '.join(models)}")
    print(f"  Total scans: {len(results)}")
    print()

    # Group by repo
    repos_seen = []
    by_repo = {}
    for r in results:
        tag = r["tag"]
        if tag not in by_repo:
            by_repo[tag] = {}
            repos_seen.append(tag)
        by_repo[tag][r["model"]] = r

    # Header
    model_labels = [m.split("/")[-1] for m in models]
    hdr = f"  {'Repo':<18} {'Lang':<6}"
    for ml in model_labels:
        hdr += f" │ {ml:>8} find  conf  status"
    print(hdr)
    print(f"  {'─'*18} {'─'*6}" + " │ " + " │ ".join(["─"*30] * len(models)))

    totals = {m: {"findings": 0, "confirmed": 0, "scans": 0, "wall": 0.0} for m in models}

    for tag in repos_seen:
        row = by_repo[tag]
        first = list(row.values())[0]
        line = f"  {tag:<18} {first['lang']:<6}"
        for m in models:
            r = row.get(m)
            if r:
                f = r["findings"] if r["findings"] != "?" else 0
                c = r["confirmed"] if r["confirmed"] != "?" else 0
                line += f" │ {r['wall_s']:>7.0f}s {f:>4}  {c:>4}  {r['status']:<10}"
                totals[m]["findings"] += (f if isinstance(f, int) else 0)
                totals[m]["confirmed"] += (c if isinstance(c, int) else 0)
                totals[m]["scans"] += 1
                totals[m]["wall"] += r["wall_s"]
            else:
                line += f" │ {'—':>38}"
        print(line)

    # Totals
    print(f"  {'─'*18} {'─'*6}" + " │ " + " │ ".join(["─"*30] * len(models)))
    totline = f"  {'TOTAL':<18} {'':6}"
    for m in models:
        t = totals[m]
        totline += (f" │ {t['wall']:>7.0f}s {t['findings']:>4}  "
                    f"{t['confirmed']:>4}  {t['scans']} scans")
    print(totline)
    print(f"{'='*90}\n")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="AutoPoV Model Benchmark")
    parser.add_argument("--models", nargs="+", default=MODELS,
                        help="Models to benchmark (default: qwen3 openai/gpt-5.2)")
    parser.add_argument("--repos", nargs="+", default=None,
                        help="Repo tags to include (default: all 7)")
    parser.add_argument("--timeout", type=int, default=3600,
                        help="Timeout per scan in seconds (default: 3600)")
    parser.add_argument("--output", type=str, default="benchmark_results.json",
                        help="Output JSON file for raw results")
    args = parser.parse_args()

    # Filter repos if requested
    repos = REPOS
    if args.repos:
        tags = {t.lower() for t in args.repos}
        repos = [r for r in REPOS if r[0].lower() in tags]
        if not repos:
            print(f"No matching repos for tags: {args.repos}")
            print(f"Available: {[r[0] for r in REPOS]}")
            return 1

    total_scans = len(repos) * len(args.models)
    print(f"\n{'█'*70}")
    print(f"  AutoPoV Model Benchmark")
    print(f"  {len(repos)} repos × {len(args.models)} models = {total_scans} scans")
    print(f"  Timeout: {args.timeout}s per scan")
    print(f"  Models: {', '.join(args.models)}")
    print(f"  Repos: {', '.join(r[0] for r in repos)}")
    print(f"{'█'*70}")

    results = []
    completed = 0

    for tag, lang, url in repos:
        for model in args.models:
            completed += 1
            print(f"\n  ▶ Scan {completed}/{total_scans}")
            r = run_one(tag, lang, url, model, args.timeout)
            results.append(r)

            # Save intermediate results after each scan
            with open(args.output, "w") as f:
                json.dump({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "models": args.models,
                    "results": results,
                }, f, indent=2)
            print(f"    [saved to {args.output}]")

    # Final summary
    print_summary(results, args.models)

    # Save final
    with open(args.output, "w") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "models": args.models,
            "complete": True,
            "results": results,
        }, f, indent=2)
    print(f"  Raw results saved to: {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""
validate_fixes.py — 3-repo validation run using qwen3 only.

Tests:
  1. skeeto/enchive   — regression check (should still confirm 6/6)
  2. libexpat/libexpat — DO NOT COMPILE fix (was self-compiling, should now invoke binary)
  3. DaveGamble/cJSON  — DO NOT COMPILE fix (small, fast)

Usage:
    python3 validate_fixes.py --key <API_KEY>
    python3 validate_fixes.py --key <API_KEY> --resume
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib import request as urllib_request
from urllib.error import URLError

API_BASE = "http://localhost:8000"
MODEL    = "qwen3"
TIMEOUT  = 3600   # 1 hour per scan max
POLL     = 30     # poll every 30s
STATE_FILE = "validate_fixes_state.json"

REPOS = [
    "https://github.com/skeeto/enchive",       # regression check
    "https://github.com/libexpat/libexpat",    # DO NOT COMPILE fix
    "https://github.com/DaveGamble/cJSON",     # DO NOT COMPILE fix
]

# ---------------------------------------------------------------------------

def _api(method: str, path: str, key: str, body=None, base: str = ""):
    url = (base or API_BASE) + path
    data = json.dumps(body).encode() if body else None
    req = urllib_request.Request(url, data=data, method=method,
                                  headers={"Content-Type": "application/json",
                                           "Authorization": f"Bearer {key}"})
    try:
        with urllib_request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"error": str(e)}


def start_scan(repo: str, key: str, base: str = "") -> str | None:
    r = _api("POST", "/api/scan/git", key, {"url": repo, "model": MODEL}, base=base)
    if not r.get("scan_id"):
        print(f"  API response: {r}")
    return r.get("scan_id")


def poll_scan(scan_id: str, key: str, timeout: int, poll: int, base: str = "") -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = _api("GET", f"/api/scan/{scan_id}", key, base=base)
        status = r.get("status", "")
        print(f"  [{time.strftime('%H:%M:%S')}] {status}", flush=True)
        if status in ("completed", "failed", "cancelled"):
            return r
        time.sleep(poll)
    return {"status": "timeout", "scan_id": scan_id}


def load_state() -> dict:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}


def save_state(state: dict):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key", required=True)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--api", default=API_BASE)
    args = parser.parse_args()

    base = args.api

    state = load_state() if args.resume else {}
    key = args.key

    print(f"\n=== Validation run: {len(REPOS)} repos × {MODEL} ===\n")

    for repo in REPOS:
        label = repo.split("github.com/")[-1]
        key_name = f"{label}:{MODEL}"

        if key_name in state and state[key_name].get("status") in ("completed", "failed", "timeout"):
            confirmed = state[key_name].get("confirmed_vulns", "?")
            print(f"[SKIP] {label} ({MODEL}) — already done, confirmed={confirmed}")
            continue

        print(f"\n→ Starting: {label} with {MODEL}")
        scan_id = start_scan(repo, key, base)
        if not scan_id:
            print(f"  ERROR: failed to start scan for {label}")
            state[key_name] = {"status": "start_failed"}
            save_state(state)
            continue

        print(f"  scan_id={scan_id}")
        result = poll_scan(scan_id, key, TIMEOUT, POLL, base)

        # confirmed_vulns lives inside the nested 'result' dict returned by the API
        _inner = result.get("result") or {}
        confirmed = (
            _inner.get("confirmed_vulns")
            or _inner.get("confirmed_vulnerabilities")
            or result.get("confirmed_vulns")
            or result.get("confirmed_vulnerabilities")
            or 0
        )
        # Also capture total findings for context
        findings_total = (
            len(_inner.get("findings") or [])
            or len(result.get("findings") or [])
        )
        status = result.get("status", "unknown")
        state[key_name] = {
            "scan_id": scan_id,
            "status": status,
            "confirmed_vulns": confirmed,
            "findings_total": findings_total,
        }
        save_state(state)
        print(f"  DONE: status={status}  findings={findings_total}  confirmed={confirmed}")

    print("\n=== Summary ===")
    for repo in REPOS:
        label = repo.split("github.com/")[-1]
        key_name = f"{label}:{MODEL}"
        d = state.get(key_name, {})
        print(f"  {label:<35} status={d.get('status','?'):<12} findings={d.get('findings_total','?'):<5} confirmed={d.get('confirmed_vulns','?')}")

    print()


if __name__ == "__main__":
    main()

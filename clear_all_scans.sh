#!/usr/bin/env bash
# clear_all_scans.sh — Wipe all scan results, caches, and batch state.
# Run from ~/AutoPoV AFTER all active scans have finished.
# Usage: bash clear_all_scans.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "=== AutoPoV Clean Reset ==="
echo "Working dir: $ROOT"
echo ""

# Wait up to 30s for active scans to drain after API cancel
ACTIVE_COUNT=$(find "$ROOT/results/runs/active" -name "*.json" 2>/dev/null | wc -l)
if [ "$ACTIVE_COUNT" -gt 0 ]; then
    echo "Found $ACTIVE_COUNT active scan(s) — waiting up to 30s for them to drain..."
    for i in $(seq 1 6); do
        sleep 5
        ACTIVE_COUNT=$(find "$ROOT/results/runs/active" -name "*.json" 2>/dev/null | wc -l)
        echo "  [${i}/6] Active scans remaining: $ACTIVE_COUNT"
        if [ "$ACTIVE_COUNT" -eq 0 ]; then
            break
        fi
    done
fi

# Force-clear any remaining stale active files (already cancelled via API)
ACTIVE_COUNT=$(find "$ROOT/results/runs/active" -name "*.json" 2>/dev/null | wc -l)
if [ "$ACTIVE_COUNT" -gt 0 ]; then
    echo "Force-removing $ACTIVE_COUNT stale active file(s) (already API-cancelled)..."
    find "$ROOT/results/runs/active" -name "*.json" -delete
fi

echo "No active scans. Proceeding with cleanup..."
echo ""

# ── Scan results ────────────────────────────────────────────────────────────
echo "[1/7] Clearing completed scan results (results/runs/)..."
find "$ROOT/results/runs" -maxdepth 1 -name "*.json" -delete
echo "      Done."

echo "[2/7] Clearing PoV scripts (results/povs/)..."
find "$ROOT/results/povs" -mindepth 1 -delete 2>/dev/null || true
echo "      Done."

echo "[3/7] Clearing proof artifacts (results/proof_artifacts/)..."
find "$ROOT/results/proof_artifacts" -mindepth 1 -delete 2>/dev/null || true
echo "      Done."

echo "[4/7] Clearing snapshots (results/snapshots/)..."
find "$ROOT/results/snapshots" -mindepth 1 -delete 2>/dev/null || true
echo "      Done."

# ── Caches ──────────────────────────────────────────────────────────────────
echo "[5/7] Clearing result and prompt caches..."
> "$ROOT/data/cache/result_cache.json" && echo '{}' > "$ROOT/data/cache/result_cache.json"
> "$ROOT/data/cache/prompt_cache.json" && echo '{}' > "$ROOT/data/cache/prompt_cache.json"
echo "      Done."

echo "[6/7] Clearing ChromaDB RAG vectors (data/chroma/)..."
find "$ROOT/data/chroma" -mindepth 1 -delete 2>/dev/null || true
echo "      Done."

# ── Batch state ─────────────────────────────────────────────────────────────
echo "[7/7] Resetting batch state files..."
echo '{"completed": [], "failed": [], "skipped": []}' > "$ROOT/batch_offline_state.json"
echo '{"completed": [], "failed": [], "skipped": []}' > "$ROOT/batch_online_state.json"
echo "      Done."

echo ""
echo "=== Clean Reset Complete ==="
echo ""
echo "Ready to run:"
echo "  Offline: python3 batch_scan.py --key <YOUR_KEY> --mode all"
echo "  Online:  python3 batch_scan_online.py --key <YOUR_KEY> --mode all"

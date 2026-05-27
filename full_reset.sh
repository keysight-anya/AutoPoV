#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

echo "=========================================="
echo "  AutoPoV Full Reset & Rebuild Script"
echo "=========================================="
echo ""

# ─────────────────────────────────────────────
# STEP 1: Nuclear Docker cleanup
# ─────────────────────────────────────────────
echo ">>> STEP 1: Complete Docker cleanup"
echo "    Stopping all containers..."
docker compose down --remove-orphans 2>/dev/null || true
docker stop $(docker ps -aq) 2>/dev/null || true

echo "    Removing all containers..."
docker rm -f $(docker ps -aq) 2>/dev/null || true

echo "    Removing all autopov images..."
docker rmi -f $(docker images --filter "reference=autopov/*" -q) 2>/dev/null || true
docker rmi -f $(docker images --filter "reference=autopov-*" -q) 2>/dev/null || true

echo "    Removing all images..."
docker rmi -f $(docker images -aq) 2>/dev/null || true

echo "    Removing all volumes (except ollama_data)..."
# Keep ollama_data so you don't have to re-pull models
for v in $(docker volume ls -q 2>/dev/null | grep -v ollama_data); do
    docker volume rm -f "$v" 2>/dev/null || true
done

echo "    Removing all networks..."
docker network prune -f 2>/dev/null || true

echo "    Pruning build cache..."
docker builder prune -af 2>/dev/null || true

echo "    Final system prune..."
docker system prune -af --volumes 2>/dev/null || true

echo "    ✅ Docker completely cleaned"
echo ""

# ─────────────────────────────────────────────
# STEP 2: Build all proof images + backend + frontend
# ─────────────────────────────────────────────
echo ">>> STEP 2: Building all Docker images"
echo ""

echo "    [2a] Building proof-native image..."
docker build -t autopov/proof-native:latest ./docker/proof-images/native/
echo "    ✅ proof-native done"

echo "    [2b] Building proof-python image..."
docker build -t autopov/proof-python:latest ./docker/proof-images/python/
echo "    ✅ proof-python done"

echo "    [2c] Building proof-node image..."
docker build -t autopov/proof-node:latest ./docker/proof-images/node/
echo "    ✅ proof-node done"

echo "    [2d] Building proof-java image..."
docker build -t autopov/proof-java:latest ./docker/proof-images/java/
echo "    ✅ proof-java done"

echo "    [2e] Building proof-go image..."
docker build -t autopov/proof-go:latest ./docker/proof-images/go/
echo "    ✅ proof-go done"

echo "    [2f] Building proof-browser image..."
docker build -t autopov/proof-browser:latest ./docker/proof-images/browser/
echo "    ✅ proof-browser done"

echo "    [2g] Building proof-php image..."
docker build -t autopov/proof-php:latest ./docker/proof-images/php/
echo "    ✅ proof-php done"

echo "    [2h] Building proof-ruby image..."
docker build -t autopov/proof-ruby:latest ./docker/proof-images/ruby/
echo "    ✅ proof-ruby done"

echo ""
echo "    [2i] Building backend + frontend via docker compose..."
docker compose build --no-cache
echo "    ✅ Backend + frontend built"

echo ""
echo "    [2j] Starting services..."
docker compose up -d
echo "    ✅ Services starting"

echo ""
echo "    Waiting for backend health..."
for i in $(seq 1 40); do
    if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
        echo "    ✅ Backend healthy after ~$((i*5))s"
        break
    fi
    sleep 5
done

echo ""
echo "    All images:"
docker images | grep -E "autopov|REPOSITORY"
echo ""

# ─────────────────────────────────────────────
# STEP 3: Clear all scan results and data
# ─────────────────────────────────────────────
echo ">>> STEP 3: Clearing all scan results and data"

echo "    Clearing results/runs/..."
rm -rf results/runs/*.json results/runs/active/* 2>/dev/null || true

echo "    Clearing results/povs/..."
rm -rf results/povs/* 2>/dev/null || true

echo "    Clearing results/proof_artifacts/..."
rm -rf results/proof_artifacts/* 2>/dev/null || true

echo "    Clearing results/snapshots/..."
rm -rf results/snapshots/* 2>/dev/null || true

echo "    Clearing data/chroma/..."
rm -rf data/chroma/* 2>/dev/null || true

echo "    Clearing prompt/result caches..."
echo '{}' > data/cache/prompt_cache.json 2>/dev/null || true
echo '{}' > data/cache/result_cache.json 2>/dev/null || true

echo "    Clearing batch state files..."
rm -f batch_offline_state.json batch_online_state.json 2>/dev/null || true

echo "    Clearing autopov build volumes..."
for v in $(docker volume ls -q 2>/dev/null | grep autopov_build_); do
    docker volume rm -f "$v" 2>/dev/null || true
done

echo "    ✅ All scan results cleared"
echo ""

# ─────────────────────────────────────────────
# STEP 4: Delete temp/diagnostic scripts
# ─────────────────────────────────────────────
echo ">>> STEP 4: Cleaning temporary scripts"

# Files to KEEP (not delete)
KEEP_LIST=(
    "batch_scan.py"
    "batch_scan_online.py"
    "add_api_key.py"
    "generate_key.py"
    "cancel_all.py"
    "check_active.py"
    "check_pov.py"
    "check_scan.py"
    "check_state.py"
    "cleanup_chromadb.py"
    "cleanup_docker.py"
    "monitor_scan.py"
    "scan_summary.py"
    "fix_stuck.py"
    "analyse.py"
    "verify_changes.py"
    "verify_discovery.py"
    "test_sanitizer.py"
    "test_verifier_fix.py"
    "verify_verifier_fix.py"
    "count_semgrep.py"
    "debug_placeholder.py"
    "analyze_last_scan.py"
)

deleted=0
kept=0
for f in _*.py; do
    [ -f "$f" ] || continue
    basename="$f"
    skip=0
    for k in "${KEEP_LIST[@]}"; do
        if [ "$basename" = "$k" ]; then
            skip=1
            break
        fi
    done
    if [ $skip -eq 0 ]; then
        rm -f "$f"
        deleted=$((deleted + 1))
    else
        kept=$((kept + 1))
    fi
done

echo "    Deleted $deleted temp _*.py scripts"
echo "    Kept $kept scripts from keep-list"

# Also clean other known temp files
rm -f = 2>/dev/null || true
rm -f .codex_patch_smoke .codex_patch_test .codex_patch_test2 2>/dev/null || true

# Clean nested duplicates
rm -rf home/olumba/ 2>/dev/null || true

echo "    ✅ Temp files cleaned"
echo ""

echo "=========================================="
echo "  DONE — Full reset complete"
echo "=========================================="
echo ""
echo "  Next steps:"
echo "  1. Verify: docker ps"
echo "  2. Check health: curl http://localhost:8000/api/health"
echo "  3. Run a scan: python3 batch_scan.py"
echo ""

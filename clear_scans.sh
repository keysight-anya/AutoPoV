#!/usr/bin/env bash
# Clears all scan results, history, snapshots, povs, and proof_artifacts
set -e

RUNS="/app/results/runs"
SNAPSHOTS="/app/results/snapshots"
ARTIFACTS="/app/results/proof_artifacts"
POVS="/app/results/povs"

echo "Clearing scan results..."
find "$RUNS" -maxdepth 1 -name "*.json" -delete
find "$RUNS" -maxdepth 1 -name "*.csv" -delete
find "$RUNS/active" -mindepth 1 -delete 2>/dev/null || true

echo "Clearing snapshots..."
find "$SNAPSHOTS" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true

echo "Clearing proof artifacts..."
find "$ARTIFACTS" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true

echo "Clearing povs..."
find "$POVS" -mindepth 1 -maxdepth 1 -exec rm -rf {} + 2>/dev/null || true

echo "Done. All scan data cleared."

#!/usr/bin/env bash
# rebuild_all_images.sh
# Rebuilds every autopov proof image from scratch (--no-cache).
# Run from the repo root: bash rebuild_all_images.sh
set -euo pipefail

IMAGES=(
  "native   docker/proof-images/native   autopov/proof-native:latest"
  "python   docker/proof-images/python   autopov/proof-python:latest"
  "node     docker/proof-images/node     autopov/proof-node:latest"
  "java     docker/proof-images/java     autopov/proof-java:latest"
  "go       docker/proof-images/go       autopov/proof-go:latest"
  "ruby     docker/proof-images/ruby     autopov/proof-ruby:latest"
  "php      docker/proof-images/php      autopov/proof-php:latest"
  "browser  docker/proof-images/browser  autopov/proof-browser:latest"
)

for entry in "${IMAGES[@]}"; do
  read -r name ctx tag <<< "$entry"
  echo ""
  echo "================================================================"
  echo "  Building: $tag  (context: $ctx)"
  echo "================================================================"
  docker build --no-cache -t "$tag" -f "$ctx/Dockerfile" . \
    && echo "  [OK] $tag" \
    || { echo "  [FAILED] $tag"; exit 1; }
done

echo ""
echo "All images built successfully."
docker images | grep autopov

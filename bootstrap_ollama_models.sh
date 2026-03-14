#!/usr/bin/env bash
set -euo pipefail

CONTAINER=${1:-autopov-ollama}
MODELS=(llama4 glm-4.7-flash qwen3)

for model in "${MODELS[@]}"; do
  echo "Pulling $model into $CONTAINER"
  docker exec -i "$CONTAINER" ollama pull "$model"
done

echo "Installed models:"
docker exec -i "$CONTAINER" ollama list

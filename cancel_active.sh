#!/bin/bash
API_KEY="apov_7ZcziTB7veZ2eUxSvmLdm1NHRlvGD0s9Js5ji6xI8PU"
BASE="http://localhost:8000/api/scan"

SCANS=(
  "07bc7829-5549-4c99-a996-bed77ebf53c1"
  "3d48e877-8653-4aaf-b773-e99e8d3ed7a0"
  "4395e14f-dd9a-4562-b4e2-d6d420dd3b36"
  "7babd36f-a719-4577-bfff-35513f2f7865"
  "c508980c-b018-4fc9-8f6e-6b04ff47d740"
  "d4591b39-41a0-4c81-a0b0-716895ac76db"
  "f12835da-2712-4fbc-b3c8-24e73e940a99"
)

for ID in "${SCANS[@]}"; do
  RESP=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE}/${ID}/cancel" -H "X-API-Key: ${API_KEY}")
  echo "[$RESP] Cancelled: $ID"
done

echo ""
echo "Active scans remaining:"
ls /home/olumba/AutoPoV/results/runs/active/ 2>/dev/null | wc -l

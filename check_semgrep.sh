#!/bin/bash
CODEBASE="/tmp/autopov/3bce23f2-9d6a-4578-8fd2-961487cc7e40"

echo "=== Semgrep YAML validity check ==="
semgrep --config /app/semgrep-rules/owasp-min.yml --validate 2>&1

echo ""
echo "=== Semgrep on lib/ ==="
semgrep --config /app/semgrep-rules/owasp-min.yml --json --quiet "$CODEBASE/lib/" > /tmp/sg2.json 2>/tmp/sg2_err.txt
echo "exit: $?"
cat /tmp/sg2_err.txt | head -5

python3 - <<'PY'
import json
with open('/tmp/sg2.json') as f:
    raw = f.read()
if not raw.strip():
    print("Empty output")
else:
    d = json.loads(raw)
    results = d.get('results', [])
    errors = d.get('errors', [])
    print(f"Findings: {len(results)}, errors: {len(errors)}")
    for r in results[:10]:
        cid = r.get('check_id','?')
        path = r.get('path','?')
        line = r.get('start',{}).get('line','?')
        code = r.get('extra',{}).get('lines','')[:60]
        print(f"  [{cid}] {path}:{line}  {code}")
    for e in errors[:3]:
        print(f"  ERROR: {str(e)[:150]}")
PY

#!/usr/bin/env python3
import json
from datetime import datetime

SCAN_ID = "40745440-b559-4c57-ae86-f882ceba022e"

with open(f"/home/user/AutoPoV/results/runs/{SCAN_ID}.json", "r") as f:
    data = json.load(f)

print(f"Current status: {data['status']}")
print(f"Findings: {len(data['findings'])}")

# Count by status
confirmed = sum(1 for f in data['findings'] if f.get('final_status') == 'confirmed')
skipped = sum(1 for f in data['findings'] if f.get('final_status') == 'skipped')
failed = sum(1 for f in data['findings'] if f.get('final_status') == 'failed')
pending = sum(1 for f in data['findings'] if f.get('final_status') == 'pending')
no_status = sum(1 for f in data['findings'] if not f.get('final_status'))

print(f"Confirmed: {confirmed}, Skipped: {skipped}, Failed: {failed}, Pending: {pending}, No status: {no_status}")

# Fix: mark as failed since investigation is done but no PoVs
if confirmed > 0:
    data['status'] = 'completed'
else:
    data['status'] = 'failed'
    data['error'] = 'Scan completed but no vulnerabilities were confirmed'

data['end_time'] = datetime.utcnow().isoformat()
data['confirmed_vulns'] = confirmed
data['false_positives'] = skipped + pending + no_status
data['failed'] = failed

with open(f"/home/user/AutoPoV/results/runs/{SCAN_ID}.json", "w") as f:
    json.dump(data, f, indent=2)

print(f"Fixed! New status: {data['status']}")

#!/usr/bin/env python3
"""Cancel/stop all active scans."""
import sys
sys.path.insert(0, '/app')

import os
import glob
import json

# Find all active scan IDs from the filesystem
active_dir = '/app/results/runs/active'
scan_ids = []
if os.path.isdir(active_dir):
    for f in glob.glob(os.path.join(active_dir, '*.json')):
        scan_ids.append(os.path.basename(f).replace('.json', ''))

print(f"Active scans found: {scan_ids}")

if not scan_ids:
    print("No active scans to cancel.")
    sys.exit(0)

# Use ScanManager to cancel them
try:
    from app.scan_manager import get_scan_manager
    sm = get_scan_manager()

    for scan_id in scan_ids:
        # Try graceful cancel first, then force stop
        ok, msg = sm.cancel_scan(scan_id)
        print(f"cancel_scan({scan_id}): ok={ok} msg={msg}")
        if not ok:
            ok2, msg2 = sm.stop_scan(scan_id)
            print(f"stop_scan({scan_id}):  ok={ok2} msg={msg2}")
except Exception as e:
    print(f"ScanManager approach failed: {e}")
    print("Falling back to direct file manipulation...")
    # Fallback: directly update the JSON status to cancelled
    for scan_id in scan_ids:
        path = os.path.join(active_dir, f'{scan_id}.json')
        try:
            with open(path) as f:
                d = json.load(f)
            d['status'] = 'cancelled'
            with open(path, 'w') as f:
                json.dump(d, f)
            # Move from active to runs dir
            import shutil
            dest = f'/app/results/runs/{scan_id}.json'
            shutil.move(path, dest)
            print(f"  Force-cancelled and moved: {scan_id}")
        except Exception as e2:
            print(f"  Failed for {scan_id}: {e2}")

print("Done.")

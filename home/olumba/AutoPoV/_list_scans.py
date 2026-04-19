import json, os, glob

files = sorted(glob.glob('/home/olumba/AutoPoV/results/runs/*.json'))
for f in files:
    try:
        d = json.load(open(f))
        scan_id = d.get('scan_id', os.path.basename(f))[:8]
        model = d.get('model_name', '?')
        start = (d.get('start_time') or '')[:16]
        findings = d.get('total_findings', 0)
        confirmed = d.get('confirmed_vulns', 0)
        failed = d.get('failed', 0)
        fp = d.get('false_positives', 0)
        status = d.get('status', '?')
        print(f"{start}  {model:<30}  findings:{findings}  confirmed:{confirmed}  failed:{failed}  fp:{fp}  [{status}]  {scan_id}")
    except Exception as e:
        print(f"ERROR {f}: {e}")

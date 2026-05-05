#!/usr/bin/env python3
"""Analyze the most recent scan — shows per-finding diagnostic detail."""
import json, glob, os, sys

# Find most recent completed scan
run_dir = '/home/olumba/AutoPoV/results/runs'
active_dir = os.path.join(run_dir, 'active')

files = []
for d in [run_dir, active_dir]:
    files += glob.glob(os.path.join(d, '*.json'))

files.sort(key=os.path.getmtime, reverse=True)

# Accept scan_id override
scan_id_filter = sys.argv[1] if len(sys.argv) > 1 else None

target = None
for f in files:
    if scan_id_filter and scan_id_filter not in f:
        continue
    with open(f) as fh:
        try:
            d = json.load(fh)
        except Exception:
            continue
    if d.get('findings'):
        target = (f, d)
        break

if not target:
    print("No scan with findings found")
    sys.exit(1)

path, d = target
findings = d.get('findings', [])
confirmed = sum(1 for f in findings if f.get('final_status') == 'confirmed')
failed_all = sum(1 for f in findings if f.get('final_status') in {'failed', 'failed_validation', 'contract_gate_failed', 'unproven_contract_gate'})

print(f"SCAN:     {d.get('scan_id')}")
print(f"STATUS:   {d.get('status')}")
print(f"MODEL:    {d.get('model_name') or d.get('model', '?')}")
print(f"FINDINGS: {len(findings)}  confirmed={confirmed}  failed={failed_all}  unproven={len(findings)-confirmed-failed_all}")
probe = d.get('probe_result') or {}
print(f"PROBE:    binary={probe.get('probe_binary_path') or 'none'}  surface={probe.get('probe_surface_type') or 'none'}")
print()

_FAILED_STATUSES = {'failed', 'failed_validation', 'contract_gate_failed', 'unproven_contract_gate'}

for i, f in enumerate(findings):
    ec = f.get('exploit_contract') or {}
    tr = f.get('test_result') or {}
    pov_result = f.get('pov_result') or {}
    ca = f.get('contract_audit') or {}
    final_status = f.get('final_status', '?')
    verdict_icon = '✓' if final_status == 'confirmed' else ('✗' if final_status in _FAILED_STATUSES else '~')

    print(f"{'='*60}")
    print(f"[{i+1}] {verdict_icon} {f.get('cwe_type','?')}  {f.get('filepath','?')}:{f.get('line_number','?')}")
    print(f"     status={final_status}  reason={str(f.get('failure_reason',''))[:80]}")
    print(f"     exec_surface={ec.get('execution_surface') or 'None'}"
          f"  probe_bin={ec.get('probe_binary_name') or 'None'}"
          f"  runtime={ec.get('runtime_profile') or 'None'}")
    print(f"     target_binary={ec.get('target_binary') or 'None'}"
          f"  target_entrypoint={ec.get('target_entrypoint') or 'None'}")

    # Contract audit issues
    ca_issues = ca.get('issues') or []
    if ca_issues:
        print(f"     contract_audit.issues: {ca_issues[:3]}")

    # Oracle result
    oracle = pov_result.get('oracle_result') or tr.get('oracle_result') or {}
    if oracle:
        print(f"     oracle: triggered={oracle.get('triggered')}  reason={oracle.get('reason')}  "
              f"signal={oracle.get('signal_class')}")

    # Failure detail
    vr = f.get('validation_result') or {}
    vr_issues = vr.get('issues') or []
    if vr_issues:
        print(f"     validation.issues: {vr_issues[:2]}")

    # PoV language and model
    if f.get('pov_script'):
        print(f"     pov: model={f.get('pov_model_used','?')}  lang={f.get('pov_language','?')}  "
              f"size={len(f.get('pov_script',''))} chars")

    # Proof strategy
    ps = (ec.get('proof_strategy') or {})
    if ps:
        print(f"     proof_strategy: type={ps.get('proof_type')}  oracle={ps.get('oracle_type')}")

print(f"{'='*60}")

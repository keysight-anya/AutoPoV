import json, sys, os

SCAN_IDS = [
    '4cc08488-3536-4476-8531-41d6e8854706',
    '05100458-4b4a-4a86-b977-d77a5dd86f9e',
]

RUNS_DIR = '/home/olumba/AutoPoV/results/runs'

for sid in SCAN_IDS:
    path = os.path.join(RUNS_DIR, f'{sid}.json')
    with open(path) as f:
        d = json.load(f)
    print(f'\n{"="*60}')
    print(f'SCAN: {sid[:8]}')
    print(f'  model       : {d.get("model_name")}')
    print(f'  status      : {d.get("status")}')
    print(f'  confirmed   : {d.get("confirmed_vulns")} / {d.get("total_findings")} total')
    print(f'  probe_result: {bool(d.get("probe_result"))}')
    if d.get("probe_result"):
        pr = d["probe_result"]
        print(f'    binary    : {pr.get("probe_binary_path")}')
        print(f'    skipped   : {pr.get("probe_skipped")} - {pr.get("probe_skip_reason")}')
        print(f'    build_ok  : {pr.get("probe_build_succeeded")}')
        print(f'    crash     : {pr.get("probe_crash_observed")} signal={pr.get("probe_crash_signal")}')
        print(f'    ldd_miss  : {pr.get("probe_ldd_missing")}')
        print(f'    error     : {pr.get("probe_error")}')

    findings = d.get('findings', [])
    print(f'\n  --- Findings ({len(findings)}) ---')
    for i, f in enumerate(findings):
        pov = f.get('pov_result') or {}
        meta = pov.get('metadata') or {}
        ec = pov.get('exploit_contract') or f.get('exploit_contract') or {}
        print(f'  [{i}] {f.get("cwe_type")} | {f.get("filepath","")[-50:]}:{f.get("line_number")}')
        print(f'       final={f.get("final_status")}  retries={f.get("retry_count",0)}  verdict={f.get("llm_verdict")}')
        print(f'       vuln_triggered={pov.get("vulnerability_triggered")}  oracle={( pov.get("oracle_result") or {}).get("label")}')
        print(f'       infra_err={pov.get("proof_infrastructure_error")}  failure={pov.get("failure_reason")}')
        bstatus = pov.get("build_status") or meta.get("build_status") or ""
        blog = (pov.get("build_log") or meta.get("build_log") or "")[-300:]
        print(f'       build_status={bstatus}')
        if blog:
            print(f'       build_log: {blog[:200].replace(chr(10)," ")}')
        stdout = (pov.get('stdout') or '')[:400].replace('\n', ' | ')
        stderr = (pov.get('stderr') or '')[:400].replace('\n', ' | ')
        if stdout:
            print(f'       stdout: {stdout}')
        if stderr:
            print(f'       stderr: {stderr}')
        # Show selected binary
        print(f'       selected_bin={pov.get("selected_binary")}  target_bin={pov.get("target_binary")}')
        # Show contract binary hint
        print(f'       contract_binary={ec.get("binary_name")}  probe_bin={ec.get("probe_binary_path")}')
        print()

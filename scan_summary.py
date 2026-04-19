import json, sys

path = '/home/olumba/AutoPoV/results/runs/f35794ee-efa3-404d-acc3-cd02b17ea5b8.json'
with open(path) as f:
    d = json.load(f)

print('repo_url:', d.get('repo_url') or d.get('target_url'))
print('model:', d.get('model_name') or d.get('model'))
print('status:', d.get('status'))
findings = d.get('findings', [])
print('findings count:', len(findings))
print()
for i, fi in enumerate(findings):
    ec = fi.get('exploit_contract') or {}
    pr = fi.get('pov_result') or {}
    pplan = fi.get('proof_plan') or ec.get('proof_plan') or {}
    oracle = pr.get('oracle_result') or {}
    print(f'[{i}] cwe={fi.get("cwe_type")} source={fi.get("source")} verdict={fi.get("llm_verdict")} conf={fi.get("confidence")} status={fi.get("final_status")}')
    print(f'     file={fi.get("filepath")}:{fi.get("line_number")}')
    print(f'     entrypoint={ec.get("target_entrypoint")}  binary={ec.get("target_binary")}')
    print(f'     known_subcommands={ec.get("known_subcommands")}')
    print(f'     surface={ec.get("execution_surface") or pplan.get("execution_surface")}  runtime={ec.get("runtime_profile")}')
    print(f'     pov_success={pr.get("vulnerability_triggered")}  failure_cat={pr.get("failure_category")}')
    print(f'     oracle_reason={oracle.get("reason")}  signal={oracle.get("signal_class")}')
    stderr = str(pr.get('stderr') or '')
    stdout = str(pr.get('stdout') or '')
    if stderr:
        print(f'     stderr[:300]={stderr[:300]}')
    if stdout and not stderr:
        print(f'     stdout[:200]={stdout[:200]}')
    pov = str(fi.get('pov_script') or '')
    if pov:
        print(f'     pov_preview={pov[:400]}')
    print()

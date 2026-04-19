import sys, os
sys.path.insert(0, '/app')
os.chdir('/app')
from agents.verifier import VulnerabilityVerifier
v = VulnerabilityVerifier()

pov = (
    "import subprocess, os\n"
    "env = os.environ.copy()\n"
    "env['CODEBASE_PATH'] = '/path/to/codebase'\n"
    "subprocess.run(['./enchive', '-v'], env=env)\n"
)
lower = pov.lower()
markers = ['/path/to/codebase', '/path/to/binary', '/path/to/', "env['codebase_path']", 'env["codebase_path"]']
print("lower script:", repr(lower[:120]))
for m in markers:
    print(f"  {m!r} in lower: {m in lower}")

issues = v._native_guardrail_issues(
    pov,
    {'proof_plan': {'runtime_family': 'native', 'execution_surface': 'binary_cli', 'input_mode': 'argv', 'input_format': 'text', 'oracle': ['crash_signal']}},
    'src/enchive.c',
)
print("issues:", issues)

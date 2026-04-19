#!/bin/bash
cd /home/olumba/AutoPoV
export PATH="/home/olumba/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
# Try pip-installed pytest first, then venv
if command -v pytest &>/dev/null; then
    PYTHONPATH=/home/olumba/AutoPoV pytest tests/test_oracle_policy.py tests/test_target_resolution.py -v --tb=short 2>&1 | tail -120
elif [ -f venv/bin/python3 ]; then
    PYTHONPATH=/home/olumba/AutoPoV venv/bin/python3 -m pytest tests/test_oracle_policy.py tests/test_target_resolution.py -v --tb=short 2>&1 | tail -120
else
    echo 'ERROR: no usable Python/pytest found'
    ls -la venv/bin/ 2>&1 | head -10
fi

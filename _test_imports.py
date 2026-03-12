#!/usr/bin/env python3
"""Quick test to verify all modified modules import correctly."""

import sys

try:
    import app.config
    print("✓ app.config")
except Exception as e:
    print(f"✗ app.config: {e}")
    sys.exit(1)

try:
    import app.policy
    print("✓ app.policy")
except Exception as e:
    print(f"✗ app.policy: {e}")
    sys.exit(1)

try:
    import prompts
    print("✓ prompts")
except Exception as e:
    print(f"✗ prompts: {e}")
    sys.exit(1)

try:
    import agents.verifier
    print("✓ agents.verifier")
except Exception as e:
    print(f"✗ agents.verifier: {e}")
    sys.exit(1)

try:
    import agents.unit_test_runner
    print("✓ agents.unit_test_runner")
except Exception as e:
    print(f"✗ agents.unit_test_runner: {e}")
    sys.exit(1)

try:
    import app.agent_graph
    print("✓ app.agent_graph")
except Exception as e:
    print(f"✗ app.agent_graph: {e}")
    sys.exit(1)

print("\nAll modules imported successfully!")

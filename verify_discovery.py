import sys
sys.path.insert(0, '/app')
import agents.agentic_discovery as d

a = d.AgenticDiscovery()
print("import OK")
print("CODEQL_LANGUAGES:", sorted(d.AgenticDiscovery.CODEQL_LANGUAGES))

import inspect
src = inspect.getsource(a.discover)
assert 'codeql_succeeded_langs' in src, "NEW discover() not found in container"
assert 'seen_codeql_extractors' in src, "Extractor dedup logic missing"
assert 'langs_needing_fallback' in src, "Semgrep fallback logic missing"
assert 'high_risk_covered_by_codeql' in src, "HIGH_RISK supplemental logic missing"
print("discover() logic: NEW version confirmed")
print("ALL OK")

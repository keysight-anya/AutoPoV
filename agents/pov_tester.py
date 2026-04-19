"""
AutoPoV PoV Tester Module
Tests PoV scripts against running applications and native targets
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from agents.app_runner import get_app_runner
from agents.live_app_tester import get_live_app_tester
from agents.live_docker_tester import get_live_docker_tester
from agents.unit_test_runner import get_unit_test_runner
import agents.oracle_policy as oracle_policy
from agents.proof_schemas import SetupPlan, TriggerPlan


class PoVTesterError(Exception):
    """Exception raised during PoV testing"""
    pass


class PoVTester:
    GENERIC_SELF_REPORTED_MARKERS = {"vulnerability triggered"}
    # These markers are only excluded from corroboration when the exploit contract does NOT
    # declare an 'exception' oracle type.  When the contract explicitly declares 'exception'
    # as an expected oracle signal (e.g. Python/JS crash-by-exception PoVs), they are
    # promoted to corroborating evidence so the oracle does not reject them.
    GENERIC_EXCEPTION_MARKERS = {"traceback", "referenceerror", "typeerror", "valueerror", "exception"}
    SETUP_FAILURE_PATTERNS = [
        "modulenotfounderror",
        "importerror",
        "no module named",
        "cannot import name",
        "error while finding module specification",
        "pkg_resources.distributionnotfound",
        "distributionnotfound",
    ]
    INVALID_NATIVE_ENTRYPOINTS = {
        "if", "for", "while", "switch", "return", "sizeof", "malloc", "calloc", "realloc", "free",
        "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat", "strcmp", "unknown", "main-like",
    }
    NATIVE_CRASH_PATTERNS = [
        'addresssanitizer',
        'undefinedbehaviorsanitizer',
        'runtime error:',
        'heap-buffer-overflow',
        'stack-buffer-overflow',
        'global-buffer-overflow',
        'use-after-free',
        'segmentation fault',
        'sigsegv',
        'null pointer',
        'deadlysignal',
        'abort',
    ]

    def _proof_plan(self, exploit_contract: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        contract = exploit_contract or {}
        plan = contract.get('proof_plan') or {}
        return plan if isinstance(plan, dict) else {}

    def _proof_plan_value(self, exploit_contract: Optional[Dict[str, Any]], key: str, default: Any = None) -> Any:
        plan = self._proof_plan(exploit_contract)
        value = plan.get(key)
        return default if value in (None, '', [], {}) else value

    def _detect_script_language(self, pov_script: str, runtime_profile: str = "") -> str:
        script = str(pov_script or "")
        profile = str(runtime_profile or "").lower()
        if profile in {"python"}:
            return "python"
        if profile in {"javascript", "node", "typescript", "browser", "web"}:
            return "javascript"
        stripped = script.lstrip()
        if stripped.startswith("import ") or stripped.startswith("from ") or stripped.startswith("def ") or "requests." in script:
            return "python"
        if stripped.startswith("#!/usr/bin/env node") or "console.log(" in script or "require(" in script or re.search(r"(^|\n)\s*(const|let|var)\s+", script):
            return "javascript"
        return "python"

    def _patch_target_refs(self, pov_script: str, target_url: Optional[str] = None, target_binary: Optional[str] = None) -> str:
        if target_url:
            pov_script = pov_script.replace("{{target_url}}", target_url).replace("{target_url}", target_url)
            pov_script = re.sub(r"http://localhost:\d+", target_url, pov_script)
            pov_script = re.sub(r"http://127\.0\.0\.1:\d+", target_url, pov_script)
        if target_binary:
            pov_script = pov_script.replace("{{target_binary}}", target_binary).replace("{target_binary}", target_binary)
        return pov_script

    def _repair_native_runtime_script(self, pov_script: str) -> str:
        script = str(pov_script or '')
        if not script or 'TARGET_BINARY' not in script:
            return script
        script = script.replace('    global TARGET_BINARY\n', '')

        # If the script uses TARGET_BINARY as a bare module-level name but never
        # assigns it via os.environ.get(), inject the assignment at the top of the
        # module so it is always defined.  This repairs scripts that write
        # `binary = TARGET_BINARY` inside main() without a prior assignment.
        _has_env_assign = (
            "os.environ.get('TARGET_BINARY')" in script
            or 'os.environ.get("TARGET_BINARY")' in script
            or "os.environ.get('TARGET_BIN')" in script
            or 'os.environ.get("TARGET_BIN")' in script
            or 'TARGET_BINARY = os.environ' in script
            or 'TARGET_BIN = os.environ' in script
        )
        if not _has_env_assign:
            # Prepend after the last import line so the variable is always defined
            _inject = (
                "TARGET_BINARY = os.environ.get('TARGET_BINARY') or os.environ.get('TARGET_BIN') or ''\n"
            )
            # Insert after the last top-level import statement
            import_end = 0
            for i, line in enumerate(script.splitlines(keepends=True)):
                stripped = line.strip()
                if stripped.startswith('import ') or stripped.startswith('from ') or stripped == '':
                    import_end = sum(len(l) for l in script.splitlines(keepends=True)[:i + 1])
                elif stripped and not stripped.startswith('#'):
                    break
            if import_end:
                script = script[:import_end] + _inject + script[import_end:]
            else:
                script = _inject + script

        if 'def main() -> int:\n    binary = TARGET_BINARY\n' not in script and 'def main():\n    binary = TARGET_BINARY\n' not in script:
            script = script.replace('def main() -> int:\n', 'def main() -> int:\n    binary = TARGET_BINARY\n', 1)
            script = script.replace('def main():\n', 'def main():\n    binary = TARGET_BINARY\n', 1)
        replacements = {
            'if not TARGET_BINARY:': 'if not binary:',
            'if TARGET_BINARY is None:': 'if binary is None:',
            'if TARGET_BINARY == "":': 'if binary == "":',
            'TARGET_BINARY = _find_binary': 'binary = _find_binary',
            'TARGET_BINARY = _compile_project': 'binary = _compile_project',
            'os.path.isfile(TARGET_BINARY)': 'os.path.isfile(binary)',
            'os.path.exists(TARGET_BINARY)': 'os.path.exists(binary)',
            'return _run_exploit(TARGET_BINARY)': 'return _run_exploit(binary)',
            '[TARGET_BINARY,': '[binary,',
            '(TARGET_BINARY,': '(binary,',
            ' TARGET_BINARY,': ' binary,',
        }
        for src, dst in replacements.items():
            script = script.replace(src, dst)
        script = script.replace('{TARGET_BINARY}', '{binary}')
        return script

    def _write_pinentry_stub(self, target_dir: str, *, passphrase: str = 'autopov-passphrase') -> str:
        os.makedirs(target_dir, exist_ok=True)
        stub_path = os.path.join(target_dir, 'autopov_pinentry_stub.py')
        stub = (
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "print('OK AutoPoV pinentry stub')\n"
            "sys.stdout.flush()\n"
            "for line in sys.stdin:\n"
            "    cmd = line.strip().upper()\n"
            f"    if cmd.startswith('GETPIN'):\n        print('D {passphrase}')\n        print('OK')\n"
            "    elif cmd.startswith('BYE'):\n        print('OK')\n        break\n"
            "    else:\n        print('OK')\n"
            "    sys.stdout.flush()\n"
        )
        Path(stub_path).write_text(stub, encoding='utf-8')
        os.chmod(stub_path, 0o755)
        return stub_path

    # Exit codes and stderr patterns that indicate a sanitizer-instrumented binary
    # crashed during keygen.  This is a *proof* that ASan/UBSan is working, not a
    # setup failure.  The PoV script must self-provision keys in this case.
    _KEYGEN_SANITIZER_EXIT_CODES: frozenset = frozenset({134, 139})
    _KEYGEN_SANITIZER_PATTERNS: tuple = (
        'AddressSanitizer',
        'UndefinedBehaviorSanitizer',
        'runtime error:',
        'heap-use-after-free',
        'double-free',
        'heap-buffer-overflow',
        'stack-buffer-overflow',
    )

    @staticmethod
    def _is_keygen_sanitizer_crash(returncode: int, stderr_text: str) -> bool:
        """Return True when a keygen attempt exited due to a sanitizer signal."""
        if returncode in PoVTester._KEYGEN_SANITIZER_EXIT_CODES:
            return True
        return any(p in (stderr_text or '') for p in PoVTester._KEYGEN_SANITIZER_PATTERNS)

    def _bootstrap_key_material_via_keygen(self, binary_path: str, env: Dict[str, str], *, config_name: str = '') -> Dict[str, Any]:
        home = env.get('HOME') or ''
        if not home:
            return self._build_setup_result(stage='setup', success=False, stderr='HOME is not set for native setup bootstrap', exit_code=-1)
        binary_name = config_name or Path(binary_path).name or 'autopov-target'
        config_dir = os.path.join(home, '.config', binary_name)
        os.makedirs(config_dir, exist_ok=True)
        pub = os.path.join(config_dir, f'{binary_name}.pub')
        sec = os.path.join(config_dir, f'{binary_name}.sec')
        pinentry_stub = self._write_pinentry_stub(os.path.join(home, '.autopov'))
        if os.path.exists(pub) and os.path.exists(sec):
            return self._build_setup_result(stage='setup', success=True, artifacts=[pub, sec, pinentry_stub], notes=[f'{binary_name} key material already present'])
        try:
            keygen_env = dict(env)
            keygen_env['TERM'] = 'dumb'
            last_result = None
            keygen_attempts = ([binary_path, '-A', f'--pinentry={pinentry_stub}', 'keygen'], [binary_path, '--no-agent', f'--pinentry={pinentry_stub}', 'keygen'], [binary_path, '-A', 'keygen'], [binary_path, 'keygen'])
            for command in keygen_attempts:
                for passphrase in ['autopov-passphrase\nautopov-passphrase\n', '\n\n']:
                    last_result = subprocess.run(
                        command,
                        input=passphrase,
                        capture_output=True,
                        text=True,
                        timeout=20,
                        env=keygen_env,
                    )
                    if last_result.returncode == 0 and os.path.exists(pub) and os.path.exists(sec):
                        return self._build_setup_result(
                            stage='setup',
                            success=True,
                            stdout=last_result.stdout,
                            stderr=last_result.stderr,
                            exit_code=last_result.returncode,
                            artifacts=[pub, sec],
                            notes=[f'bootstrapped {binary_name} key material via keygen'],
                        )
                    # If keygen itself crashed with a sanitizer signal, that means the
                    # ASan/UBSan-instrumented binary is working.  Treat as soft-pass:
                    # keys may be absent but the PoV script can self-provision them.
                    # Preserve the crash stderr so the oracle can see structural evidence.
                    if self._is_keygen_sanitizer_crash(last_result.returncode, last_result.stderr):
                        return self._build_setup_result(
                            stage='setup',
                            success=True,
                            stdout=last_result.stdout,
                            stderr=last_result.stderr,  # preserve raw sanitizer output
                            exit_code=last_result.returncode,
                            artifacts=[item for item in [pub, sec] if os.path.exists(item)],
                            notes=[
                                f'{binary_name} keygen crashed with sanitizer signal — '
                                'keys absent, PoV script must self-provision key material',
                            ],
                        )
            if last_result is None:
                return self._build_setup_result(stage='setup', success=False, stderr='Key bootstrap did not execute', exit_code=-1)
            return self._build_setup_result(
                stage='setup',
                success=False,
                stdout=last_result.stdout,
                stderr=last_result.stderr,
                exit_code=last_result.returncode,
                artifacts=[item for item in [pub, sec] if os.path.exists(item)],
                notes=[f'{binary_name} key bootstrap failed'],
            )
        except Exception as exc:
            return self._build_setup_result(
                stage='setup',
                success=False,
                stderr=str(exc),
                exit_code=-1,
                artifacts=[item for item in [pub, sec] if os.path.exists(item)],
                notes=[f'{binary_name} key bootstrap raised an exception'],
            )

    def _prepare_native_runtime_env(self, env: Dict[str, str], temp_dir: str, binary_path: str, codebase_path: str, exploit_contract: Optional[Dict[str, Any]]) -> Dict[str, str]:
        prepared = dict(env)
        prepared['TARGET_BINARY'] = binary_path
        prepared['TARGET_BIN'] = binary_path
        prepared['CODEBASE_PATH'] = codebase_path
        prepared['MQJS_BIN'] = binary_path
        home_dir = os.path.join(temp_dir, 'home')
        os.makedirs(home_dir, exist_ok=True)
        prepared['HOME'] = home_dir
        prepared.setdefault('ASAN_OPTIONS', 'detect_leaks=0:abort_on_error=1:print_stacktrace=1')
        prepared.setdefault('UBSAN_OPTIONS', 'print_stacktrace=1:halt_on_error=1')
        prepared = self._apply_setup_environment(prepared, exploit_contract)
        self._materialize_plan_files(temp_dir, self._build_setup_plan(exploit_contract, base_dir=temp_dir).files_to_create)
        return prepared

    def _setup_plugin_capabilities(self, exploit_contract: Optional[Dict[str, Any]], runtime_kind: str) -> List[str]:
        contract = exploit_contract or {}
        requirements = [item.lower() for item in self._setup_requirements(contract)]
        known_subcommands = [str(x).strip().lower() for x in (contract.get('known_subcommands') or []) if str(x).strip()]
        capabilities: List[str] = []
        # Determine whether this binary needs key material bootstrapped via keygen.
        # Three signals can trigger this — any one is sufficient:
        #   1. setup_requirements explicitly mentions key material
        #   2. known_subcommands lists 'keygen'
        #   3. target_binary name matches 'enchive' (hard-coded safety net for the
        #      enchive test target, where offline models may omit known_subcommands)
        # Keygen is skipped for function_call / function_harness / browser_dom
        # surfaces because those don't run the binary as a standalone CLI.
        binary_name_lower = str(contract.get('target_binary') or '').lower()
        # Determine whether this binary needs key material bootstrapped.
        # Generalised: any subcommand whose name suggests initialisation/setup
        # (keygen, init, setup, configure, generate-key, etc.) paired with a
        # binary that requires key material implies bootstrapping is needed.
        # The old 'enchive' hard-name check is replaced with crypto-tool keyword
        # matching so any similar CLI (gpg-like, vault, age, etc.) works correctly.
        _BOOTSTRAP_SUBCOMMAND_HINTS = {
            'keygen', 'init', 'setup', 'configure', 'generate-key', 'genkey',
            'key-gen', 'key_gen', 'gen-key', 'generate_key',
        }
        needs_keygen = (
            any('key material' in item or 'bootstrap key material' in item for item in requirements)
            or bool(known_subcommands and _BOOTSTRAP_SUBCOMMAND_HINTS & set(known_subcommands))
            or (
                # Fallback: no known_subcommands but binary name suggests a crypto tool
                # that likely requires key material to function.
                not known_subcommands
                and any(kw in binary_name_lower for kw in ('crypt', 'pgp', 'gpg', 'age', 'vault', 'pass', 'encrypt', 'sign'))
            )
        )
        surface_allows_keygen = str(contract.get('execution_surface') or '').strip().lower() not in {
            'function_call', 'function_harness', 'browser_dom'
        }
        if runtime_kind == 'native' and needs_keygen and surface_allows_keygen:
            capabilities.append('key_material_bootstrap')
        if runtime_kind in {'script', 'live'} and (contract.get('setup_files') or contract.get('files_to_create')):
            capabilities.append('materialize_setup_files')
        if runtime_kind == 'live' and (contract.get('target_url') or contract.get('base_url')):
            capabilities.append('external_target_url')
        return capabilities

    def _run_native_setup_plugins(self, binary_path: str, env: Dict[str, str], exploit_contract: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        contract = exploit_contract or {}
        capabilities = self._setup_plugin_capabilities(contract, 'native')
        registry = {
            'key_material_bootstrap': lambda: self._bootstrap_key_material_via_keygen(binary_path, env),
        }
        results: List[Dict[str, Any]] = []
        for capability in capabilities:
            handler = registry.get(capability)
            if handler is None:
                continue
            results.append(handler())
        # Expose the HOME dir used for bootstrap so the PoV script can reference it
        # via AUTOPOV_BOOTSTRAP_HOME (and HOME is already set by _prepare_native_runtime_env).
        if 'key_material_bootstrap' in capabilities and env.get('HOME'):
            env['AUTOPOV_BOOTSTRAP_HOME'] = env['HOME']
        if not results:
            notes = self._setup_requirements(contract) or ['no native setup plugins required']
            return self._build_setup_result(stage='setup', success=True, notes=notes)
        success = all(result.get('success') for result in results)
        stdout = '\n'.join(str(result.get('stdout') or '') for result in results if result.get('stdout'))
        stderr = '\n'.join(str(result.get('stderr') or '') for result in results if result.get('stderr'))
        exit_code = next((int(result.get('exit_code', 0)) for result in results if not result.get('success')), 0)
        artifacts: List[str] = []
        notes: List[str] = []
        for result in results:
            artifacts.extend([str(item) for item in (result.get('artifacts') or []) if str(item).strip()])
            notes.extend([str(item) for item in (result.get('notes') or []) if str(item).strip()])
        return self._build_setup_result(stage='setup', success=success, stdout=stdout, stderr=stderr, exit_code=exit_code, artifacts=list(dict.fromkeys(artifacts)), notes=list(dict.fromkeys(notes or self._setup_requirements(contract))))

    def _setup_requirements(self, exploit_contract: Optional[Dict[str, Any]]) -> List[str]:
        contract = exploit_contract or {}
        return [str(item).strip() for item in (contract.get('setup_requirements') or []) if str(item).strip()]


    def _build_setup_plan(self, exploit_contract: Optional[Dict[str, Any]], *, base_dir: str = '', target_url: str = '') -> SetupPlan:
        contract = exploit_contract or {}
        files = contract.get('setup_files') or contract.get('files_to_create') or []
        normalized_files = []
        for item in files if isinstance(files, list) else []:
            if isinstance(item, dict) and str(item.get('path') or '').strip():
                normalized_files.append({'path': str(item.get('path')).strip(), 'content': str(item.get('content') or '')})
        notes = self._setup_requirements(contract)
        if base_dir:
            notes.append(f'setup_base_dir:{base_dir}')
        if target_url:
            notes.append(f'setup_target_url:{target_url}')
        return SetupPlan(
            steps=self._setup_requirements(contract),
            files_to_create=normalized_files,
            environment={str(k): str(v) for k, v in ((contract.get('setup_environment') or contract.get('environment') or {}).items())} if isinstance((contract.get('setup_environment') or contract.get('environment') or {}), dict) else {},
            notes=list(dict.fromkeys(notes)),
        )

    def _build_trigger_plan(self, exploit_contract: Optional[Dict[str, Any]]) -> TriggerPlan:
        contract = exploit_contract or {}
        plan = self._proof_plan(contract)
        files = plan.get('files_to_create') or []
        normalized_files = []
        for item in files if isinstance(files, list) else []:
            if isinstance(item, dict) and str(item.get('path') or '').strip():
                normalized_files.append({'path': str(item.get('path')).strip(), 'content': str(item.get('content') or '')})
        return TriggerPlan(
            execution_surface=str(plan.get('execution_surface') or contract.get('execution_surface') or '').strip(),
            input_mode=str(plan.get('input_mode') or contract.get('input_mode') or '').strip(),
            argv=[str(x) for x in (plan.get('argv') or []) if str(x).strip()],
            stdin_payload=(None if plan.get('stdin_payload') in (None, '') else str(plan.get('stdin_payload'))),
            files_to_create=normalized_files,
            subcommand=(None if plan.get('subcommand') in (None, '') else str(plan.get('subcommand'))),
            target_entrypoint=str(plan.get('target_entrypoint') or contract.get('target_entrypoint') or '').strip(),
            target_route=str(contract.get('target_route') or plan.get('target_route') or '').strip(),
            target_dom_selector=str(contract.get('target_dom_selector') or plan.get('target_dom_selector') or '').strip(),
            http_method=str(contract.get('http_method') or plan.get('http_method') or 'GET').strip().upper(),
            request_param=str(contract.get('param') or plan.get('param') or 'input').strip(),
        )

    def _extract_trigger_payload(self, exploit_contract: Optional[Dict[str, Any]]) -> str:
        contract = exploit_contract or {}
        trigger_plan = self._build_trigger_plan(contract)
        if trigger_plan.stdin_payload not in (None, ''):
            return str(trigger_plan.stdin_payload)
        if trigger_plan.argv:
            return str(trigger_plan.argv[-1])
        inputs = contract.get('inputs') or []
        if inputs:
            first = inputs[0]
            if isinstance(first, dict):
                for key in ['value', 'payload', 'body', 'data']:
                    if first.get(key) not in (None, ''):
                        return str(first.get(key))
            else:
                return str(first)
        return ''

    def _apply_deterministic_script_skeleton(self, pov_script: str, *, language: str, mode: str, exploit_contract: Optional[Dict[str, Any]], codebase_path: str = '', target_url: str = '') -> str:
        script = str(pov_script or '')
        if 'AUTOPOV_DETERMINISTIC_SKELETON' in script:
            return script
        contract = exploit_contract or {}
        setup_plan = self._build_setup_plan(contract, base_dir=codebase_path, target_url=target_url)
        trigger_plan = self._build_trigger_plan(contract)
        payload = self._extract_trigger_payload(contract)
        context = {
            'mode': mode,
            'target_entrypoint': str(contract.get('target_entrypoint') or ''),
            'target_route': trigger_plan.target_route,
            'target_dom_selector': trigger_plan.target_dom_selector,
            'target_url': target_url,
            'codebase_path': codebase_path,
            'payload': payload,
            'setup_plan': asdict(setup_plan),
            'trigger_plan': asdict(trigger_plan),
            'headers': dict(contract.get('headers') or {}),
            'query_params': dict(contract.get('query_params') or {}),
            'form_data': dict(contract.get('form_data') or {}),
        }
        context_json = json.dumps(context, ensure_ascii=True)
        payload_literal = json.dumps(payload, ensure_ascii=True)
        param_literal = json.dumps(trigger_plan.request_param or 'input', ensure_ascii=True)
        method_literal = json.dumps(trigger_plan.http_method or 'GET', ensure_ascii=True)
        route_literal = json.dumps(trigger_plan.target_route or str(contract.get('target_entrypoint') or ''), ensure_ascii=True)
        selector_literal = json.dumps(trigger_plan.target_dom_selector or '', ensure_ascii=True)
        url_literal = json.dumps(target_url or str(contract.get('target_url') or contract.get('base_url') or ''), ensure_ascii=True)
        codebase_literal = json.dumps(codebase_path or '', ensure_ascii=True)
        entry_literal = json.dumps(str(contract.get('target_entrypoint') or ''), ensure_ascii=True)
        if language == 'javascript':
            header = (
                "// AUTOPOV_DETERMINISTIC_SKELETON\n"
                f"const AUTOPOV_CONTEXT = {context_json};\n"
                f"const TARGET_URL = process.env.TARGET_URL || {url_literal};\n"
                f"const CODEBASE_PATH = process.env.CODEBASE_PATH || {codebase_literal};\n"
                f"const TARGET_ENTRYPOINT = {entry_literal};\n"
                f"const TARGET_ROUTE = {route_literal};\n"
                f"const TARGET_DOM_SELECTOR = {selector_literal};\n"
                f"const method = {method_literal};\n"
                f"const param = {param_literal};\n"
                f"const payload = {payload_literal};\n"
                "const headers = AUTOPOV_CONTEXT.headers || {};\n"
                "const query_params = AUTOPOV_CONTEXT.query_params || {};\n"
                "const form_data = AUTOPOV_CONTEXT.form_data || {};\n\n"
            )
        else:
            header = (
                "# AUTOPOV_DETERMINISTIC_SKELETON\n"
                "import os, json\n"
                f"AUTOPOV_CONTEXT = json.loads({json.dumps(context_json, ensure_ascii=True)})\n"
                f"TARGET_URL = os.environ.get('TARGET_URL', {url_literal})\n"
                f"CODEBASE_PATH = os.environ.get('CODEBASE_PATH', {codebase_literal})\n"
                f"TARGET_ENTRYPOINT = {entry_literal}\n"
                f"TARGET_ROUTE = {route_literal}\n"
                f"TARGET_DOM_SELECTOR = {selector_literal}\n"
                f"method = {method_literal}\n"
                f"param = {param_literal}\n"
                f"payload = {payload_literal}\n"
                "headers = AUTOPOV_CONTEXT.get('headers', {})\n"
                "query_params = AUTOPOV_CONTEXT.get('query_params', {})\n"
                "form_data = AUTOPOV_CONTEXT.get('form_data', {})\n\n"
            )
        return header + script

    def _selector_candidates(self, selector: str) -> List[str]:
        raw = str(selector or '').strip().lower()
        if not raw:
            return []
        candidates = [raw]
        if raw.startswith('#') and len(raw) > 1:
            ident = raw[1:]
            candidates.extend([ident, f'id="{ident}"', f"id='{ident}'"])
        if raw.startswith('.') and len(raw) > 1:
            klass = raw[1:]
            candidates.extend([klass, f'class="{klass}"', f"class='{klass}'"])
        return list(dict.fromkeys(candidates))

    def _classify_live_oracle_reason(self, *, live_result: Any, validation_method: str, exploit_contract: Optional[Dict[str, Any]], target_url: str) -> str:
        triggered = bool(getattr(live_result, 'vulnerability_triggered', False))
        error = str(getattr(live_result, 'error', '') or '')
        if not triggered:
            return 'environment_failure' if error else 'no_oracle_match'
        evidence = [str(item).lower() for item in (getattr(live_result, 'evidence', []) or []) if str(item).strip()]
        contract = exploit_contract or {}
        selector = str(contract.get('target_dom_selector') or '').strip().lower()
        selector_candidates = self._selector_candidates(selector)
        route = str(contract.get('target_route') or contract.get('target_entrypoint') or target_url or '').strip().lower()
        preview = str(getattr(live_result, 'response_preview', '') or '').lower()
        status_code = int(getattr(live_result, 'status_code', 0) or 0)
        if validation_method == 'browser_live_contract':
            if selector_candidates and any(candidate in preview or any(candidate in item for item in evidence) for candidate in selector_candidates):
                return 'browser_dom_selector_evidence'
            if any('browser dialog observed' in item for item in evidence):
                return 'browser_dialog_evidence'
            if any('dom' in item for item in evidence):
                return 'browser_dom_evidence'
            if any('script' in item for item in evidence):
                return 'browser_script_evidence'
            return 'browser_dom_evidence'
        if any('server error' in item for item in evidence) or status_code >= 500:
            return 'http_status_evidence'
        if any('header' in item for item in evidence):
            return 'http_header_evidence'
        if any('side effect' in item or 'command output detected' in item or 'file content detected' in item for item in evidence):
            return 'http_side_effect_evidence'
        if route and route in preview:
            return 'http_route_evidence'
        return 'http_body_evidence'

    def _is_live_path_relevant(self, *, live_result: Any, validation_method: str, exploit_contract: Optional[Dict[str, Any]], target_url: str) -> bool:
        contract = exploit_contract or {}
        evidence = ' '.join(str(item) for item in (getattr(live_result, 'evidence', []) or []))
        preview = str(getattr(live_result, 'response_preview', '') or '')
        haystack = (evidence + '\n' + preview + '\n' + str(target_url or '')).lower()
        selector = str(contract.get('target_dom_selector') or '').strip().lower()
        selector_candidates = self._selector_candidates(selector)
        route = str(contract.get('target_route') or contract.get('target_entrypoint') or target_url or '').strip().lower()
        if validation_method == 'browser_live_contract' and selector_candidates:
            return any(candidate in haystack for candidate in selector_candidates)
        if route:
            return route in haystack
        return bool(getattr(live_result, 'vulnerability_triggered', False))

    def _materialize_plan_files(self, base_dir: str, files_to_create: Optional[List[Dict[str, str]]]) -> List[str]:
        artifacts: List[str] = []
        for item in files_to_create or []:
            if not isinstance(item, dict):
                continue
            path = str(item.get('path') or '').strip()
            if not path:
                continue
            target_path = Path(path)
            if not target_path.is_absolute():
                target_path = Path(base_dir) / target_path
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_text(str(item.get('content') or ''), encoding='utf-8')
            artifacts.append(str(target_path))
        return artifacts

    def _apply_setup_environment(self, env: Dict[str, str], exploit_contract: Optional[Dict[str, Any]]) -> Dict[str, str]:
        prepared = dict(env)
        setup_plan = self._build_setup_plan(exploit_contract)
        for key, value in setup_plan.environment.items():
            if key and value is not None:
                prepared[str(key)] = str(value)
        return prepared

    def _run_script_setup_plugins(self, env: Dict[str, str], codebase_path: str, exploit_contract: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        setup_plan = self._build_setup_plan(exploit_contract, base_dir=codebase_path, target_url=str(env.get('TARGET_URL') or ''))
        artifacts = [str(codebase_path)] if codebase_path else []
        artifacts.extend(self._materialize_plan_files(codebase_path or tempfile.gettempdir(), setup_plan.files_to_create))
        if env.get('TARGET_URL'):
            artifacts.append(str(env.get('TARGET_URL')))
        capabilities = self._setup_plugin_capabilities(exploit_contract, 'script')
        notes = list(setup_plan.notes or []) or ['no script setup plugins required']
        notes.extend([f'plugin:{capability}' for capability in capabilities])
        notes.append('repo_script_runtime_prepared')
        return self._build_setup_result(stage='setup', success=True, artifacts=list(dict.fromkeys(artifacts)), notes=list(dict.fromkeys(notes)))

    def _run_live_setup_plugins(self, exploit_contract: Optional[Dict[str, Any]], *, target_url: str = '', started: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        setup_plan = self._build_setup_plan(exploit_contract, target_url=target_url)
        artifacts = []
        capabilities = self._setup_plugin_capabilities(exploit_contract, 'live')
        notes = list(setup_plan.notes or []) + [f'plugin:{capability}' for capability in capabilities]
        if target_url:
            artifacts.append(str(target_url))
            notes.append('external_target_url_provided')
        if started is not None:
            if started.get('url'):
                artifacts.append(str(started.get('url')))
            if started.get('success'):
                notes.append('application_started')
                return self._build_setup_result(stage='setup', success=True, stdout=str(started.get('stdout', '') or ''), stderr=str(started.get('error', '') or ''), exit_code=0, artifacts=artifacts, notes=notes or ['application_started'])
            notes.append('application_start_failed')
            return self._build_setup_result(stage='setup', success=False, stdout=str(started.get('stdout', '') or ''), stderr=str(started.get('error', '') or ''), exit_code=-1, artifacts=artifacts, notes=notes)
        return self._build_setup_result(stage='setup', success=bool(target_url), artifacts=artifacts, notes=notes or (['external_target_url_provided'] if target_url else ['missing_target_url']))

    def _run_script(self, cwd: str, pov_filename: str, language: str, env: Dict[str, str]) -> Dict[str, Any]:
        command = ["python3", pov_filename] if language == "python" else ["node", pov_filename]
        try:
            result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=45, env=env)
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "vulnerability_triggered": False,
                "failure_category": None,
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "PoV execution timed out", "exit_code": -1, "vulnerability_triggered": False, "failure_category": "timeout"}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1, "vulnerability_triggered": False, "failure_category": "execution_error"}

    def _contract_indicators(self, exploit_contract: Optional[Dict[str, Any]]) -> List[str]:
        indicators = ["VULNERABILITY TRIGGERED"]
        contract = exploit_contract or {}
        indicators.extend(contract.get("success_indicators", []) or [])
        indicators.extend(contract.get("side_effects", []) or [])
        return [str(ind).strip() for ind in indicators if str(ind).strip()]

    def _exception_oracle_declared(self, exploit_contract: Optional[Dict[str, Any]]) -> bool:
        """Return True when the exploit contract explicitly declares 'exception' as an oracle type."""
        plan = self._proof_plan(exploit_contract)
        oracles = [str(x).lower() for x in (plan.get('oracle') or []) if str(x).strip()]
        return 'exception' in oracles

    def _corroborating_contract_indicators(self, exploit_contract: Optional[Dict[str, Any]]) -> List[str]:
        exception_oracle = self._exception_oracle_declared(exploit_contract)
        indicators = []
        seen = set()
        for indicator in self._contract_indicators(exploit_contract):
            normalized = indicator.lower()
            # Always filter out pure self-report markers
            if normalized in self.GENERIC_SELF_REPORTED_MARKERS or normalized in seen:
                continue
            # Only filter generic exception markers when the contract does NOT declare
            # 'exception' as an explicit oracle type (prevents spurious rejections on
            # Python/JS PoVs that prove the issue via a controlled exception or traceback)
            if normalized in self.GENERIC_EXCEPTION_MARKERS and not exception_oracle:
                continue
            seen.add(normalized)
            indicators.append(indicator)
        return indicators

    def _oracle_markers(self, exploit_contract: Optional[Dict[str, Any]]) -> List[str]:
        plan = self._proof_plan(exploit_contract)
        markers = [x.lower() for x in self._contract_indicators(exploit_contract)]
        oracles = [str(x).lower() for x in (plan.get('oracle') or []) if str(x).strip()]
        oracle_map = {
            'crash_signal': ['segmentation fault', 'sigsegv', 'sigabrt', 'bus error', 'core dumped'],
            'sanitizer_output': ['addresssanitizer', 'undefinedbehaviorsanitizer', 'runtime error:', 'heap-buffer-overflow', 'stack-buffer-overflow', 'null pointer'],
            'response_marker': [],
            'exception': ['traceback', 'referenceerror', 'typeerror', 'valueerror', 'exception'],
            'dom_execution': ['alert(', 'xss', 'script executed'],
            'behavioral_assertion': ['assertion', 'assert failed'],
            'http_effect': ['http/1.1 200', 'set-cookie', 'location:'],
        }
        for oracle in oracles:
            markers.extend(oracle_map.get(oracle, []))
        ordered = []
        seen = set()
        for marker in markers:
            if marker and marker not in seen:
                seen.add(marker)
                ordered.append(marker)
        return ordered

    def _detect_setup_failure(self, stdout: str, stderr: str, exit_code: int) -> bool:
        if exit_code == 0:
            return False
        haystack = (str(stdout or '') + "\n" + str(stderr or '')).lower()
        return any(pattern in haystack for pattern in self.SETUP_FAILURE_PATTERNS)

    def _extract_structured_native_evidence(self, stdout: str, stderr: str) -> Dict[str, Any]:
        combined_lines = [line.strip() for line in (str(stdout or '') + "\n" + str(stderr or '')).splitlines() if line.strip()]
        for line in reversed(combined_lines):
            if not (line.startswith('{') and line.endswith('}')):
                continue
            try:
                payload = json.loads(line)
            except Exception:
                continue
            if not isinstance(payload, dict):
                continue
            evidence = [str(item).lower() for item in (payload.get('evidence') or []) if str(item).strip()]
            child_returncode = payload.get('returncode')
            child_crash = False
            if isinstance(child_returncode, int) and child_returncode < 0:
                child_crash = True
            if any(item.startswith('signal=') for item in evidence):
                child_crash = True
            if any(token in ' '.join(evidence) for token in ['sanitizer_output', 'segfault_text']):
                child_crash = True
            return {'payload': payload, 'child_crash': child_crash, 'evidence': evidence}
        return {'payload': None, 'child_crash': False, 'evidence': []}

    def _evaluate_proof_outcome(
        self,
        stdout: str,
        stderr: str,
        exit_code: int,
        exploit_contract: Optional[Dict[str, Any]] = None,
        target_entrypoint: str = '',
        filepath: str = '',
        pov_script: str = '',
        expected_oracle: str = '',
        target_binary: str = '',
        execution_stage: str = 'trigger',
    ) -> Dict[str, Any]:
        """Taxonomy-agnostic proof outcome evaluation.

        Delegates the core oracle decision to oracle_policy.evaluate_proof_outcome
        (structural signal classification, path relevance, self-report blocking)
        while preserving the existing return dict shape for backward compatibility.

        Legacy oracle machinery (GENERIC_EXCEPTION_MARKERS, _oracle_markers,
        _native_triggered flat-list) is kept for non-native / app-layer proof
        families that are not yet covered by oracle_policy (browser, HTTP, repo
        script proofs).  For native crash-oriented proofs, oracle_policy is
        authoritative.
        """
        # ── Resolve target_entrypoint from contract if not passed explicitly ────
        contract = exploit_contract or {}
        if not target_entrypoint:
            target_entrypoint = str(contract.get('target_entrypoint') or '').strip()
            if target_entrypoint.lower() in {'unknown', 'none', 'n/a', ''}:
                target_entrypoint = ''
        if not target_binary:
            target_binary = str(contract.get('target_binary') or '').strip()
        if not expected_oracle:
            # Pull from proof plan if available (model-filled supporting signal)
            plan = self._proof_plan(exploit_contract)
            expected_oracle = str(plan.get('expected_oracle') or '').strip()
        relevance_anchors = [
            str(item).strip()
            for item in (contract.get('relevance_anchors') or [])
            if str(item).strip()
        ]
        if not relevance_anchors and target_entrypoint:
            relevance_anchors = [target_entrypoint]

        # ── Structured native evidence (JSON envelope from harness wrappers) ───
        structured_native = self._extract_structured_native_evidence(stdout, stderr)

        # ── New taxonomy-agnostic oracle evaluation ──────────────────────────
        # Extract asan_disabled flag and probe baseline from contract so the
        # asan_disabled fallback oracle fires when ASan could not be compiled.
        asan_disabled = bool(
            contract.get('asan_disabled')
            or contract.get('probe_asan_disabled')
        )
        baseline_exit_code = int(contract.get('probe_baseline_exit_code') or -1)
        baseline_stderr = str(contract.get('probe_baseline_stderr') or '')
        op_result = oracle_policy.evaluate_proof_outcome(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            target_entrypoint=target_entrypoint,
            filepath=filepath,
            pov_script=pov_script,
            expected_oracle=expected_oracle,
            target_binary=target_binary,
            stage=execution_stage,
            relevance_anchors=relevance_anchors,
            asan_disabled=asan_disabled,
            baseline_exit_code=baseline_exit_code,
            baseline_stderr=baseline_stderr,
        )
        # Task 6: c_library_harness behavioral oracle fallback
        _exec_surf_pt = str(contract.get('execution_surface') or
                            (contract.get('proof_plan') or {}).get('execution_surface') or '').strip().lower()
        if _exec_surf_pt == 'c_library_harness' and not op_result.get('triggered'):
            _beh = oracle_policy.evaluate_behavioral_proof_outcome(
                stdout=stdout, stderr=stderr, exit_code=exit_code,
                execution_surface=_exec_surf_pt,
                target_entrypoint=target_entrypoint, filepath=filepath,
                pov_script=pov_script, expected_oracle=expected_oracle,
                target_binary=target_binary, relevance_anchors=relevance_anchors,
            )
            if _beh.get('triggered'):
                op_result = _beh

        # ── Legacy app-layer / exception oracle path (browser, repo-script) ──
        # For non-native families the new oracle may return ambiguous/non_evidence
        # because it is scoped to crash/sanitizer families.  Fall back to the
        # legacy logic in those cases so existing proofs keep working.
        haystack = (str(stdout or '') + '\n' + str(stderr or '')).lower()
        markers = self._oracle_markers(exploit_contract)
        matched = [marker for marker in markers if marker in haystack]
        exception_oracle = self._exception_oracle_declared(exploit_contract)
        corroborating_matches = [
            marker for marker in matched
            if marker not in self.GENERIC_SELF_REPORTED_MARKERS
            and (marker not in self.GENERIC_EXCEPTION_MARKERS or exception_oracle)
        ]
        setup_failure = self._detect_setup_failure(stdout, stderr, exit_code)

        # Incorporate structured native evidence (JSON envelope from harness)
        if structured_native.get('child_crash'):
            for item in structured_native.get('evidence') or []:
                if item not in matched:
                    matched.append(item)
                if item not in corroborating_matches:
                    corroborating_matches.append(item)

        # ── Merge oracle_policy result with legacy path ───────────────────────
        # oracle_policy is authoritative when it sees strong evidence (native crash).
        # Legacy path covers exception/DOM/app-layer oracles not yet in oracle_policy.
        op_triggered = op_result.get('triggered', False)
        op_reason = op_result.get('reason', '')
        op_signal = op_result.get('signal_class', 'ambiguous')

        legacy_triggered = (
            (bool(corroborating_matches) and not setup_failure)
            or structured_native.get('child_crash', False)
        )
        legacy_self_report = bool(matched) and not corroborating_matches and not structured_native.get('child_crash')

        # Final decision: oracle_policy wins on strong signal; legacy fills the gap
        if op_signal == 'strong':
            # oracle_policy is authoritative for crash/sanitizer families
            triggered = op_triggered
            reason = op_reason
            self_report_only = op_result.get('self_report_only', False)
        elif op_result.get('self_report_only'):
            triggered = False
            reason = 'self_report_only'
            self_report_only = True
        elif op_result.get('disqualified') and not legacy_triggered:
            # Non-evidence confirmed by oracle_policy and no legacy corroboration
            triggered = False
            reason = op_reason if op_reason else 'non_evidence'
            self_report_only = False
        else:
            # Ambiguous signal or non-crash family — fall back to legacy logic
            triggered = legacy_triggered
            reason = (
                'environment_failure' if setup_failure and not legacy_triggered
                else 'oracle_matched' if corroborating_matches
                else 'structured_native_crash' if structured_native.get('child_crash')
                else 'self_report_only' if legacy_self_report
                else 'no_oracle_match'
            )
            self_report_only = legacy_self_report

        # Always include setup_failure info for caller diagnostics
        if setup_failure and not triggered:
            reason = 'environment_failure'

        return {
            'triggered': triggered,
            'matched_markers': matched,
            'reason': reason,
            'self_report_only': self_report_only,
            'setup_failure_detected': setup_failure,
            'structured_native_evidence': structured_native.get('payload'),
            'execution_stage': execution_stage,
            'proof_verdict': ('proven' if triggered and execution_stage == 'trigger' else 'setup_only' if reason == 'setup_stage_only' else 'failed'),
            # New fields from oracle_policy (backward-compatible additions)
            'signal_class': op_signal,
            'path_relevant': op_result.get('path_relevant', False),
            'model_oracle_matched': op_result.get('model_oracle_matched', False),
            'matched_evidence_markers': op_result.get('matched_evidence_markers', []),
        }

    def _repo_preflight(self, codebase_path: str, exploit_contract: Optional[Dict[str, Any]], filepath: str = '') -> Dict[str, Any]:
        contract = exploit_contract or {}
        plan = self._proof_plan(contract)
        runtime_profile = str(contract.get('runtime_profile') or '').strip().lower()
        execution_surface = str(plan.get('execution_surface') or '').strip().lower()
        target_entrypoint = str(contract.get('target_entrypoint') or '').strip()
        if target_entrypoint.lower() in {'unknown', 'none', 'n/a', ''}:
            target_entrypoint = ''
        checks = []
        issues = []
        codebase_ok = os.path.isdir(codebase_path)
        checks.append({'check': 'codebase_exists', 'ok': codebase_ok})
        if not codebase_ok:
            issues.append('Codebase path is missing')
        resolved_path = os.path.join(codebase_path, filepath) if filepath and not os.path.isabs(filepath) else filepath
        if filepath:
            file_ok = os.path.exists(resolved_path)
            checks.append({'check': 'finding_file_exists', 'ok': file_ok, 'path': resolved_path})
            if not file_ok:
                issues.append('Finding file does not exist in codebase snapshot')
        browser_dom = runtime_profile == 'browser' or execution_surface == 'browser_dom'
        if target_entrypoint and filepath and os.path.exists(resolved_path) and not browser_dom:
            try:
                content = Path(resolved_path).read_text(encoding='utf-8', errors='ignore')
                entry_ok = target_entrypoint in content
            except Exception:
                entry_ok = False
            checks.append({'check': 'target_entrypoint_resolves', 'ok': entry_ok, 'target_entrypoint': target_entrypoint})
            if not entry_ok:
                issues.append('Target entrypoint not found in source file during preflight')
        return {'ok': not issues, 'checks': checks, 'issues': issues}

    # Keywords in help text that indicate the binary reads a passphrase / PIN
    # interactively from /dev/tty or a TTY.  Detected at preflight time so the
    # PoV generator receives a hint to use pexpect / stdin piping instead of
    # bare subprocess invocation (which would hang waiting for tty input).
    _INTERACTIVE_KEYWORDS: tuple = (
        'passphrase', 'password', 'passwd', 'pinentry', 'pin entry',
        'pin:', 'interactive', 'tty', '/dev/tty', 'prompt',
    )

    def _parse_native_surface(self, help_text: str) -> Dict[str, Any]:
        text = str(help_text or '')
        options = sorted(set(re.findall(r'(?<!\w)(--[A-Za-z0-9][A-Za-z0-9-]*|-\w)\b', text)))

        def option_for(*hints: str) -> Optional[str]:
            for line in text.splitlines():
                low = line.lower()
                if any(h in low for h in hints):
                    matches = re.findall(r'(?<!\w)(--[A-Za-z0-9][A-Za-z0-9-]*|-\w)\b', line)
                    if matches:
                        return matches[0]
            return None

        supports_positional_file = bool(
            re.search(r'\[file(?:\s+\[args\])?\]', text, re.IGNORECASE)
            or re.search(r'usage: .*\bfile\b', text, re.IGNORECASE)
        )
        # Detect interactive/passphrase requirement from help text
        text_lower = text.lower()
        requires_interactive_input = any(kw in text_lower for kw in self._INTERACTIVE_KEYWORDS)

        # Extract subcommands from Commands:/Subcommands: sections in help text.
        # This makes subcommand discovery generic for any CLI binary, not just enchive.
        subcommands: List[str] = []
        _collecting_cmds = False
        for _line in text.splitlines():
            _m = re.search(r'^\s*(?:commands?|subcommands?|actions?)\s*:', _line, re.IGNORECASE)
            if _m:
                _collecting_cmds = True
                _rest = _line[_m.end():].strip()
                subcommands += [t.strip(',') for t in _rest.split() if t.strip(',') and not t.startswith('-')]
                continue
            if _collecting_cmds:
                _stripped = _line.strip()
                if not _stripped or re.match(r'^[A-Z][a-z]+.*:', _stripped):
                    _collecting_cmds = False
                    continue
                _tok = _stripped.split()[0].strip(',') if _stripped.split() else ''
                if _tok and not _tok.startswith('-') and len(_tok) >= 2:
                    subcommands.append(_tok)
        # Deduplicate while preserving order
        _seen: set = set()
        subcommands = [s for s in subcommands if not (_seen.add(s) or s in _seen)]

        return {
            'help_text': text,
            'options': options,
            'subcommands': subcommands,
            'supports_positional_file': supports_positional_file,
            'eval_option': option_for(' eval ', 'evaluate expr', '--eval', 'eval expr'),
            'include_option': option_for(' include ', 'include file', '--include'),
            'requires_interactive_input': requires_interactive_input,
        }

    def _inspect_native_surface(self, binary_path: str, codebase_path: str) -> Dict[str, Any]:
        attempts = []
        combined = []
        for args in (['--help'], ['-h']):
            result = self._run_binary(binary_path, args=args, cwd=codebase_path, env=os.environ.copy())
            attempts.append({'args': args, 'exit_code': result.get('exit_code')})
            output = ((result.get('stdout') or '') + "\n" + (result.get('stderr') or '')).strip()
            if output:
                combined.append(output)
        surface = self._parse_native_surface("\n".join(combined))
        surface['attempts'] = attempts
        surface['binary'] = binary_path
        return surface

    def _benign_payload_for_invocation(self, invocation: Dict[str, Any]) -> str:
        input_format = str(invocation.get('input_format') or '').lower()
        if input_format == 'javascript':
            return 'print(1)\n'
        if input_format == 'html':
            return '<html><body>ok</body></html>\n'
        return 'autopov-preflight\n'

    def _results_differ(self, baseline: Dict[str, Any], exploit: Dict[str, Any]) -> bool:
        if baseline.get('exit_code') != exploit.get('exit_code'):
            return True
        for key in ('stdout', 'stderr'):
            if str(baseline.get(key) or '').strip() != str(exploit.get(key) or '').strip():
                return True
        return False

    def _supported_native_input_modes(self, surface: Dict[str, Any]) -> List[str]:
        supported: List[str] = ['argv']
        if surface.get('supports_positional_file') or surface.get('include_option'):
            supported.insert(0, 'file')
        if surface.get('eval_option'):
            supported.append('eval')
        supported.append('stdin')
        ordered = []
        seen = set()
        for mode in supported:
            if mode not in seen:
                seen.add(mode)
                ordered.append(mode)
        return ordered

    def _recommend_native_input_mode(self, exploit_contract: Optional[Dict[str, Any]], surface: Dict[str, Any], invocation: Dict[str, Any]) -> str:
        plan = self._proof_plan(exploit_contract)
        candidates = [str(x).lower() for x in (plan.get('candidate_input_modes') or []) if str(x).strip()]
        declared = str(plan.get('input_mode') or invocation.get('strategy') or 'argv').lower()
        supported = self._supported_native_input_modes(surface)
        if not candidates:
            candidates = [declared]
        if declared not in candidates:
            candidates.insert(0, declared)
        mode_aliases = {
            'file': 'file',
            'filepath': 'file',
            'stdin': 'stdin',
            'pipe': 'stdin',
            'eval': 'eval',
            'eval_payload': 'eval',
            'argv': 'argv',
            'argument': 'argv',
        }
        normalized_supported = [mode_aliases.get(mode, mode) for mode in supported]
        for candidate in candidates:
            normalized = mode_aliases.get(candidate, candidate)
            if normalized in normalized_supported:
                return normalized
        return normalized_supported[0] if normalized_supported else 'argv'

    def _adapt_contract_to_surface(self, exploit_contract: Optional[Dict[str, Any]], surface: Dict[str, Any], invocation: Dict[str, Any]) -> Dict[str, Any]:
        contract = dict(exploit_contract or {})
        plan = dict(self._proof_plan(contract))
        recommended_input_mode = self._recommend_native_input_mode(contract, surface, invocation)
        supported_input_modes = self._supported_native_input_modes(surface)
        plan['supported_input_modes'] = supported_input_modes
        plan['recommended_input_mode'] = recommended_input_mode
        plan['input_mode'] = recommended_input_mode
        if recommended_input_mode in {'eval', 'file', 'stdin'}:
            plan['execution_surface'] = 'binary_cli'
        contract['proof_plan'] = plan
        return contract

    def _build_native_variants(self, invocation: Dict[str, Any], surface: Dict[str, Any], exploit_payload: str) -> List[Dict[str, Any]]:
        variants: List[Dict[str, Any]] = []
        strategy = invocation.get('strategy') or 'argv'
        args = list(invocation.get('args') or [])
        input_format = str(invocation.get('input_format') or 'text').lower()
        file_name = invocation.get('file_name') or ('autopov_input.js' if input_format == 'javascript' else 'autopov_input.txt')
        eval_option = surface.get('eval_option')
        include_option = surface.get('include_option')
        positional = bool(surface.get('supports_positional_file'))

        if strategy == 'file':
            if args:
                variants.append({'name': 'file_args_template', 'strategy': 'file', 'args': args, 'file_name': file_name})
            if positional:
                variants.append({'name': 'file_positional', 'strategy': 'file', 'args': ['{input_file}'], 'file_name': file_name})
            variants.append({'name': 'file_after_double_dash', 'strategy': 'file', 'args': ['--', '{input_file}'], 'file_name': file_name})
            if include_option:
                variants.append({'name': 'file_include_option', 'strategy': 'file', 'args': [include_option, '{input_file}'], 'file_name': file_name})
            if eval_option and exploit_payload:
                variants.append({'name': 'eval_payload', 'strategy': 'argv', 'args': [eval_option, '{payload}'], 'file_name': file_name})
        elif strategy == 'stdin':
            variants.append({'name': 'stdin_payload', 'strategy': 'stdin', 'args': args, 'stdin': '{payload}', 'file_name': file_name})
        else:
            variants.append({'name': 'argv_payload', 'strategy': 'argv', 'args': args or ['{payload}'], 'file_name': file_name})
            if eval_option and exploit_payload and input_format in {'javascript', 'text'}:
                variants.append({'name': 'eval_payload', 'strategy': 'argv', 'args': [eval_option, '{payload}'], 'file_name': file_name})

        deduped = []
        seen = set()
        for variant in variants:
            key = (variant['strategy'], tuple(variant.get('args') or []), variant.get('stdin'))
            if key not in seen:
                seen.add(key)
                deduped.append(variant)
        return deduped

    def _execute_native_variant(self, binary_path: str, codebase_path: str, variant: Dict[str, Any], benign_payload: str, exploit_payload: str, exploit_contract: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        env = os.environ.copy()
        temp_dir = tempfile.mkdtemp(prefix='autopov_native_variant_')
        env = self._prepare_native_runtime_env(env, temp_dir, binary_path, codebase_path, exploit_contract)
        setup_result = self._run_native_setup_plugins(binary_path, env, exploit_contract)
        try:
            def materialize(payload: str) -> Dict[str, Any]:
                args = list(variant.get('args') or [])
                stdin_data = None
                if variant['strategy'] == 'file':
                    file_name = variant.get('file_name') or 'autopov_input.txt'
                    file_path = os.path.join(temp_dir, file_name)
                    Path(file_path).parent.mkdir(parents=True, exist_ok=True)
                    Path(file_path).write_text(payload, encoding='utf-8')
                    args = [arg.replace('{input_file}', file_path).replace('{payload}', payload) for arg in args]
                    env['TARGET_INPUT_FILE'] = file_path
                    env['TARGET_INPUT_PATH'] = file_path
                elif variant['strategy'] == 'stdin':
                    args = [arg.replace('{payload}', payload) for arg in args]
                    stdin_data = payload if variant.get('stdin') == '{payload}' else variant.get('stdin')
                else:
                    args = [arg.replace('{payload}', payload) for arg in args]
                return self._run_binary(binary_path, args=args, env=env, stdin_data=stdin_data, cwd=codebase_path)

            baseline = materialize(benign_payload)
            exploit = materialize(exploit_payload)
            return {
                'baseline_result': baseline,
                'exploit_result': exploit,
                'path_exercised': self._results_differ(baseline, exploit),
                'variant': variant,
                'setup_result': setup_result,
            }
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def _native_preflight(self, binary_path: str, codebase_path: str, exploit_contract: Optional[Dict[str, Any]], filepath: str = '') -> Dict[str, Any]:
        checks = []
        issues = []
        source_like_suffixes = {'.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.java', '.js', '.ts', '.py', '.rb', '.pl', '.sh'}
        binary_suffix = Path(binary_path or '').suffix.lower()
        binary_ok = bool(binary_path and os.path.isfile(binary_path) and os.access(binary_path, os.X_OK) and binary_suffix not in source_like_suffixes)
        checks.append({'check': 'binary_exists', 'ok': binary_ok, 'binary': binary_path})
        surface = {'help_text': '', 'options': [], 'supports_positional_file': False, 'eval_option': None, 'include_option': None}
        if not binary_ok:
            issues.append('Target binary is missing, not executable, or resolves to a source file instead of a built program')
            return {'ok': False, 'checks': checks, 'issues': issues, 'surface': surface}
        invocation = self._extract_native_invocation(exploit_contract, filepath)
        surface = self._inspect_native_surface(binary_path, codebase_path)
        supported_input_modes = self._supported_native_input_modes(surface)
        recommended_input_mode = self._recommend_native_input_mode(exploit_contract, surface, invocation)
        checks.append({'check': 'surface_observed', 'ok': bool(surface.get('help_text') or surface.get('options')), 'options': surface.get('options', [])[:20]})
        checks.append({'check': 'input_mode_selected', 'ok': bool(recommended_input_mode), 'recommended_input_mode': recommended_input_mode, 'supported_input_modes': supported_input_modes})
        adapted_contract = self._adapt_contract_to_surface(exploit_contract, surface, invocation)
        adapted_invocation = self._extract_native_invocation(adapted_contract, filepath)
        variants = self._build_native_variants(adapted_invocation, surface, self._normalize_native_file_payload(self._extract_native_payload(adapted_contract)))
        checks.append({'check': 'invocation_variants_available', 'ok': bool(variants), 'variant_count': len(variants)})
        if not variants:
            issues.append('No executable invocation variants could be derived from the observed target surface')
            return {'ok': False, 'checks': checks, 'issues': issues, 'surface': surface}
        benign_payload = self._benign_payload_for_invocation(adapted_invocation)
        baseline_probe = self._execute_native_variant(binary_path, codebase_path, variants[0], benign_payload, benign_payload)
        baseline_result = baseline_probe.get('exploit_result') or baseline_probe.get('baseline_result') or {}
        setup_result = baseline_probe.get('setup_result') or self._build_setup_result(stage='setup', success=True, notes=['no native setup plugins required'])
        baseline_ok = setup_result.get('success', True) and baseline_result.get('exit_code') in {0, 1, 2} and not self._native_triggered(baseline_result.get('stdout', ''), baseline_result.get('stderr', ''), baseline_result.get('exit_code', -1), exploit_contract)
        checks.append({'check': 'baseline_execution_succeeds', 'ok': baseline_ok, 'exit_code': baseline_result.get('exit_code'), 'variant': variants[0].get('name')})
        if not setup_result.get('success', True):
            issues.append('Setup stage failed before trigger execution')
        if not baseline_ok:
            issues.append('Baseline binary execution did not behave as expected during preflight')
        return {
            'ok': not issues,
            'checks': checks,
            'issues': issues,
            'surface': surface,
            'variants': [v.get('name') for v in variants],
            'supported_input_modes': supported_input_modes,
            'recommended_input_mode': recommended_input_mode,
            'adapted_invocation': adapted_invocation,
            'effective_contract': adapted_contract,
            'setup_result': setup_result,
        }

    def _native_triggered(self, stdout: str, stderr: str, exit_code: int, exploit_contract: Optional[Dict[str, Any]] = None) -> bool:
        """Thin wrapper — delegates to oracle_policy.classify_signal for native crash detection.
        Kept for backward compatibility with callers outside _evaluate_proof_outcome."""
        # Use oracle_policy as the canonical check for structural crash evidence.
        if oracle_policy.classify_signal(stdout, stderr, exit_code) == 'strong':
            return True
        # Also accept corroborating contract indicators (side_effects etc.)
        haystack = (stdout + "\n" + stderr).lower()
        if any(ind.lower() in haystack for ind in self._corroborating_contract_indicators(exploit_contract)):
            return True
        return False

    def _extract_inline_eval_payloads(self, pov_script: str) -> List[str]:
        script = str(pov_script or '')
        payloads: List[str] = []
        patterns = [
            r"[\"'](?:-e|--eval)[\"']\s*,\s*([\"'])(.*?)\1",
            r"(?:-e|--eval)\s+([\"'])(.*?)\1",
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, script, re.DOTALL):
                payload = match.group(2)
                if payload and payload not in payloads:
                    payloads.append(payload)
        return payloads


    def _native_trigger_requirement_issues(self, pov_script: str, exploit_contract: Optional[Dict[str, Any]]) -> List[str]:
        contract = exploit_contract or {}
        script = str(pov_script or '')
        lower_script = script.lower()
        issues: List[str] = []
        requirements = [str(item).strip() for item in (contract.get('trigger_requirements') or []) if str(item).strip()]
        target_entrypoint = str(contract.get('target_entrypoint') or '').strip()
        plan = self._proof_plan(contract)
        plan_subcommand = str(plan.get('subcommand') or '').strip().lower()

        for requirement in requirements:
            lower_req = requirement.lower()
            if lower_req.startswith('reach target entrypoint:'):
                expected = requirement.split(':', 1)[1].strip()
                expected_lower = expected.lower()
                if expected and expected_lower not in lower_script:
                    issues.append(f'Generated native PoV does not satisfy trigger requirement: reach target entrypoint: {expected}')
            elif lower_req.startswith('use trigger subcommand:'):
                expected = requirement.split(':', 1)[1].strip()
                expected_lower = expected.lower()
                if expected and expected_lower not in lower_script:
                    issues.append(f'Generated native PoV does not satisfy trigger requirement: use trigger subcommand: {expected}')

        if plan_subcommand and target_entrypoint and target_entrypoint.lower() not in {'unknown', 'none', 'n/a'}:
            if plan_subcommand in lower_script and target_entrypoint.lower() not in lower_script:
                issues.append(f'Generated native PoV references trigger subcommand {plan_subcommand} but not the resolved target entrypoint {target_entrypoint}')

        return list(dict.fromkeys(issues))

    def _native_script_guardrail_issues(self, pov_script: str, exploit_contract: Optional[Dict[str, Any]], surface: Optional[Dict[str, Any]] = None) -> List[str]:
        contract = exploit_contract or {}
        plan = self._proof_plan(contract)
        runtime_family = str(plan.get('runtime_family') or contract.get('runtime_profile') or '').lower()
        if runtime_family not in {'native', 'c', 'cpp', 'binary'}:
            return []

        script = str(pov_script or '')
        lower_script = script.lower()
        issues: List[str] = []
        input_mode = str(plan.get('input_mode') or '').lower()
        input_format = str(plan.get('input_format') or '').lower()
        options = [str(x) for x in ((surface or {}).get('options') or [])]

        weak_file_markers = ['does_not_exist', 'nonexistent', 'missing.js', 'no such file', 'definitely_missing']
        if any(marker in lower_script for marker in weak_file_markers):
            issues.append('Generated native PoV relies on a missing-file path instead of a concrete exploit trigger')

        if input_mode == 'file' and re.search(r"[\"'](?:-e|--eval)[\"']", script):
            issues.append('Observed proof plan requires file input, but the generated PoV switches to inline eval mode')

        if '--memory-limit' in options and 'no memory-size option detected' in lower_script:
            issues.append('Generated native PoV ignores the observed --memory-limit option on the target surface')

        if input_format == 'javascript':
            for payload in self._extract_inline_eval_payloads(script):
                syntax_check = get_unit_test_runner().validate_syntax(payload, runtime_profile='javascript')
                if not syntax_check.get('valid'):
                    issues.append('Generated inline eval payload has invalid JavaScript syntax')
                    break

        issues.extend(self._native_trigger_requirement_issues(pov_script, contract))
        return list(dict.fromkeys(issues))

    def _non_native_script_guardrail_issues(self, pov_script: str, exploit_contract: Optional[Dict[str, Any]], mode: str = 'live_app') -> List[str]:
        """Guardrail checks for non-native (live_app, repo_script) PoV scripts.

        Enforces that scripts injected with the deterministic skeleton use the
        provided variables (TARGET_URL, TARGET_ROUTE, CODEBASE_PATH, etc.) rather
        than hardcoded values that bypass the skeleton contract.

        Returns a list of issue strings (empty = no issues).
        """
        script = str(pov_script or '')
        if not script:
            return []
        issues: List[str] = []
        contract = exploit_contract or {}
        target_url = str(contract.get('target_url') or contract.get('base_url') or '').strip()
        target_route = str(contract.get('target_route') or '').strip()
        target_entrypoint = str(contract.get('target_entrypoint') or '').strip()

        if mode == 'live_app':
            # After skeleton injection, hardcoded localhost URLs should have been
            # replaced by TARGET_URL.  Flag any that survive patching.
            if re.search(r'["\']http://(localhost|127\.0\.0\.1):\d+', script):
                issues.append(
                    'Non-native PoV contains hardcoded localhost URL; use TARGET_URL from the injected skeleton instead'
                )
            # If a target_route is declared, the script should reference it
            if target_route and 'AUTOPOV_DETERMINISTIC_SKELETON' in script:
                route_used = (
                    target_route in script
                    or 'TARGET_ROUTE' in script
                    or 'target_route' in script
                )
                if not route_used:
                    issues.append(
                        f'Non-native PoV does not reference declared target_route {target_route!r}; '
                        'use TARGET_ROUTE from the injected skeleton'
                    )

        elif mode == 'repo_script':
            # Repo scripts must reference CODEBASE_PATH or TARGET_ENTRYPOINT
            # when a concrete entrypoint is known.
            if target_entrypoint and target_entrypoint.lower() not in {'unknown', 'none', 'n/a'}:
                entry_used = (
                    target_entrypoint in script
                    or 'TARGET_ENTRYPOINT' in script
                    or 'CODEBASE_PATH' in script
                )
                if not entry_used:
                    issues.append(
                        f'Repo PoV does not reference target entrypoint {target_entrypoint!r} '
                        'or the CODEBASE_PATH/TARGET_ENTRYPOINT skeleton variables'
                    )

        return list(dict.fromkeys(issues))

    def _run_binary(
        self,
        binary_path: str,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
        stdin_data: Optional[str] = None,
        cwd: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                [binary_path] + (args or []),
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
                cwd=cwd,
                input=stdin_data,
            )
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "vulnerability_triggered": False,
            }
        except subprocess.TimeoutExpired:
            return {"stdout": "", "stderr": "Native harness timed out", "exit_code": -1, "vulnerability_triggered": False}
        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1, "vulnerability_triggered": False}

    def _is_binary_native_target(self, target_entrypoint: str, filepath: str = "", exploit_contract: Optional[Dict[str, Any]] = None) -> bool:
        candidate = str(target_entrypoint or "").strip().lower()
        stem = Path(filepath or "").stem.lower()
        contract = exploit_contract or {}
        plan = self._proof_plan(contract)
        surface = str(plan.get('execution_surface') or contract.get('execution_surface') or '').strip().lower()
        target_binary = str(contract.get('target_binary') or '').strip()
        if surface in {'binary_cli', 'cli'}:
            return True
        if not candidate:
            return False
        if target_binary and candidate in {"main", "mqjs", "qjs", "mquickjs", "example", "example_stdlib", "mqjs_stdlib"}:
            return True
        if target_binary and stem and candidate == stem:
            return True
        if candidate in {"main", "mqjs", "qjs", "mquickjs", "example", "example_stdlib", "mqjs_stdlib"}:
            return True
        if stem and candidate == stem:
            return True
        return False

    def _script_uses_target_binary(self, pov_script: str) -> bool:
        script = str(pov_script or "")
        binary_markers = [
            "TARGET_BINARY",
            "TARGET_BIN",
            "MQJS_BIN",
            "subprocess.run([binary",
            "subprocess.run([binary,",
            "os.environ.get('MQJS_BIN')",
            "os.environ.get('TARGET_BINARY')",
            "os.environ.get('TARGET_BIN')",
        ]
        return any(marker in script for marker in binary_markers)

    def _candidate_binary_names(self, exploit_contract: Optional[Dict[str, Any]], filepath: str = "") -> List[str]:
        names: List[str] = []
        contract = exploit_contract or {}
        target_entrypoint = str(contract.get("target_entrypoint") or "").strip()
        if target_entrypoint and target_entrypoint.lower() not in self.INVALID_NATIVE_ENTRYPOINTS and "/" not in target_entrypoint:
            names.extend([target_entrypoint, f"{target_entrypoint}.exe"])
        file_name = Path(filepath or "").stem.strip()
        if file_name:
            names.extend([file_name, f"{file_name}.exe"])
        goal = str(contract.get("goal") or "").lower()
        if "mquickjs_build" in goal:
            names.extend(["mquickjs_build", "mquickjs-build", "qjsc"])
        if "mqjs" in goal:
            names.extend(["mqjs", "mquickjs", "qjs"])
        ordered = []
        seen = set()
        for name in names:
            lowered = name.lower()
            if lowered and lowered not in seen:
                seen.add(lowered)
                ordered.append(name)
        return ordered

    def _preferred_binary_paths(self, codebase_path: str, exploit_contract: Optional[Dict[str, Any]], filepath: str = "") -> List[str]:
        codebase = Path(codebase_path)
        candidates: List[str] = []
        search_dirs = [codebase, codebase / 'build', codebase / 'out', codebase / 'bin', codebase / '.autopov-cmake-build', codebase / '.autopov-meson-build']
        for name in self._candidate_binary_names(exploit_contract, filepath):
            for directory in search_dirs:
                candidate = directory / name
                if candidate.exists() and os.access(candidate, os.X_OK):
                    candidates.append(str(candidate))
        seen = set()
        ordered = []
        for item in candidates:
            if item not in seen:
                seen.add(item)
                ordered.append(item)
        return ordered

    def _extract_native_payload(self, exploit_contract: Optional[Dict[str, Any]]) -> str:
        contract = exploit_contract or {}
        inputs = contract.get("inputs") or []
        if not inputs:
            return "A" * 1024
        first = inputs[0]
        if isinstance(first, dict):
            for key in ["value", "payload", "body", "data", "path", "file_path"]:
                if first.get(key) not in (None, ""):
                    return str(first.get(key))
        return str(first)

    def _normalize_native_file_payload(self, raw_payload: Any) -> str:
        text = str(raw_payload or "")
        lowered = text.lower().strip()
        if not text.strip():
            return ""
        patterns = [
            r"(?:a\s+)?javascript\s+file\s+containing\s*:\s*(.+)$",
            r"(?:a\s+)?js\s+file\s+containing\s*:\s*(.+)$",
            r"file\s+containing\s*:\s*(.+)$",
            r"payload\s*:\s*(.+)$",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                candidate = match.group(1).strip()
                if candidate:
                    return candidate.strip('`').strip()
        if lowered.startswith('javascript:'):
            return text.split(':', 1)[1].strip()
        return text

    def _looks_like_file_payload(self, raw_payload: Any, exploit_contract: Optional[Dict[str, Any]], filepath: str = "") -> bool:
        payload = str(raw_payload or "").strip()
        if not payload:
            return False
        lowered = payload.lower()
        contract = exploit_contract or {}
        target_entrypoint = str(contract.get("target_entrypoint") or "").lower()
        goal = str(contract.get("goal") or "").lower()
        if any(term in target_entrypoint for term in ["js_load", "load", "mqjs", "qjs", "mquickjs"]):
            return True
        if any(term in goal for term in ["javascript file", "js file", "script file"]):
            return True
        if any(term in lowered for term in ["javascript file", "js file", "file containing", "script file", "input file"]):
            return True
        if Path(filepath or "").suffix.lower() in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"} and ("load(" in lowered or payload.strip().endswith('.js')):
            return True
        return False

    def _native_payload_filename(self, raw_payload: Any, exploit_contract: Optional[Dict[str, Any]], filepath: str = "") -> str:
        payload = str(raw_payload or "")
        lowered = payload.lower()
        contract = exploit_contract or {}
        target_entrypoint = str(contract.get("target_entrypoint") or "").lower()
        if any(term in target_entrypoint for term in ["js_load", "load", "mqjs", "qjs", "mquickjs"]) or "javascript" in lowered or "load(" in lowered:
            return "autopov_input.js"
        if any(token in lowered for token in ['<html', '<script', 'onerror=', 'onload=']):
            return 'autopov_input.html'
        return 'autopov_input.txt'

    def _extract_native_invocation(self, exploit_contract: Optional[Dict[str, Any]], filepath: str = "") -> Dict[str, Any]:
        contract = exploit_contract or {}
        plan = self._proof_plan(contract)
        target_entrypoint = str(contract.get("target_entrypoint") or "").strip()
        invocation = {
            "strategy": str(plan.get('input_mode') or "argv").lower(),
            "args": [],
            "stdin": None,
            "file_payload": None,
            "file_name": "autopov_input.txt",
            "target_entrypoint": target_entrypoint,
            "input_format": str(plan.get('input_format') or 'text').lower(),
        }
        inputs = contract.get("inputs") or []
        if inputs:
            first = inputs[0]
            if isinstance(first, dict):
                mode = str(first.get("mode") or first.get("channel") or "argv").lower()
                payload = None
                for key in ["value", "payload", "body", "data", "path", "file_path"]:
                    if first.get(key) not in (None, ""):
                        payload = str(first.get(key))
                        break
                args = first.get("args") if isinstance(first.get("args"), list) else []
                inferred_file_payload = self._looks_like_file_payload(payload, contract, filepath) if payload is not None else False
                if mode in {"stdin", "pipe"}:
                    invocation["strategy"] = "stdin"
                    invocation["stdin"] = payload or self._extract_native_payload(contract)
                elif mode in {"file", "filepath"} or inferred_file_payload:
                    invocation["strategy"] = "file"
                    normalized_payload = self._normalize_native_file_payload(payload or self._extract_native_payload(contract))
                    invocation["file_payload"] = normalized_payload
                    invocation["file_name"] = str(first.get("name") or first.get("filename") or self._native_payload_filename(normalized_payload, contract, filepath))
                    invocation["args"] = [str(x) for x in args] if args else []
                else:
                    invocation["strategy"] = "argv"
                    if args:
                        invocation["args"] = [str(x) for x in args]
                    elif payload is not None:
                        invocation["args"] = [payload]
            else:
                normalized = self._normalize_native_file_payload(first)
                if self._looks_like_file_payload(first, contract, filepath):
                    invocation["strategy"] = "file"
                    invocation["file_payload"] = normalized
                    invocation["file_name"] = self._native_payload_filename(normalized, contract, filepath)
                else:
                    invocation["args"] = [str(first)]
        if not invocation["args"] and invocation["strategy"] == "argv":
            invocation["args"] = [self._extract_native_payload(contract)]
        if target_entrypoint.startswith("/"):
            invocation["strategy"] = "file"
        if invocation.get('input_format') == 'javascript' and invocation["strategy"] == 'argv':
            invocation["strategy"] = "file"
            payload = invocation["args"][0] if invocation["args"] else self._extract_native_payload(contract)
            invocation["file_payload"] = self._normalize_native_file_payload(payload)
            invocation["file_name"] = 'autopov_input.js'
            invocation["args"] = []
        if filepath and Path(filepath).suffix.lower() in {".txt", ".json", ".xml", ".cfg", ".ini"} and invocation["strategy"] == "argv":
            invocation["strategy"] = "file"
            invocation["file_payload"] = invocation["args"][0] if invocation["args"] else self._extract_native_payload(contract)
        return invocation

    def _run_native_binary_with_contract(self, binary_path: str, codebase_path: str, exploit_contract: Optional[Dict[str, Any]], filepath: str = "") -> Dict[str, Any]:
        invocation = self._extract_native_invocation(exploit_contract, filepath)
        preferred = [binary_path] + [p for p in self._preferred_binary_paths(codebase_path, exploit_contract, filepath) if p != binary_path]
        adapted_contract = dict(exploit_contract or {})
        exploit_payload = self._normalize_native_file_payload(self._extract_native_payload(adapted_contract))
        benign_payload = self._benign_payload_for_invocation(invocation)
        best_result = None
        attempted = []
        for candidate in preferred:
            surface = self._inspect_native_surface(candidate, codebase_path)
            adapted_contract = self._adapt_contract_to_surface(exploit_contract, surface, invocation)
            adapted_invocation = self._extract_native_invocation(adapted_contract, filepath)
            exploit_payload = self._normalize_native_file_payload(self._extract_native_payload(adapted_contract))
            benign_payload = self._benign_payload_for_invocation(adapted_invocation)
            variants = self._build_native_variants(adapted_invocation, surface, exploit_payload)
            for variant in variants:
                executed = self._execute_native_variant(candidate, codebase_path, variant, benign_payload, exploit_payload, adapted_contract)
                baseline_result = executed.get('baseline_result') or {}
                exploit_result = executed.get('exploit_result') or {}
                path_exercised = bool(executed.get('path_exercised'))
                attempted.append({
                    'binary': candidate,
                    'variant': variant.get('name'),
                    'args': list(variant.get('args') or []),
                    'baseline_exit_code': baseline_result.get('exit_code'),
                    'exploit_exit_code': exploit_result.get('exit_code'),
                    'path_exercised': path_exercised,
                })
                setup_result = executed.get('setup_result') or self._build_setup_result(stage='setup', success=True, notes=['no native setup plugins required'])
                if self._native_triggered(exploit_result.get('stdout', ''), exploit_result.get('stderr', ''), exploit_result.get('exit_code', -1), adapted_contract):
                    exploit_result['attempted_binaries'] = list(attempted)
                    exploit_result['setup_result'] = setup_result
                    exploit_result['selected_binary'] = candidate
                    exploit_result['selected_variant'] = variant.get('name')
                    exploit_result['baseline_result'] = baseline_result
                    exploit_result['path_exercised'] = path_exercised
                    exploit_result['surface'] = surface
                    exploit_result['effective_contract'] = adapted_contract
                    exploit_result['recommended_input_mode'] = (adapted_contract.get('proof_plan') or {}).get('recommended_input_mode')
                    exploit_result['supported_input_modes'] = (adapted_contract.get('proof_plan') or {}).get('supported_input_modes')
                    return exploit_result
                if best_result is None or (path_exercised and not best_result.get('path_exercised')):
                    merged = dict(exploit_result)
                    merged['attempted_binaries'] = list(attempted)
                    merged['setup_result'] = setup_result
                    merged['selected_binary'] = candidate
                    merged['selected_variant'] = variant.get('name')
                    merged['baseline_result'] = baseline_result
                    merged['path_exercised'] = path_exercised
                    merged['surface'] = surface
                    merged['effective_contract'] = adapted_contract
                    merged['recommended_input_mode'] = (adapted_contract.get('proof_plan') or {}).get('recommended_input_mode')
                    merged['supported_input_modes'] = (adapted_contract.get('proof_plan') or {}).get('supported_input_modes')
                    best_result = merged
        if best_result is None:
            best_result = {
                'stdout': '',
                'stderr': 'No native binary candidates executed',
                'exit_code': -1,
                'vulnerability_triggered': False,
                'attempted_binaries': attempted,
                'selected_binary': binary_path,
                'baseline_result': {},
                'path_exercised': False,
                'surface': {},
            }
        return best_result

    def _build_setup_result(self, *, stage: str, success: bool, stdout: str = '', stderr: str = '', exit_code: int = 0, artifacts: Optional[List[str]] = None, notes: Optional[List[str]] = None) -> Dict[str, Any]:
        return {
            'stage': stage,
            'success': bool(success),
            'stdout': stdout,
            'stderr': stderr,
            'exit_code': exit_code,
            'artifacts': list(artifacts or []),
            'notes': list(notes or []),
        }

    def _build_trigger_result(self, *, oracle: Dict[str, Any], stdout: str, stderr: str, exit_code: int) -> Dict[str, Any]:
        return {
            'stage': 'trigger',
            'success': bool(oracle.get('triggered')),
            'stdout': stdout,
            'stderr': stderr,
            'exit_code': exit_code,
            'oracle_reason': oracle.get('reason', ''),
            'path_relevant': bool(oracle.get('path_relevant')),
            'matched_evidence_markers': list(oracle.get('matched_evidence_markers') or []),
        }

    def _failure_category_from_outcome(self, *, setup_success: bool, triggered: bool, oracle_reason: str = '', execution_success: bool = True, error: str = '', validation_failed: bool = False) -> Optional[str]:
        if triggered:
            return None
        if validation_failed:
            return 'proof_script_invalid'
        if not setup_success:
            return 'setup_failed'
        reason = str(oracle_reason or '').lower()
        detail = str(error or '').lower()
        if reason == 'setup_stage_only':
            return 'setup_crashed_unrelated'
        if reason == 'strong_signal_no_target':
            return 'target_unresolved'
        if reason == 'path_not_relevant':
            return 'oracle_not_relevant'
        if reason == 'self_report_only':
            return 'self_report_only'
        if reason == 'non_evidence':
            return 'trigger_reached_no_oracle'
        if reason in {'no_oracle_match', 'oracle_not_observed'}:
            return 'trigger_not_reached'
        if not execution_success or any(token in detail for token in ['timed out', 'timeout', 'could not connect', 'connection refused', 'missing browser target url']):
            return 'environment_failure'
        return 'trigger_reached_no_oracle'

    def _format_live_test_result(self, *, live_result: Any, validation_method: str, setup_result: Dict[str, Any], target_url: str, exploit_contract: Optional[Dict[str, Any]] = None, pov_script: str = '') -> Dict[str, Any]:
        family = 'browser' if validation_method == 'browser_live_contract' else 'http'
        live_policy = oracle_policy.evaluate_live_proof_outcome(
            list(getattr(live_result, 'evidence', []) or []),
            target_route=str((exploit_contract or {}).get('target_route') or (exploit_contract or {}).get('target_entrypoint') or target_url or ''),
            target_dom_selector=str((exploit_contract or {}).get('target_dom_selector') or ''),
            target_url=target_url,
            response_preview=str(getattr(live_result, 'response_preview', '') or ''),
            pov_script=pov_script,
            stage='trigger',
            runtime_family=family,
        )
        classified_reason = self._classify_live_oracle_reason(
            live_result=live_result,
            validation_method=validation_method,
            exploit_contract=exploit_contract,
            target_url=target_url,
        )
        triggered = bool(live_policy.get('triggered', False)) and classified_reason != 'no_oracle_match'
        if triggered:
            oracle_reason = classified_reason
        elif classified_reason == 'no_oracle_match' and not getattr(live_result, 'error', ''):
            oracle_reason = 'no_oracle_match'
        else:
            oracle_reason = str(live_policy.get('reason') or ('environment_failure' if getattr(live_result, 'error', '') else 'no_oracle_match'))
        path_relevant = bool(live_policy.get('path_relevant', False))
        oracle = {
            'triggered': triggered,
            'reason': oracle_reason,
            'matched_evidence_markers': list(getattr(live_result, 'evidence', []) or []),
            'path_relevant': path_relevant,
            'execution_stage': 'trigger',
            'proof_verdict': 'proven' if triggered else ('setup_only' if live_policy.get('reason') == 'setup_stage_only' else 'failed'),
            'signal_class': live_policy.get('signal_class', 'live'),
            'self_report_only': live_policy.get('self_report_only', False),
        }
        trigger_plan = self._build_trigger_plan(exploit_contract or {'proof_plan': {'execution_surface': 'browser_dom' if validation_method == 'browser_live_contract' else 'live_app', 'input_mode': 'request'}, 'target_route': target_url})
        trigger_result = {
            'stage': 'trigger',
            'success': bool(oracle['triggered']),
            'stdout': str(getattr(live_result, 'response_preview', '') or ''),
            'stderr': str(getattr(live_result, 'error', '') or ''),
            'exit_code': 0 if getattr(live_result, 'success', False) else -1,
            'oracle_reason': oracle_reason,
            'path_relevant': path_relevant,
            'matched_evidence_markers': list(getattr(live_result, 'evidence', []) or []),
            'trigger_plan': asdict(trigger_plan),
        }
        failure_category = self._failure_category_from_outcome(
            setup_success=bool(setup_result.get('success')),
            triggered=bool(oracle['triggered']),
            oracle_reason=oracle_reason,
            execution_success=bool(getattr(live_result, 'success', False)),
            error=str(getattr(live_result, 'error', '') or ''),
        )
        return {
            'success': bool(getattr(live_result, 'success', False)),
            'vulnerability_triggered': bool(oracle['triggered']),
            'stdout': str(getattr(live_result, 'response_preview', '') or ''),
            'stderr': str(getattr(live_result, 'error', '') or ''),
            'exit_code': 0 if getattr(live_result, 'success', False) else -1,
            'execution_time_s': float(getattr(live_result, 'response_time_ms', 0.0) or 0.0) / 1000.0,
            'timestamp': datetime.utcnow().isoformat(),
            'target_url': target_url,
            'evidence': list(getattr(live_result, 'evidence', []) or []),
            'validation_method': validation_method,
            'oracle_result': oracle,
            'failure_category': failure_category,
            'setup_result': setup_result,
            'trigger_result': trigger_result,
            'proof_verdict': oracle['proof_verdict'],
        }

    def _build_runtime_evidence(self, result: Dict[str, Any], *, validation_method: str, target_binary: Optional[str] = None, target_url: Optional[str] = None) -> Dict[str, Any]:
        stdout = str(result.get("stdout", "") or "")
        stderr = str(result.get("stderr", "") or "")
        exit_code = result.get("exit_code", -1)
        combined = (stdout + "\n" + stderr).strip()
        summary = "Runtime harness executed"
        lowered = combined.lower()
        if 'addresssanitizer' in lowered:
            summary = 'AddressSanitizer reported memory corruption'
        elif 'undefinedbehaviorsanitizer' in lowered:
            summary = 'UndefinedBehaviorSanitizer reported unsafe behavior'
        elif 'assertion `' in lowered or 'assertion failed' in lowered:
            summary = 'Assertion failure observed in vulnerable path'
        elif 'segmentation fault' in lowered or exit_code in {-11, 139}:
            summary = 'Segmentation fault observed during exploit execution'
        elif exit_code in {-6, 134}:
            summary = 'Process aborted during exploit execution'
        elif 'vulnerability triggered' in lowered:
            summary = 'Exploit reported vulnerability triggered'
        elif 'invoked target entrypoint' in lowered:
            summary = 'Native harness reached target entrypoint'
        excerpt = (stderr or stdout)[:1200]
        return {
            'summary': summary,
            'validation_method': validation_method,
            'target_binary': target_binary,
            'target_url': target_url,
            'exit_code': exit_code,
            'stdout_excerpt': stdout[:1200],
            'stderr_excerpt': stderr[:1200],
            'combined_excerpt': excerpt,
            'execution_stage': 'trigger',
        }

    def _build_targeted_native_harness(self, scan_id: str, cwe_type: str, vulnerable_code: str, exploit_contract: Optional[Dict[str, Any]], language: str) -> Dict[str, Any]:
        exploit_contract = exploit_contract or {}
        target_entrypoint = str(exploit_contract.get("target_entrypoint") or "")
        entry_name = ""
        if target_entrypoint.lower() in {'unknown', 'none', 'n/a'}:
            target_entrypoint = ''
        if re.fullmatch(r"[A-Za-z_]\w*", target_entrypoint) and target_entrypoint.lower() not in self.INVALID_NATIVE_ENTRYPOINTS:
            entry_name = target_entrypoint
        else:
            inferred = re.search(r"(?:static\s+)?(?:[\w\*\s]+)\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", vulnerable_code)
            if inferred and inferred.group(1).lower() not in self.INVALID_NATIVE_ENTRYPOINTS:
                entry_name = inferred.group(1)
            else:
                backticked = re.search(r"`([A-Za-z_]\w*)\s*\(", target_entrypoint)
                if backticked and backticked.group(1).lower() not in self.INVALID_NATIVE_ENTRYPOINTS:
                    entry_name = backticked.group(1)
                elif "main" in target_entrypoint.lower():
                    entry_name = "main"
        if not vulnerable_code.strip() or not entry_name or entry_name.lower() in self.INVALID_NATIVE_ENTRYPOINTS:
            return {"success": False, "error": "No compilable vulnerable snippet or target entrypoint for targeted native harness", "binary_path": None}

        def _signature_map(name: str) -> Dict[str, Any]:
            return {
                "buf_len_payload": re.search(rf"(?:static\s+)?(?:[\w\*\s]+)\b{re.escape(name)}\s*\(\s*char\s*\*\s*\w+\s*,\s*size_t\s+\w+\s*,\s*const\s+char\s*\*\s*\w+\s*\)", vulnerable_code),
                "buf_payload": re.search(rf"(?:static\s+)?(?:[\w\*\s]+)\b{re.escape(name)}\s*\(\s*char\s*\*\s*\w+\s*,\s*const\s+char\s*\*\s*\w+\s*\)", vulnerable_code),
                "payload_only": re.search(rf"(?:static\s+)?(?:[\w\*\s]+)\b{re.escape(name)}\s*\(\s*const\s+char\s*\*\s*\w+\s*\)", vulnerable_code),
            }

        signatures = _signature_map(entry_name)
        strategy = next((name for name, match in signatures.items() if match), None)
        if not strategy:
            inferred = re.search(r"(?:static\s+)?(?:[\w\*\s]+)\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{", vulnerable_code)
            inferred_name = inferred.group(1) if inferred else ""
            if inferred_name and inferred_name.lower() not in self.INVALID_NATIVE_ENTRYPOINTS and inferred_name != entry_name:
                entry_name = inferred_name
                signatures = _signature_map(entry_name)
                strategy = next((name for name, match in signatures.items() if match), None)
        if not strategy:
            return {"success": False, "error": f"No supported native harness signature detected for {entry_name}", "binary_path": None}

        compiler = "gcc" if language == "c" else "g++"
        if not shutil.which(compiler):
            return {"success": False, "error": f"{compiler} is not installed", "binary_path": None}

        temp_dir = tempfile.mkdtemp(prefix=f"autopov_native_harness_{scan_id}_")
        source_path = os.path.join(temp_dir, f"targeted_harness.{'c' if language == 'c' else 'cpp'}")
        binary_path = os.path.join(temp_dir, "targeted_harness")

        call_map = {
            "buf_len_payload": f"{entry_name}(frame.buf, sizeof(frame.buf), payload);",
            "buf_payload": f"{entry_name}(frame.buf, payload);",
            "payload_only": f"{entry_name}(payload);",
        }
        snippet = vulnerable_code
        if entry_name.lower() != "main" and re.search(r"\bmain\s*\(", vulnerable_code):
            snippet = "#define main autopov_original_main\n" + vulnerable_code + "\n#undef main\n"

        if strategy == "payload_only":
            success_check = '    fprintf(stdout, "[AutoPoV] invoked target entrypoint\\n");\n    return 0;'
        else:
            success_check = (
                '    for (size_t i = 0; i < sizeof(frame.canary); ++i) {\n'
                '        if (frame.canary[i] != 0x5A) {\n'
                '            fprintf(stdout, "VULNERABILITY TRIGGERED\\n");\n'
                '            return 0;\n'
                '        }\n'
                '    }\n'
                '    fprintf(stderr, "[AutoPoV] no sanitizer signal or overwrite observed\\n");\n'
                '    return 2;'
            )

        harness = (
            '#include <stdio.h>\n'
            '#include <stdlib.h>\n'
            '#include <string.h>\n'
            '#include <stdint.h>\n'
            '#include <assert.h>\n'
            f'{snippet}\n'
            'int main(void) {\n'
            '    struct {\n'
            '        char buf[64];\n'
            '        unsigned char canary[32];\n'
            '    } frame;\n'
            '    char payload[4096];\n'
            '    memset(&frame, 0, sizeof(frame));\n'
            '    memset(frame.canary, 0x5A, sizeof(frame.canary));\n'
            '    memset(payload, \"A\"[0], sizeof(payload) - 1);\n'
            '    payload[sizeof(payload) - 1] = 0;\n'
            f'    fprintf(stderr, "[AutoPoV] invoking {entry_name} via {strategy}\\n");\n'
            f'    {call_map[strategy]}\n'
            f'{success_check}\n'
            '}\n'
        )

        Path(source_path).write_text(harness, encoding='utf-8')
        result = subprocess.run([
            compiler,
            source_path,
            '-O0',
            '-g',
            '-fsanitize=address,undefined',
            '-fno-omit-frame-pointer',
            '-o',
            binary_path,
        ], capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return {"success": False, "error": result.stderr or result.stdout, "binary_path": None}
        return {"success": True, "error": None, "binary_path": binary_path, "build_method": f"targeted_native_harness:{strategy}", "temp_dir": temp_dir}

    def test_pov_against_app(self, pov_script: str, scan_id: str, cwe_type: str, target_url: str, language: str = "python", exploit_contract: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        start_time = datetime.utcnow()
        temp_dir = tempfile.mkdtemp(prefix=f"pov_{scan_id}_")
        preflight = {
            "ok": bool(target_url),
            "checks": [{"check": "target_url_present", "ok": bool(target_url), "target_url": target_url}],
            "issues": [] if target_url else ["Target URL is missing"],
        }
        try:
            pov_filename = "pov.py" if language == "python" else "pov.js"
            patched = self._apply_deterministic_script_skeleton(self._patch_target_refs(pov_script, target_url=target_url), language=language, mode='live_app', exploit_contract=exploit_contract, target_url=target_url, codebase_path=temp_dir)
            with open(os.path.join(temp_dir, pov_filename), "w", encoding="utf-8") as handle:
                handle.write(patched)
            env = os.environ.copy()
            env["TARGET_URL"] = target_url
            env = self._apply_setup_environment(env, exploit_contract)
            setup_plan = self._build_setup_plan(exploit_contract, base_dir=temp_dir, target_url=target_url)
            trigger_plan = self._build_trigger_plan(exploit_contract)
            setup_result = self._run_script_setup_plugins(env, temp_dir, exploit_contract)
            if not preflight.get('ok', True):
                setup_result = self._build_setup_result(stage='setup', success=False, stderr='\n'.join(preflight.get('issues') or []), artifacts=list(setup_result.get('artifacts') or []), notes=list(dict.fromkeys((setup_result.get('notes') or []) + [check.get('check') for check in (preflight.get('checks') or []) if check.get('ok')])))
            guardrail_issues = self._non_native_script_guardrail_issues(patched, exploit_contract, mode='live_app')
            if guardrail_issues:
                end_time = datetime.utcnow()
                stderr = '\n'.join(guardrail_issues)
                return {"success": True, "vulnerability_triggered": False, "stdout": "", "stderr": stderr, "exit_code": -1, "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_url": target_url, "validation_method": "script_against_live_app", "preflight": preflight, "oracle_result": {"triggered": False, "reason": "guardrail_rejected", "matched_evidence_markers": [], "path_relevant": False, "execution_stage": "trigger", "proof_verdict": "failed"}, "failure_category": "guardrail_rejected", "setup_result": {**setup_result, "setup_plan": asdict(setup_plan)}, "trigger_result": {"stage": "trigger", "success": False, "stdout": "", "stderr": stderr, "exit_code": -1, "oracle_reason": "guardrail_rejected", "path_relevant": False, "matched_evidence_markers": [], "trigger_plan": asdict(trigger_plan)}, "proof_verdict": "failed"}
            result = self._run_script(temp_dir, pov_filename, language, env)
            oracle = self._evaluate_proof_outcome(result.get("stdout", ""), result.get("stderr", ""), result.get("exit_code", -1), exploit_contract, pov_script=patched, execution_stage='trigger')
            end_time = datetime.utcnow()
            failure_category = self._failure_category_from_outcome(setup_success=bool(setup_result.get('success')), triggered=bool(oracle.get("triggered")), oracle_reason=oracle.get('reason', ''), execution_success=not bool(result.get("failure_category")), error=str(result.get("failure_category") or result.get("stderr", "")))
            return {"success": True, "vulnerability_triggered": bool(oracle.get("triggered")), "stdout": result.get("stdout", ""), "stderr": result.get("stderr", ""), "exit_code": result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_url": target_url, "validation_method": "script_against_live_app", "preflight": preflight, "oracle_result": oracle, "failure_category": failure_category, "setup_result": setup_result, "trigger_result": self._build_trigger_result(oracle=oracle, stdout=result.get("stdout", ""), stderr=result.get("stderr", ""), exit_code=result.get("exit_code", -1)), "proof_verdict": oracle.get('proof_verdict', 'failed')}
        except Exception as e:
            end_time = datetime.utcnow()
            return {"success": False, "vulnerability_triggered": False, "stdout": "", "stderr": str(e), "exit_code": -1, "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_url": target_url, "preflight": preflight, "failure_category": "execution_error"}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_pov_against_repo(self, pov_script: str, scan_id: str, cwe_type: str, codebase_path: str, language: str = "python", exploit_contract: Optional[Dict[str, Any]] = None, filepath: str = "") -> Dict[str, Any]:
        start_time = datetime.utcnow()
        temp_dir = tempfile.mkdtemp(prefix=f"pov_repo_{scan_id}_")
        preflight = self._repo_preflight(codebase_path, exploit_contract, filepath=filepath)
        try:
            pov_filename = "pov.py" if language == "python" else "pov.js"
            pov_path = os.path.join(temp_dir, pov_filename)
            with open(pov_path, "w", encoding="utf-8") as handle:
                handle.write(self._apply_deterministic_script_skeleton(pov_script, language=language, mode='repo_script', exploit_contract=exploit_contract, codebase_path=codebase_path))
            env = os.environ.copy()
            env["CODEBASE_PATH"] = codebase_path
            env["TARGET_ENTRYPOINT"] = str((exploit_contract or {}).get("target_entrypoint") or "")
            if language == "python":
                env["PYTHONPATH"] = codebase_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
            else:
                env["NODE_PATH"] = codebase_path + (os.pathsep + env["NODE_PATH"] if env.get("NODE_PATH") else "")
            env = self._apply_setup_environment(env, exploit_contract)
            setup_plan = self._build_setup_plan(exploit_contract, base_dir=codebase_path)
            trigger_plan = self._build_trigger_plan(exploit_contract)
            setup_result = self._run_script_setup_plugins(env, codebase_path, exploit_contract)
            if not preflight.get('ok', True):
                setup_result = self._build_setup_result(stage='setup', success=False, stderr='\n'.join(preflight.get('issues') or []), artifacts=list(setup_result.get('artifacts') or []), notes=list(dict.fromkeys((setup_result.get('notes') or []) + [check.get('check') for check in (preflight.get('checks') or []) if check.get('ok')])))
            guardrail_issues = self._non_native_script_guardrail_issues(Path(pov_path).read_text(encoding='utf-8'), exploit_contract, mode='repo_script')
            if guardrail_issues:
                end_time = datetime.utcnow()
                stderr = '\n'.join(guardrail_issues)
                return {"success": True, "vulnerability_triggered": False, "stdout": "", "stderr": stderr, "exit_code": -1, "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "validation_method": "script_against_repo", "preflight": preflight, "oracle_result": {"triggered": False, "reason": "guardrail_rejected", "matched_evidence_markers": [], "path_relevant": False, "execution_stage": "trigger", "proof_verdict": "failed"}, "failure_category": "guardrail_rejected", "setup_result": {**setup_result, "setup_plan": asdict(setup_plan)}, "trigger_result": {"stage": "trigger", "success": False, "stdout": "", "stderr": stderr, "exit_code": -1, "oracle_reason": "guardrail_rejected", "path_relevant": False, "matched_evidence_markers": [], "trigger_plan": asdict(trigger_plan)}, "proof_verdict": "failed"}
            result = self._run_script(codebase_path, pov_path, language, env)
            oracle = self._evaluate_proof_outcome(result.get("stdout", ""), result.get("stderr", ""), result.get("exit_code", -1), exploit_contract, filepath=filepath, pov_script=pov_script, execution_stage='trigger')
            end_time = datetime.utcnow()
            failure_category = self._failure_category_from_outcome(setup_success=bool(setup_result.get('success')), triggered=bool(oracle.get("triggered")), oracle_reason=oracle.get('reason', ''), execution_success=not bool(result.get("failure_category")), error=str(result.get("failure_category") or result.get("stderr", "")))
            return {"success": True, "vulnerability_triggered": bool(oracle.get("triggered")), "stdout": result.get("stdout", ""), "stderr": result.get("stderr", ""), "exit_code": result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "validation_method": "script_against_repo", "preflight": preflight, "oracle_result": oracle, "failure_category": failure_category, "setup_result": setup_result, "trigger_result": self._build_trigger_result(oracle=oracle, stdout=result.get("stdout", ""), stderr=result.get("stderr", ""), exit_code=result.get("exit_code", -1)), "proof_verdict": oracle.get('proof_verdict', 'failed')}
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_binary_target(self, pov_script: str, scan_id: str, cwe_type: str, codebase_path: str, language: str, exploit_contract: Dict[str, Any], vulnerable_code: str = "", filepath: str = "") -> Dict[str, Any]:
        start_time = datetime.utcnow()
        build = get_app_runner().build_native_binary(scan_id, codebase_path, language=language)
        script_result = None
        target_entrypoint = str((exploit_contract or {}).get("target_entrypoint") or "")
        plan = self._proof_plan(exploit_contract)
        execution_surface = str(plan.get('execution_surface') or (exploit_contract or {}).get('execution_surface') or "").lower()
        function_surface = execution_surface in {'function_call', 'function_harness'}
        if function_surface:
            # Log surface so scan artefacts expose the surface decision for debugging.
            self._log(f"[test_binary_target] execution_surface={execution_surface!r} → function_surface=True (keygen/binary-path setup skipped)")
        binary_target = (not function_surface) and (
            self._is_binary_native_target(target_entrypoint, filepath, exploit_contract)
            or self._script_uses_target_binary(pov_script)
        )

        if build.get("success"):
            preflight = self._native_preflight(build["binary_path"], codebase_path, exploit_contract, filepath=filepath)
            setup_plan = self._build_setup_plan(exploit_contract, base_dir=codebase_path)
            trigger_plan = self._build_trigger_plan(effective_contract if 'effective_contract' in locals() else exploit_contract)
            setup_result = self._build_setup_result(stage='setup', success=bool(preflight.get('ok', True)), stderr='\n'.join(preflight.get('issues') or []), artifacts=[build.get("binary_path", "")], notes=[check.get('check') for check in (preflight.get('checks') or []) if check.get('ok')])
            effective_contract = (preflight.get("effective_contract") or exploit_contract or {})
            trigger_plan = self._build_trigger_plan(effective_contract)
            direct_binary_result = self._run_native_binary_with_contract(build["binary_path"], codebase_path, effective_contract, filepath=filepath)
            effective_contract = direct_binary_result.get("effective_contract") or effective_contract
            selected_binary = direct_binary_result.get("selected_binary") or build["binary_path"]
            direct_oracle = self._evaluate_proof_outcome(direct_binary_result.get("stdout", ""), direct_binary_result.get("stderr", ""), direct_binary_result.get("exit_code", -1), effective_contract, filepath=filepath, execution_stage='trigger')
            direct_triggered = direct_oracle.get('triggered', False)
            direct_evidence = self._build_runtime_evidence(direct_binary_result, validation_method="native_binary_contract", target_binary=selected_binary)
            if direct_triggered:
                end_time = datetime.utcnow()
                return {"success": True, "vulnerability_triggered": True, "stdout": direct_binary_result.get("stdout", ""), "stderr": direct_binary_result.get("stderr", ""), "exit_code": direct_binary_result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": selected_binary, "validation_method": "native_binary_contract", "proof_summary": direct_evidence["summary"], "evidence": direct_evidence, "preflight": preflight, "oracle_result": direct_oracle, "failure_category": None, "surface": direct_binary_result.get("surface"), "baseline_result": direct_binary_result.get("baseline_result")}

            temp_dir = tempfile.mkdtemp(prefix=f"pov_native_{scan_id}")
            try:
                script_language = "javascript" if "console.log" in pov_script or "require(" in pov_script else "python"
                pov_filename = "pov.js" if script_language == "javascript" else "pov.py"
                patched = self._repair_native_runtime_script(self._patch_target_refs(pov_script, target_binary=selected_binary))
                with open(os.path.join(temp_dir, pov_filename), "w", encoding="utf-8") as handle:
                    handle.write(patched)
                env = os.environ.copy()
                env = self._prepare_native_runtime_env(env, temp_dir, selected_binary, codebase_path, effective_contract)
                # Run setup plugins (keygen bootstrap, etc.) and let them mutate env
                # so AUTOPOV_BOOTSTRAP_HOME is set before the PoV script runs.
                self._run_native_setup_plugins(selected_binary, env, effective_contract)
                if effective_contract.get("inputs"):
                    first_input = effective_contract["inputs"][0]
                    env["TARGET_INPUT"] = json.dumps(first_input) if isinstance(first_input, dict) else str(first_input)
                guardrail_issues = self._native_script_guardrail_issues(patched, effective_contract, direct_binary_result.get("surface") or preflight.get("surface"))
                if guardrail_issues:
                    end_time = datetime.utcnow()
                    stderr = "\n".join(guardrail_issues)
                    evidence = self._build_runtime_evidence({"stdout": "", "stderr": stderr, "exit_code": -1}, validation_method="native_binary_guardrails", target_binary=selected_binary)
                    failure_category = 'guardrail_rejected'
                    return {"success": True, "vulnerability_triggered": False, "stdout": "", "stderr": stderr, "exit_code": -1, "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": selected_binary, "validation_method": "native_binary_guardrails", "proof_summary": evidence["summary"], "evidence": evidence, "preflight": preflight, "oracle_result": {"triggered": False, "matched_markers": [], "reason": "guardrail_rejected"}, "failure_category": failure_category, "surface": direct_binary_result.get("surface"), "baseline_result": direct_binary_result.get("baseline_result"), "recommended_input_mode": preflight.get("recommended_input_mode"), "supported_input_modes": preflight.get("supported_input_modes"), 'setup_result': direct_binary_result.get('setup_result') or setup_result, 'trigger_result': {'stage': 'trigger', 'success': False, 'stdout': '', 'stderr': stderr, 'exit_code': -1, 'oracle_reason': 'guardrail_rejected', 'path_relevant': False, 'matched_evidence_markers': []}, 'proof_verdict': 'failed'}
                script_result = self._run_script(codebase_path, os.path.join(temp_dir, pov_filename), script_language, env)
                oracle = self._evaluate_proof_outcome(script_result.get("stdout", ""), script_result.get("stderr", ""), script_result.get("exit_code", -1), effective_contract, filepath=filepath, pov_script=patched, execution_stage='trigger')
                triggered = oracle.get('triggered', False)
                evidence = self._build_runtime_evidence(script_result, validation_method="native_binary_harness", target_binary=selected_binary)
                if triggered:
                    end_time = datetime.utcnow()
                    return {"success": True, "vulnerability_triggered": True, "stdout": script_result.get("stdout", ""), "stderr": script_result.get("stderr", ""), "exit_code": script_result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": selected_binary, "validation_method": "native_binary_harness", "proof_summary": evidence["summary"], "evidence": evidence, "preflight": preflight, "oracle_result": oracle, "failure_category": None, "surface": direct_binary_result.get("surface"), "baseline_result": script_result.get("baseline_result"), 'setup_result': {**(direct_binary_result.get('setup_result') or setup_result), 'setup_plan': asdict(setup_plan)}, 'trigger_result': {**self._build_trigger_result(oracle=oracle, stdout=script_result.get("stdout", ""), stderr=script_result.get("stderr", ""), exit_code=script_result.get("exit_code", -1)), 'trigger_plan': asdict(trigger_plan)}, 'proof_verdict': oracle.get('proof_verdict', 'failed')}
                if binary_target:
                    end_time = datetime.utcnow()
                    failure_category = 'preflight_failed' if not preflight.get('ok', True) else ('path_exercised_no_oracle' if direct_binary_result.get('path_exercised') or script_result.get('path_exercised') else 'oracle_not_observed')
                    staged_setup_result = direct_binary_result.get('setup_result') or setup_result
                    staged_trigger_result = self._build_trigger_result(oracle=oracle, stdout=script_result.get("stdout", ""), stderr=script_result.get("stderr", ""), exit_code=script_result.get("exit_code", -1))
                    return {"success": True, "vulnerability_triggered": False, "stdout": script_result.get("stdout", ""), "stderr": script_result.get("stderr", ""), "exit_code": script_result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": selected_binary, "validation_method": "native_binary_harness", "proof_summary": evidence["summary"], "evidence": evidence, "preflight": preflight, "oracle_result": oracle, "failure_category": failure_category, "surface": direct_binary_result.get("surface"), "baseline_result": script_result.get("baseline_result"), "recommended_input_mode": preflight.get("recommended_input_mode"), "supported_input_modes": preflight.get("supported_input_modes"), 'setup_result': {**staged_setup_result, 'setup_plan': asdict(setup_plan)}, 'trigger_result': {**staged_trigger_result, 'trigger_plan': asdict(trigger_plan)}, 'proof_verdict': oracle.get('proof_verdict', 'failed')}
            finally:
                shutil.rmtree(temp_dir, ignore_errors=True)

        elif binary_target:
            end_time = datetime.utcnow()
            stderr = build.get("error", "Failed to build target binary")
            oracle = {'triggered': False, 'reason': 'setup_failed', 'path_relevant': False, 'matched_evidence_markers': [], 'proof_verdict': 'failed'}
            return {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": stderr,
                "exit_code": -1,
                "execution_time_s": (end_time - start_time).total_seconds(),
                "timestamp": end_time.isoformat(),
                "validation_method": "native_binary_build",
                "proof_infrastructure_error": True,
                'failure_category': 'infrastructure_failure',
                'setup_result': {**self._build_setup_result(stage='setup', success=False, stderr=stderr, artifacts=[path for path in [build.get("binary_path")] if path], notes=['native build failed before trigger execution']), 'setup_plan': asdict(self._build_setup_plan(exploit_contract, base_dir=codebase_path))},
                'trigger_result': {**self._build_trigger_result(oracle=oracle, stdout='', stderr=stderr, exit_code=-1), 'trigger_plan': asdict(self._build_trigger_plan(exploit_contract))},
                'proof_verdict': oracle['proof_verdict'],
                'oracle_result': oracle,
            }

        targeted = self._build_targeted_native_harness(scan_id, cwe_type, vulnerable_code, exploit_contract, language)
        if targeted.get("success") and targeted.get("binary_path"):
            try:
                native_result = self._run_binary(targeted["binary_path"])
                triggered = self._native_triggered(native_result.get("stdout", ""), native_result.get("stderr", ""), native_result.get("exit_code", -1), exploit_contract)
                evidence = self._build_runtime_evidence(native_result, validation_method="targeted_native_sanitizer_harness", target_binary=targeted["binary_path"])
                end_time = datetime.utcnow()
                return {"success": True, "vulnerability_triggered": bool(triggered), "stdout": native_result.get("stdout", ""), "stderr": native_result.get("stderr", ""), "exit_code": native_result.get("exit_code", -1), "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": end_time.isoformat(), "target_binary": targeted["binary_path"], "validation_method": "targeted_native_sanitizer_harness", "proof_summary": evidence["summary"], "evidence": evidence}
            finally:
                shutil.rmtree(targeted.get("temp_dir") or "", ignore_errors=True)

        end_time = datetime.utcnow()
        stderr = (script_result or {}).get("stderr") or targeted.get("error") or build.get("error", "Failed to build target binary")
        failure_result = {"stdout": (script_result or {}).get("stdout", ""), "stderr": stderr, "exit_code": (script_result or {}).get("exit_code", -1)}
        evidence = self._build_runtime_evidence(failure_result, validation_method="native_binary_build", target_binary=build.get("binary_path"))
        proof_infra = bool(build.get("proof_infrastructure_error")) or not build.get("success")
        setup_artifacts = [path for path in [build.get("binary_path"), targeted.get("binary_path")] if path]
        setup_success = bool(build.get("success")) and not proof_infra
        setup_result = self._build_setup_result(stage='setup', success=setup_success, stderr='' if setup_success else stderr, artifacts=setup_artifacts, notes=['native build prepared for trigger execution'] if setup_success else ['native build or harness preparation failed'])
        oracle = {'triggered': False, 'reason': 'setup_failed' if proof_infra else 'no_oracle_match', 'path_relevant': False, 'matched_evidence_markers': [], 'proof_verdict': 'failed'}
        trigger_result = self._build_trigger_result(oracle=oracle, stdout=failure_result["stdout"], stderr=stderr, exit_code=failure_result["exit_code"])
        return {"success": False, "vulnerability_triggered": False, "stdout": failure_result["stdout"], "stderr": stderr, "exit_code": failure_result["exit_code"], "execution_time_s": (end_time - start_time).total_seconds(), "timestamp": datetime.utcnow().isoformat(), "validation_method": "native_binary_build", "proof_infrastructure_error": proof_infra, "proof_summary": evidence["summary"], "evidence": evidence, "failure_category": 'infrastructure_failure' if proof_infra else 'harness_unsupported', 'setup_result': setup_result, 'trigger_result': trigger_result, 'proof_verdict': oracle['proof_verdict'], 'oracle_result': oracle}

    def test_with_contract(self, pov_script: str, scan_id: str, cwe_type: str, codebase_path: str, exploit_contract: Optional[Dict[str, Any]], target_language: str = "python", vulnerable_code: str = "", filepath: str = "") -> Dict[str, Any]:
        """Emergency fallback harness for when Docker is unavailable.

        Primary execution is via docker_runner.run_pov() which routes each
        finding to the correct autopov/proof-* image based on language.
        This method is only called when Docker is not available (e.g. unit-test
        environments or local development without Docker running).
        """
        exploit_contract = exploit_contract or {}
        plan = self._proof_plan(exploit_contract)
        runtime_profile = (exploit_contract.get("runtime_profile") or target_language or "python").lower()
        runtime_family = str(plan.get('runtime_family') or runtime_profile or target_language or 'python').lower()
        execution_surface = str(plan.get('execution_surface') or '').lower()
        target_entrypoint = str(exploit_contract.get("target_entrypoint") or "")
        if runtime_family in {"native", "c", "cpp", "binary"} or runtime_profile in {"c", "cpp", "binary", "native"} or target_language in {"c", "cpp"} or execution_surface == 'binary_cli':
            native_language = "c" if target_language == "c" else "cpp"
            return self.test_binary_target(pov_script, scan_id, cwe_type, codebase_path, native_language, exploit_contract, vulnerable_code=vulnerable_code, filepath=filepath)
        # function_call surface can be generated for native/C targets when the proof plan
        # specifies surface=function_call and input=function/c.  In that case the runtime
        # family is still native — route to the native binary path, not the Python runner.
        if execution_surface == 'function_call' and (
            runtime_profile in {'c', 'cpp', 'native', 'binary'}
            or target_language in {'c', 'cpp'}
            or runtime_family in {'c', 'cpp', 'native', 'binary'}
        ):
            native_language = 'c' if target_language in {'c'} else 'cpp'
            return self.test_binary_target(pov_script, scan_id, cwe_type, codebase_path, native_language, exploit_contract, vulnerable_code=vulnerable_code, filepath=filepath)
        if runtime_family in {"web", "browser", "http"} or runtime_profile in {"web", "http", "browser"} or execution_surface in {'http_request', 'browser_dom'} or target_entrypoint.startswith("/") or target_entrypoint.startswith("http"):
            browser_dom = execution_surface == 'browser_dom' or runtime_family == 'browser' or runtime_profile == 'browser'
            target_url = exploit_contract.get("target_url") or exploit_contract.get("base_url")
            request_target = {"url": target_url or "", "method": exploit_contract.get("http_method", "GET")}
            if target_url:
                setup_result = self._run_live_setup_plugins(exploit_contract, target_url=str(target_url))
                if browser_dom:
                    prepared_pov = self._apply_deterministic_script_skeleton(pov_script, language='javascript', mode='browser_dom', exploit_contract=exploit_contract, target_url=str(target_url or request_target.get('url') or ''), codebase_path=codebase_path)
                    request_config = get_live_app_tester()._build_request_config(prepared_pov, request_target, exploit_contract)
                    live = get_live_docker_tester().test_browser_interaction(scan_id, cwe_type, request_config, exploit_contract=exploit_contract)
                    return self._format_live_test_result(live_result=live, validation_method="browser_live_contract", setup_result=setup_result, target_url=str(getattr(live, 'target_url', '') or target_url), exploit_contract=exploit_contract, pov_script=prepared_pov)
                prepared_pov = self._apply_deterministic_script_skeleton(pov_script, language=self._detect_script_language(pov_script, runtime_profile=runtime_profile), mode='live_app', exploit_contract=exploit_contract, target_url=str(target_url or request_target.get('url') or ''), codebase_path=codebase_path)
                live = get_live_app_tester().test_against_live_app(prepared_pov, cwe_type, request_target, scan_id, exploit_contract=exploit_contract)
                return self._format_live_test_result(live_result=live, validation_method="live_app_contract", setup_result=setup_result, target_url=str(getattr(live, 'target_url', '') or target_url), exploit_contract=exploit_contract, pov_script=prepared_pov)
            started = get_app_runner().start_application(scan_id, codebase_path, target_language if target_language in {"python", "javascript", "typescript", "java"} else "javascript")
            setup_result = self._run_live_setup_plugins(exploit_contract, started=started)
            if started.get("success"):
                try:
                    request_target = {"url": started["url"], "method": exploit_contract.get("http_method", "GET")}
                    if browser_dom:
                        prepared_pov = self._apply_deterministic_script_skeleton(pov_script, language='javascript', mode='browser_dom', exploit_contract=exploit_contract, target_url=str(started.get('url') or request_target.get('url') or ''), codebase_path=codebase_path)
                        request_config = get_live_app_tester()._build_request_config(prepared_pov, request_target, exploit_contract)
                        live = get_live_docker_tester().test_browser_interaction(scan_id, cwe_type, request_config, exploit_contract=exploit_contract)
                        return self._format_live_test_result(live_result=live, validation_method="browser_live_contract", setup_result=setup_result, target_url=str(getattr(live, 'target_url', '') or started['url']), exploit_contract=exploit_contract, pov_script=prepared_pov)
                    prepared_pov = self._apply_deterministic_script_skeleton(pov_script, language=self._detect_script_language(pov_script, runtime_profile=runtime_profile), mode='live_app', exploit_contract=exploit_contract, target_url=str(started.get('url') or request_target.get('url') or ''), codebase_path=codebase_path)
                    live = get_live_app_tester().test_against_live_app(prepared_pov, cwe_type, request_target, scan_id, exploit_contract=exploit_contract)
                    return self._format_live_test_result(live_result=live, validation_method="live_app_contract", setup_result=setup_result, target_url=str(getattr(live, 'target_url', '') or started['url']), exploit_contract=exploit_contract, pov_script=prepared_pov)
                finally:
                    get_app_runner().stop_app(scan_id)
            return {
                'success': False,
                'vulnerability_triggered': False,
                'stdout': '',
                'stderr': str(started.get('error', '') or 'Failed to start target application'),
                'exit_code': -1,
                'execution_time_s': 0.0,
                'timestamp': datetime.utcnow().isoformat(),
                'target_url': str(target_url or ''),
                'evidence': [],
                'validation_method': 'browser_live_contract' if browser_dom else 'live_app_contract',
                'oracle_result': {'triggered': False, 'reason': 'setup_failed', 'matched_evidence_markers': [], 'path_relevant': False, 'execution_stage': 'setup', 'proof_verdict': 'failed'},
                'failure_category': 'setup_failed',
                'setup_result': setup_result,
                'trigger_result': {'stage': 'trigger', 'success': False, 'stdout': '', 'stderr': '', 'exit_code': -1, 'oracle_reason': 'setup_failed', 'path_relevant': False, 'matched_evidence_markers': []},
                'proof_verdict': 'failed',
            }
        if runtime_family in {"python", "node", "javascript", "typescript"} or runtime_profile in {"python", "javascript", "node", "typescript"} or execution_surface in {'repo_script', 'function_call'}:
            # function_call for native/C families is already handled above.
            # Only route here when the language is genuinely a script family.
            is_native_surface = (
                runtime_profile in {'c', 'cpp', 'native', 'binary'}
                or target_language in {'c', 'cpp'}
                or runtime_family in {'c', 'cpp', 'native', 'binary'}
            )
            if execution_surface == 'function_call' and is_native_surface:
                native_language = 'c' if target_language in {'c'} else 'cpp'
                return self.test_binary_target(pov_script, scan_id, cwe_type, codebase_path, native_language, exploit_contract, vulnerable_code=vulnerable_code, filepath=filepath)
            script_language = self._detect_script_language(pov_script, runtime_profile=runtime_profile)
            return self.test_pov_against_repo(pov_script, scan_id, cwe_type, codebase_path, language=script_language, exploit_contract=exploit_contract, filepath=filepath)
        script_language = self._detect_script_language(pov_script, runtime_profile=runtime_profile)
        target_url = exploit_contract.get("target_url") or exploit_contract.get("base_url") or "http://localhost:3000"
        return self.test_pov_against_app(pov_script, scan_id, cwe_type, target_url, language=script_language, exploit_contract=exploit_contract)


pov_tester = PoVTester()


def get_pov_tester() -> PoVTester:
    """Get the global PoV tester instance"""
    return pov_tester

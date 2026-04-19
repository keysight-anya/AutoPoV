"""
AutoPoV Probe Runner
Lightweight preflight execution that runs BEFORE PoV generation to give the LLM
concrete runtime data (actual binary path, accepted flags, crash behaviour, missing
shared libs) instead of forcing it to guess.

All probe steps are best-effort and non-fatal: any step that raises an exception or
returns non-zero simply records what it got and moves on.  The aggregated ProbeResult
is injected into exploit_contract['probe_context'] as a structured string so both
format_pov_generation_prompt and format_pov_refinement_prompt can include it in the
INPUT PAYLOAD JSON.

Public API
----------
    probe_result = run_probe(codebase_path, scan_id, exploit_contract)
    probe_context_str = format_probe_context(probe_result)
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import docker
    from docker.errors import DockerException, ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from app.config import settings


# ---------------------------------------------------------------------------
# ProbeResult schema
# ---------------------------------------------------------------------------

class ProbeResult:
    """Aggregated results from the preflight probe phase."""

    def __init__(self) -> None:
        self.probe_binary_path: str = ''
        self.probe_cli_flags: List[str] = []
        self.probe_crash_observed: bool = False
        self.probe_crash_input: str = ''
        self.probe_crash_signal: str = ''
        self.probe_crash_output: str = ''
        self.probe_ldd_missing: List[str] = []
        self.probe_interesting_strings: List[str] = []
        self.probe_build_succeeded: bool = False
        self.probe_build_log: str = ''
        self.probe_help_text: str = ''
        self.probe_input_surface: str = 'unknown'  # file_argument | stdin | argv_only | network | unknown
        self.probe_baseline_exit_code: int = -1   # exit code on known-good / empty input
        self.probe_baseline_stderr: str = ''      # stderr on known-good / empty input
        self.probe_skipped: bool = False
        self.probe_skip_reason: str = ''
        self.probe_duration_s: float = 0.0
        self.probe_error: str = ''
        # Surface-adaptive fields (Task 1)
        self.probe_surface_type: str = ''          # native_elf | python_module | node_module | web_service
        self.probe_entry_command: str = ''         # full command to invoke target
        self.probe_install_ok: bool = False        # True if package install succeeded
        self.probe_base_url: str = ''              # for web_service: http://localhost:<port>
        self.probe_exports: str = ''               # Task 2B: exported names from Python/Node package

    def to_dict(self) -> Dict[str, Any]:
        return {
            'probe_binary_path': self.probe_binary_path,
            'probe_cli_flags': self.probe_cli_flags,
            'probe_crash_observed': self.probe_crash_observed,
            'probe_crash_input': self.probe_crash_input,
            'probe_crash_signal': self.probe_crash_signal,
            'probe_crash_output': self.probe_crash_output[:1200] if self.probe_crash_output else '',
            'probe_ldd_missing': self.probe_ldd_missing,
            'probe_interesting_strings': self.probe_interesting_strings,
            'probe_build_succeeded': self.probe_build_succeeded,
            'probe_build_log': self.probe_build_log[-600:] if self.probe_build_log else '',
            'probe_help_text': self.probe_help_text,
            'probe_exports': self.probe_exports,
            'probe_input_surface': self.probe_input_surface,
            'probe_baseline_exit_code': self.probe_baseline_exit_code,
            'probe_baseline_stderr': self.probe_baseline_stderr[:500] if self.probe_baseline_stderr else '',
            'probe_skipped': self.probe_skipped,
            'probe_skip_reason': self.probe_skip_reason,
            'probe_error': self.probe_error,
            # Surface-adaptive fields
            'probe_surface_type': self.probe_surface_type,
            'probe_entry_command': self.probe_entry_command,
            'probe_install_ok': self.probe_install_ok,
            'probe_base_url': self.probe_base_url,
        }


def format_probe_context(probe: ProbeResult) -> str:
    """Render a ProbeResult as a compact plain-text block for the LLM prompt.

    The output is included as 'probe_context' in the INPUT PAYLOAD JSON so the
    model knows the actual binary path, CLI flags it accepts, and whether a
    crash was already observed with an empty or trivial input.
    """
    if probe.probe_skipped:
        return f'[probe skipped: {probe.probe_skip_reason}]'

    lines: List[str] = []
    if probe.probe_surface_type:
        lines.append(f'surface_type: {probe.probe_surface_type}')
    if probe.probe_entry_command:
        lines.append(f'entry_command: {probe.probe_entry_command}')
    if probe.probe_base_url:
        lines.append(f'base_url: {probe.probe_base_url}')
    if probe.probe_binary_path:
        lines.append(f'binary: {probe.probe_binary_path}')
    if probe.probe_build_succeeded:
        lines.append('build: success')
    elif probe.probe_build_log:
        snippet = probe.probe_build_log.strip()[-400:]
        lines.append(f'build: FAILED\nbuild_log_tail:\n{snippet}')
    if probe.probe_cli_flags:
        lines.append('cli_flags: ' + ', '.join(probe.probe_cli_flags[:30]))
    if probe.probe_ldd_missing:
        lines.append('missing_runtime_libs: ' + ', '.join(probe.probe_ldd_missing))
    if probe.probe_input_surface and probe.probe_input_surface != 'unknown':
        lines.append(f'input_surface: {probe.probe_input_surface}')
    if probe.probe_crash_observed:
        lines.append(f'crash_probe: CRASH OBSERVED (signal: {probe.probe_crash_signal or "unknown"})')
        lines.append(f'crash_input: {repr(probe.probe_crash_input)[:120]}')
        if probe.probe_crash_output:
            lines.append(f'crash_output_excerpt:\n{probe.probe_crash_output[:500]}')
    else:
        lines.append('crash_probe: no crash with empty/trivial inputs')
    if probe.probe_interesting_strings:
        lines.append('interesting_strings: ' + '; '.join(probe.probe_interesting_strings[:10]))
    if probe.probe_error:
        lines.append(f'probe_error: {probe.probe_error}')
    return '\n'.join(lines)


# ---------------------------------------------------------------------------
# Input surface classifier
# ---------------------------------------------------------------------------

# JS HTTP-server frameworks — if any of these are in package.json dependencies,
# the repo runs as a network server and PoVs must use http_request surface.
_JS_HTTP_FRAMEWORKS = {
    'express', 'fastify', 'koa', '@hapi/hapi', 'hapi', 'restify', 'nest',
    '@nestjs/core', 'sails', 'loopback', 'polka', 'micro', 'connect',
}


def _classify_js_input_surface(codebase_path: str) -> str:
    """Detect JS input surface from package.json — called when no help-text is available.

    Returns:
      'network'       - repo has an HTTP framework dependency (express/fastify/koa/etc.)
      'function_call' - repo is a pure library (no HTTP framework, has a main export)
      'unknown'       - could not determine
    """
    pkg_path = os.path.join(codebase_path, 'package.json') if codebase_path else ''
    if not pkg_path or not os.path.isfile(pkg_path):
        return 'unknown'
    try:
        with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as fh:
            pkg = json.loads(fh.read())
    except Exception:
        return 'unknown'

    all_deps = set()
    for section in ('dependencies', 'devDependencies', 'peerDependencies'):
        all_deps.update(pkg.get(section, {}).keys())

    # Check for HTTP framework
    if all_deps & _JS_HTTP_FRAMEWORKS:
        return 'network'

    # Check for library pattern: has a 'main' entry pointing to a JS file
    main_field = str(pkg.get('main') or '').strip()
    if main_field and (main_field.endswith('.js') or main_field.endswith('.mjs') or main_field.endswith('.cjs')):
        return 'function_call'

    return 'unknown'

def _classify_input_surface(help_text: str, binary_path: str = '') -> str:
    """Derive the primary input surface for a binary from its --help text.

    Returns one of:
      'file_argument'      - binary reads input from a file path passed as CLI argument
      'stdin'              - binary reads from stdin (pipe/redirect)
      'network'            - binary is a server that binds a port
      'argv_only'          - binary takes only flags, no file/stdin input
      'test_harness_output'- help text is actually test-runner output (cJSON, unity-style)
      'unknown'            - could not determine
    """
    if not help_text:
        return 'unknown'

    text = help_text.lower()
    binary_name = os.path.basename(binary_path or '').lower()

    # Task 5: Detect test-harness output before any other classification.
    # Unity/cJSON/Catch2 test runners print lines like:
    #   "Tests run: 12" / "PASS" / "FAIL" / "OK" / "test_parse_object"
    # This is NOT help text — it means the binary is a unit test runner.
    _TEST_HARNESS_MARKERS = [
        'tests run:', 'test suite:', 'test passed', 'test failed',
        'unity test', 'catch2', 'ctest', 'all tests passed',
    ]
    _standalone_ok_fail = __import__('re').search(r'^(pass|fail|ok)\s*$', text, __import__('re').MULTILINE)
    _has_test_marker = any(m in text for m in _TEST_HARNESS_MARKERS) or bool(_standalone_ok_fail)
    # Additional heuristic: if the output contains no flag-like tokens (--flag) and
    # has multiple test_<name> patterns, it's a test runner.
    _has_test_fn_names = len(__import__('re').findall(r'\btest_\w+', text)) >= 2
    if _has_test_marker or _has_test_fn_names:
        return 'test_harness_output'

    # Network server indicators
    if any(kw in text for kw in ('--port', '-p <port', 'bind', 'listen', '--host', '--address', ':8080', ':80 ')):
        return 'network'

    # File argument indicators: usage lines where a FILE/IMAGE/PATH positional appears
    # e.g. "usage: jhead [options] <file>" or "cjpeg [switches] inputfile"
    _file_patterns = [
        r'<file', r'<image', r'<path', r'<input', r'\[file', r'\[image',
        r'file\.\.\.', r'files\.\.\.', r' file$', r' files$',
        r'usage.*\s+[a-z_-]+\s+<', r'usage.*\s+[a-z_-]+\s+\[',
        # Image/media tools (libjpeg-turbo cjpeg/djpeg, libpng tools, etc.)
        r'inputfile', r'input.file', r'<inputfile', r'\[inputfile',
        r'<jpeg', r'<jpg', r'<png', r'<bmp', r'<tiff', r'<gif',
        r'infile', r'outfile', r'<infile', r'\[infile',
        # Generic positional at end of usage line: binary [options] SOMETHING
        r'usage.*\s+\[(?:switches|options|flags)\]\s+\S',
    ]
    for pat in _file_patterns:
        if re.search(pat, text):
            return 'file_argument'
    # Usage line: binary_name followed by non-flag positional (e.g. "jhead [options] file")
    if binary_name:
        m = re.search(rf'usage.*{re.escape(binary_name)}[^\n]*\s([a-z][a-z0-9_-]{{2,}})(?:\s|$)', text)
        if m and not m.group(1).startswith('-'):
            return 'file_argument'

    # Stdin indicators
    if any(kw in text for kw in ('stdin', 'read from -', '- as stdin', 'pipe', 'standard input')):
        return 'stdin'

    # If no positional argument detected but flags exist, argv_only
    if re.search(r'-[a-z]|--[a-z]', text):
        return 'argv_only'

    return 'unknown'


# ---------------------------------------------------------------------------
# The shell script that runs inside the Docker container
# ---------------------------------------------------------------------------

_PROBE_SHELL_SCRIPT = r"""
set -e
CB="/workspace/codebase"
[ -d "$CB" ] || { echo "PROBE_ERROR=no_codebase"; exit 0; }

# ── Pre-Step 0: Install missing build tools before attempting to build ────────
# Scans CMakeLists.txt / Makefile / configure.ac for build-tool invocations
# (flex, bison, python3-dev, nasm, etc.) and installs any that are missing.
# Must run BEFORE Step 0 so cmake/make have the tools they need to configure.
set +e
_autopov_build_tool_resolver() {
  local CB="/workspace/codebase"
  [ -d "$CB" ] || return 0
  local PKGS=""
  local CONTENT
  CONTENT=$(cat "$CB/CMakeLists.txt" "$CB/Makefile" "$CB/configure.ac" \
               "$CB/configure.in" "$CB/Makefile.am" 2>/dev/null || true)
  [ -z "$CONTENT" ] && return 0
  echo "$CONTENT" | grep -qiE 'find_package[[:space:]]*\(FLEX|FLEX_TARGET|AC_PROG_LEX' \
    && ! command -v flex >/dev/null 2>&1 && PKGS="$PKGS flex"
  echo "$CONTENT" | grep -qiE 'find_package[[:space:]]*\(BISON|BISON_TARGET|AC_PROG_YACC' \
    && ! command -v bison >/dev/null 2>&1 && PKGS="$PKGS bison"
  echo "$CONTENT" | grep -qiE 'FindPython3|python3-config|Python3_INCLUDE|python-dev' \
    && ! dpkg -s python3-dev >/dev/null 2>&1 && PKGS="$PKGS python3-dev"
  echo "$CONTENT" | grep -qiE '\bnasm\b' \
    && ! command -v nasm >/dev/null 2>&1 && PKGS="$PKGS nasm"
  echo "$CONTENT" | grep -qiE '\byasm\b' \
    && ! command -v yasm >/dev/null 2>&1 && PKGS="$PKGS yasm"
  echo "$CONTENT" | grep -qiE 'AC_PROG_INTLTOOL|AM_GNU_GETTEXT' \
    && ! command -v autopoint >/dev/null 2>&1 && PKGS="$PKGS gettext"
  echo "$CONTENT" | grep -qiE 'PKG_CHECK_MODULES|pkg-config' \
    && ! command -v pkg-config >/dev/null 2>&1 && PKGS="$PKGS pkg-config"
  echo "$CONTENT" | grep -qiE 'AM_INIT_AUTOMAKE|autoreconf' \
    && ! command -v autoreconf >/dev/null 2>&1 && PKGS="$PKGS dh-autoreconf"
  [ -z "$PKGS" ] && return 0
  echo "[AutoPoV probe] Installing missing build tools:$PKGS" >&2
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends $PKGS \
    >/dev/null 2>&1 || true
}
_autopov_build_tool_resolver || true
set -e

# ── Step 0: Build the codebase if no ELF binary exists yet ─────────────────
# This is the key fix for CMake/autoconf repos (libjpeg-turbo, leveldb, re2,
# libusb, etc.) where the probe container starts with source only and no build
# artifacts.  Without this step the probe finds nothing, the model gets no
# surface info, and guesses wrong or self-compiles.
# The build mirrors docker_runner's own build logic and is best-effort:
# any failure is recorded in PROBE_BUILD_STATUS but does NOT abort the probe.
set +e
PROBE_BUILD_STATUS="skipped"
_has_elf() {
  find "$CB" -maxdepth 8 -type f -executable \
    ! -name '*.sh' ! -name '*.py' ! -name '*.rb' ! -name '*.pl' ! -name '*.js' \
    ! -path '*/node_modules/*' ! -path '*/.git/*' \
    ! -path '*/CMakeFiles/*' \
    ! -path '*/_codeql_build_dir/*' \
    ! -path '*/CompilerIdC/*' \
    ! -path '*/CompilerIdCXX/*' \
    2>/dev/null \
  | xargs -I{} sh -c 'file "{}" 2>/dev/null | grep -q "ELF" && echo "{}"' \
  | head -1
}
# Only build if no pre-built ELF exists (e.g. jhead already has one from
# a prior run, or the repo ships pre-built binaries).
if [ -z "$(_has_elf)" ]; then
  echo "PROBE_BUILD_STATUS=building"
  # ── CMake ──────────────────────────────────────────────────────────────────
  if [ -f "$CB/CMakeLists.txt" ]; then
    CMAKE_BUILD="$CB/.autopov-probe-build"
    cmake -S "$CB" -B "$CMAKE_BUILD" \
      -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
      -DCMAKE_CXX_FLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
      -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
      -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
      -G Ninja \
      2>/tmp/_probe_cmake.log \
    && cmake --build "$CMAKE_BUILD" --parallel 4 2>>/tmp/_probe_cmake.log \
    && PROBE_BUILD_STATUS="cmake_ok" \
    || { cmake -S "$CB" -B "$CMAKE_BUILD" -DCMAKE_BUILD_TYPE=Debug -G Ninja 2>/tmp/_probe_cmake_plain.log \
         && cmake --build "$CMAKE_BUILD" --parallel 4 2>>/tmp/_probe_cmake_plain.log \
         && PROBE_BUILD_STATUS="cmake_plain_ok" \
         || PROBE_BUILD_STATUS="cmake_failed"; }
  # ── Meson ──────────────────────────────────────────────────────────────────
  elif [ -f "$CB/meson.build" ]; then
    MESON_BUILD="$CB/.autopov-probe-meson-build"
    meson setup "$MESON_BUILD" "$CB" --buildtype=debug -Db_sanitize=address,undefined 2>/tmp/_probe_meson.log \
    && meson compile -C "$MESON_BUILD" 2>>/tmp/_probe_meson.log \
    && PROBE_BUILD_STATUS="meson_ok" \
    || PROBE_BUILD_STATUS="meson_failed"
  # ── Autoconf / automake ────────────────────────────────────────────────────
  elif [ -f "$CB/configure.ac" ] || [ -f "$CB/configure.in" ]; then
    cd "$CB" \
    && ([ -x ./autogen.sh ] && ./autogen.sh 2>/tmp/_probe_auto.log \
        || autoreconf -i 2>/tmp/_probe_auto.log || true) \
    && ./configure CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined" 2>>/tmp/_probe_auto.log \
    && make -j4 2>>/tmp/_probe_auto.log \
    && PROBE_BUILD_STATUS="autoconf_ok" \
    || PROBE_BUILD_STATUS="autoconf_failed"
    cd /
  # ── Plain Makefile ─────────────────────────────────────────────────────────
  elif [ -f "$CB/Makefile" ] || [ -f "$CB/makefile" ]; then
    make -C "$CB" -j4 \
      CC=clang CFLAGS="-O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
      LDFLAGS="-fsanitize=address,undefined" \
      2>/tmp/_probe_make.log \
    && PROBE_BUILD_STATUS="make_ok" \
    || make -C "$CB" -j4 2>/tmp/_probe_make_plain.log \
    && PROBE_BUILD_STATUS="make_plain_ok" \
    || PROBE_BUILD_STATUS="make_failed"
  fi
else
  PROBE_BUILD_STATUS="prebuilt"
fi
echo "PROBE_BUILD_STATUS=$PROBE_BUILD_STATUS"
set -e

# ── Step 1: Locate the most-recently-built ELF binary ──────────────────────
PROBE_BIN=""
# Priority 1: binary named after repo (most likely the main executable)
if [ -n "${AUTOPOV_REPO_NAME:-}" ]; then
  PROBE_BIN=$(find "$CB" -maxdepth 8 -type f -executable -name "$AUTOPOV_REPO_NAME" 2>/dev/null | head -1)
fi
# Priority 2: any ELF binary — prefer build dirs over source dirs
if [ -z "$PROBE_BIN" ]; then
  PROBE_BIN=$(find "$CB" -maxdepth 8 -type f -executable \
    ! -name '*.sh' ! -name '*.py' ! -name '*.rb' ! -name '*.pl' ! -name '*.js' \
    ! -name '*.so' ! -name '*.so.*' ! -name '*.a' ! -name '*.o' \
    ! -path '*/node_modules/*' ! -path '*/.git/*' \
    ! -path '*/CMakeFiles/*' \
    ! -path '*/_codeql_build_dir/*' \
    ! -path '*/CompilerIdC/*' \
    ! -path '*/CompilerIdCXX/*' \
    2>/dev/null \
    | xargs -I{} sh -c 'file "{}" 2>/dev/null | grep -q "ELF" && echo "{}"' \
    | awk '
      # Prefer binaries in build dirs; deprioritise test/helper binaries
      /\/\.autopov-probe-build\/|autopov-cmake-build|autopov-meson-build/ { print 1, $0; next }
      # Task 3B: Strong penalty for test harness binary names
      /test_|_test$|_tests$|check_|_check$|parse_|print_|misc_|fuzz_|bench_|unity_|run_test/ { print 5, $0; next }
      /\/test\/|_test$|\/check\/|_check$/ { print 3, $0; next }
      { print 2, $0 }
    ' | sort -k1,1n -k2 | head -5 | awk '{print $2}' | head -1 || true)
fi
# Step 1 is best-effort: for non-native repos (Python/Java/Node) no ELF binary
# will be found and PROBE_BIN stays empty.  Steps 2-6 are guarded by [ -n "$PROBE_BIN" ]
# so they are skipped gracefully; Step 6 (baseline) still records RC=-1.
if [ -z "$PROBE_BIN" ]; then
  echo "PROBE_ERROR=no_binary_found"
  # Do NOT exit -- continue so later steps can still record partial data.
else
  echo "PROBE_BINARY=$PROBE_BIN"
fi
# Relax set -e from here: remaining steps are best-effort.
set +e

# ── Step 2: ldd check ──────────────────────────────────────────────────────
if [ -n "$PROBE_BIN" ] && command -v ldd >/dev/null 2>&1; then
  LDD_OUT=$(ldd "$PROBE_BIN" 2>&1 || true)
  MISSING=$(echo "$LDD_OUT" | grep 'not found' | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
  [ -n "$MISSING" ] && echo "PROBE_LDD_MISSING=$MISSING" || echo "PROBE_LDD_MISSING="
else
  echo "PROBE_LDD_MISSING="
fi

# ── Step 3: help probe ─────────────────────────────────────────────────────
# Wrapped in set +e/set -e: many binaries exit non-zero when invoked without
# required args; that must NOT kill the probe under the outer set -e.
set +e
if [ -n "$PROBE_BIN" ]; then
  echo "PROBE_HELP_BEGIN"
  "$PROBE_BIN" 2>&1 | head -60 || \
    "$PROBE_BIN" --help 2>&1 | head -60 || \
    "$PROBE_BIN" -h 2>&1 | head -60 || \
    "$PROBE_BIN" help 2>&1 | head -60 || true
  echo "PROBE_HELP_END"
fi
set -e

# ── Step 4: crash probe ────────────────────────────────────────────────────
# Try empty args, then /dev/zero as stdin, then a 256-byte all-A argv
PROBE_CRASHED=0
PROBE_SIGNAL=""
PROBE_INPUT=""
PROBE_CRASH_OUT=""

_try_crash() {
  local DESC="$1"; shift
  local OUT
  OUT=$(timeout 5 "$@" 2>&1) && true; local RC=$?
  # RC 124 = timeout, skip
  [ "$RC" = "124" ] && return 0
  # ASan / kernel signal crash
  if echo "$OUT" | grep -qiE 'addresssanitizer|sigsegv|sigabrt|signal [0-9]+|heap-buffer-overflow|use-after-free|deadlysignal|segmentation fault'; then
    PROBE_CRASHED=1
    PROBE_INPUT="$DESC"
    PROBE_CRASH_OUT="$OUT"
    PROBE_SIGNAL=$(echo "$OUT" | grep -oiE 'signal [0-9]+|sigsegv|sigabrt' | head -1 || echo "crash")
    return 1  # stop trying more inputs
  fi
  return 0
}

if [ -n "$PROBE_BIN" ]; then
  _try_crash "empty_args" "$PROBE_BIN" 2>&1 || true
  if [ "$PROBE_CRASHED" = "0" ]; then
    _try_crash "zero_stdin" sh -c "dd if=/dev/zero bs=256 count=1 2>/dev/null | \"$PROBE_BIN\"" 2>&1 || true
  fi
  if [ "$PROBE_CRASHED" = "0" ]; then
    _try_crash "aa_argv" "$PROBE_BIN" "$(python3 -c 'print("A"*256)' 2>/dev/null || printf '%0.s.A' {1..128})" 2>&1 || true
  fi
fi

echo "PROBE_CRASHED=$PROBE_CRASHED"
echo "PROBE_SIGNAL=$PROBE_SIGNAL"
echo "PROBE_INPUT=$PROBE_INPUT"
if [ "$PROBE_CRASHED" = "1" ] && [ -n "$PROBE_CRASH_OUT" ]; then
  echo "PROBE_CRASH_OUT_BEGIN"
  echo "$PROBE_CRASH_OUT" | head -40
  echo "PROBE_CRASH_OUT_END"
fi

# ── Step 5: strings probe ──────────────────────────────────────────────────
if [ -n "$PROBE_BIN" ] && command -v strings >/dev/null 2>&1; then
  echo "PROBE_STRINGS_BEGIN"
  strings "$PROBE_BIN" 2>/dev/null \
    | grep -iE 'usage|overflow|sprintf|gets\(|strcpy|strcat|scanf|memcpy|malloc|free|error|invalid|format' \
    | sort -u | head -20 || true
  echo "PROBE_STRINGS_END"
fi

# ── Step 6: baseline execution (no crashing input) ─────────────────────────
# Run the binary with empty/help args and capture exit code + stderr snippet.
# Used by the oracle as a reference when ASAN is not available.
# For non-native repos without a binary, step records RC=-1 (sentinel for "no baseline").
PROBE_BASELINE_RC=-1
PROBE_BASELINE_STDERR=""
if [ -n "$PROBE_BIN" ]; then
  _BASELINE_OUT=$(timeout 5 "$PROBE_BIN" 2>&1) && PROBE_BASELINE_RC=$? || PROBE_BASELINE_RC=$?
  if [ "$PROBE_BASELINE_RC" = "124" ]; then
    PROBE_BASELINE_RC=-2  # timeout
  fi
  PROBE_BASELINE_STDERR=$(echo "$_BASELINE_OUT" | head -5 | tr '\n' '|')
fi
echo "PROBE_BASELINE_RC=$PROBE_BASELINE_RC"
echo "PROBE_BASELINE_STDERR=$PROBE_BASELINE_STDERR"

echo "PROBE_DONE=1"
"""

# Surface-adaptive extension appended at runtime (Task 1)
# Written as a separate string to avoid quote-escaping complexity in the r-string above.
_PROBE_SURFACE_SCRIPT = r"""
# -- Step 7: Surface-adaptive discovery for Python/Node/web repos ----------
# Detects runtime surface so non-native repos get PROBE_SURFACE_TYPE/PROBE_ENTRY_CMD
# sentinels used by the contract gate and docker harness.
set +e
PROBE_SURFACE_TYPE=""
PROBE_ENTRY_CMD=""
PROBE_INSTALL_OK="0"
PROBE_BASE_URL=""
PROBE_EXPORTS=""

if [ -f "$CB/setup.py" ] || [ -f "$CB/pyproject.toml" ] || [ -f "$CB/setup.cfg" ]; then
  PROBE_SURFACE_TYPE="python_module"
  ( cd "$CB" && pip3 install --quiet --no-cache-dir --break-system-packages -e . 2>/dev/null ) \\\n    && PROBE_INSTALL_OK="1" \\
    || ( pip3 install --quiet --no-cache-dir --break-system-packages "$CB" 2>/dev/null && PROBE_INSTALL_OK="1" ) || true
  PROBE_ENTRY_CMD=$(python3 -c \
    "import sys\ntry:\n    import pkg_resources\n    for d in pkg_resources.working_set:\n        for name in d.get_entry_map().get('console_scripts',{}):\n            print(name); sys.exit(0)\nexcept Exception: pass\n" 2>/dev/null | head -1)
  # Task 2B: extract exported names for the LLM
  PROBE_EXPORTS=$(python3 -c \
    "import sys, os, ast\nroot='$CB'\nexports=[]\nfor dp,dn,fn in os.walk(root):\n    dn[:]=[ d for d in dn if not d.startswith('.') and d not in ('node_modules','.git','__pycache__')]\n    for f in fn:\n        if f.endswith('.py'):\n            try:\n                src=open(os.path.join(dp,f)).read()\n                tree=ast.parse(src)\n                for n in ast.walk(tree):\n                    if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):\n                        if not n.name.startswith('_'):\n                            exports.append(n.name)\n            except: pass\nprint(','.join(sorted(set(exports))[:60]))" \
    2>/dev/null | head -1)
  if [ -z "$PROBE_ENTRY_CMD" ]; then
    _MAIN=$(find "$CB" -name '__main__.py' ! -path '*/.git/*' 2>/dev/null | head -1)
    if [ -n "$_MAIN" ]; then
      _MOD=$(echo "$_MAIN" | sed "s|$CB/||;s|/__main__.py||;s|/|.|g")
      [ -n "$_MOD" ] && PROBE_ENTRY_CMD="python3 -m $_MOD"
    fi
  fi
  if [ -z "$PROBE_ENTRY_CMD" ] && [ -n "${AUTOPOV_REPO_NAME:-}" ]; then
    python3 -c "import $AUTOPOV_REPO_NAME" 2>/dev/null && PROBE_ENTRY_CMD="python3 -m $AUTOPOV_REPO_NAME" || true
  fi
  # Check for web service indicators
  if grep -rqE 'app\.run\(|socketio|flask|django|tornado|aiohttp|bottle|cherrypy' "$CB" --include='*.py' 2>/dev/null; then
    _PORT=$(grep -rh 'port\|PORT\|listen' "$CB" --include='*.py' 2>/dev/null \
      | grep -oE '[3-9][0-9]{3}|[1-9][0-9]{4}' | head -1)
    [ -z "$_PORT" ] && _PORT="5000"
    PROBE_SURFACE_TYPE="web_service"
    PROBE_BASE_URL="http://localhost:$_PORT"
  fi
elif [ -f "$CB/package.json" ]; then
  PROBE_SURFACE_TYPE="node_module"
  ( cd "$CB" && npm install --silent 2>/dev/null ) && PROBE_INSTALL_OK="1" || true
  PROBE_ENTRY_CMD=$(node -e \
    "try{const p=require('$CB/package.json');if(p.bin){const v=Object.values(p.bin);if(v.length){console.log(v[0]);process.exit(0);}}if(p.main){console.log('node '+p.main);}}catch(e){}" \
    2>/dev/null | head -1)
  # Task 2B: extract exported names from main JS file
  PROBE_EXPORTS=$(node -e \
    "try{const p=require('$CB/package.json');const m=p.main||'index.js';const mod=require('$CB/'+m);const keys=Object.keys(mod).filter(k=>!k.startsWith('_')).slice(0,60);console.log(keys.join(','));}catch(e){}" \
    2>/dev/null | head -1)
  _JS_DEPS=$(node -e "try{const p=require('$CB/package.json');const d=Object.assign({},p.dependencies,p.devDependencies);console.log(Object.keys(d).join(' '));}catch(e){}" 2>/dev/null)
  if echo "$_JS_DEPS" | grep -qE 'express|fastify|koa|hapi|restify|polka|connect|micro'; then
    _PORT=$(grep -rh 'listen\|PORT' "$CB" --include='*.js' --include='*.ts' 2>/dev/null \
      | grep -oE '[3-9][0-9]{3}|[1-9][0-9]{4}' | head -1)
    [ -z "$_PORT" ] && _PORT="3000"
    PROBE_SURFACE_TYPE="web_service"
    PROBE_BASE_URL="http://localhost:$_PORT"
  fi
fi

if [ -n "$PROBE_SURFACE_TYPE" ]; then
  echo "PROBE_SURFACE_TYPE=$PROBE_SURFACE_TYPE"
  echo "PROBE_ENTRY_CMD=$PROBE_ENTRY_CMD"
  echo "PROBE_INSTALL_OK=$PROBE_INSTALL_OK"
  echo "PROBE_BASE_URL=$PROBE_BASE_URL"
  [ -n "$PROBE_EXPORTS" ] && echo "PROBE_EXPORTS=$PROBE_EXPORTS"
elif [ -n "$PROBE_BIN" ]; then
  echo "PROBE_SURFACE_TYPE=native_elf"
fi
set -e
"""


# ---------------------------------------------------------------------------
# Container execution helper
# ---------------------------------------------------------------------------

def _run_probe_container(
    codebase_path: str,
    repo_name: str,
    image: str,
    timeout: int = 90,
) -> str:
    """Run the probe shell script in a Docker container and return combined stdout."""
    if not DOCKER_AVAILABLE:
        return 'PROBE_ERROR=docker_not_available'

    temp_dir = tempfile.mkdtemp(prefix='autopov_probe_')
    client = None
    container = None
    try:
        client = docker.from_env(timeout=30)
        # Ensure image is available
        try:
            client.images.get(image)
        except ImageNotFound:
            return f'PROBE_ERROR=image_not_found:{image}'

        # Write probe script (main + surface-adaptive extension)
        script_path = os.path.join(temp_dir, 'probe.sh')
        with open(script_path, 'w') as f:
            f.write(_PROBE_SHELL_SCRIPT.rstrip())
            f.write('\n')
            f.write(_PROBE_SURFACE_SCRIPT)

        # Build tar archive: codebase + probe script
        archive_buf = io.BytesIO()
        with tarfile.open(fileobj=archive_buf, mode='w') as tar:
            tar.add(script_path, arcname='probe/probe.sh')
            if codebase_path and os.path.isdir(codebase_path):
                tar.add(codebase_path, arcname='workspace/codebase', recursive=True)
        archive_buf.seek(0)

        container = client.containers.create(
            image=image,
            command=['bash', '-lc', 'chmod +x /probe/probe.sh && /probe/probe.sh'],
            working_dir='/',
            mem_limit='1g',
            cpu_quota=100000,
            # GAP-3: probe needs network access so pip/npm install can actually
            # download packages during Python/Node surface discovery.
            network_mode='bridge',
            environment={
                'AUTOPOV_REPO_NAME': repo_name,
                'DEBIAN_FRONTEND': 'noninteractive',
                'PIP_NO_CACHE_DIR': '1',
            },
            detach=True,
        )
        container.put_archive('/', archive_buf.getvalue())
        container.start()

        try:
            container.wait(timeout=timeout)
        except Exception:
            try:
                container.kill()
            except Exception:
                pass

        stdout = container.logs(stdout=True, stderr=True).decode('utf-8', errors='ignore')
        return stdout
    except Exception as ex:
        return f'PROBE_ERROR={ex!s}'
    finally:
        if container is not None:
            try:
                container.remove(force=True)
            except Exception:
                pass
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------

def _parse_probe_output(raw: str) -> ProbeResult:
    """Parse the structured sentinel output from _PROBE_SHELL_SCRIPT."""
    result = ProbeResult()
    if not raw:
        result.probe_skip_reason = 'empty_output'
        result.probe_skipped = True
        return result

    lines = raw.splitlines()
    idx = 0
    n = len(lines)

    def _collect_block(begin_marker: str, end_marker: str) -> str:
        nonlocal idx
        block: List[str] = []
        in_block = False
        while idx < n:
            line = lines[idx]
            idx += 1
            if not in_block:
                if line.strip() == begin_marker:
                    in_block = True
            else:
                if line.strip() == end_marker:
                    return '\n'.join(block)
                block.append(line)
        return '\n'.join(block)

    while idx < n:
        line = lines[idx].strip()
        idx += 1

        if line.startswith('PROBE_ERROR='):
            err_val = line[len('PROBE_ERROR='):]
            result.probe_error = err_val
            # Fatal infrastructure errors (Docker unavailable, no codebase, etc.) abort
            # parsing immediately.  'no_binary_found' is NOT fatal — the shell script
            # continues and still emits baseline/ldd data; keep parsing.
            if err_val not in {'no_binary_found'}:
                result.probe_skipped = True
                result.probe_skip_reason = err_val
                return result
            # no_binary_found: record it but do NOT return — continue parsing remaining sentinels.

        if line.startswith('PROBE_BUILD_STATUS='):
            build_status_val = line[len('PROBE_BUILD_STATUS='):]
            # Record build outcome; treat *_ok variants as success
            result.probe_build_succeeded = build_status_val.endswith('_ok') or build_status_val == 'prebuilt'
            if not result.probe_build_log:
                result.probe_build_log = build_status_val

        elif line.startswith('PROBE_BINARY='):
            result.probe_binary_path = line[len('PROBE_BINARY='):]

        elif line.startswith('PROBE_LDD_MISSING='):
            val = line[len('PROBE_LDD_MISSING='):]
            result.probe_ldd_missing = [v.strip() for v in val.split(',') if v.strip()]

        elif line.strip() == 'PROBE_HELP_BEGIN':
            idx -= 1  # let _collect_block consume the begin line too; re-enter
            # Re-parse with explicit sentinel scan
            help_lines: List[str] = []
            in_help = False
            tmp_idx = idx
            while tmp_idx < n:
                l = lines[tmp_idx].strip()
                tmp_idx += 1
                if not in_help:
                    if l == 'PROBE_HELP_BEGIN':
                        in_help = True
                else:
                    if l == 'PROBE_HELP_END':
                        idx = tmp_idx
                        break
                    help_lines.append(l)
            help_text = '\n'.join(help_lines)
            # Extract flags: lines starting with -, or tokens like --flag, -f
            flags = re.findall(r'(?:^|\s)(--?[a-zA-Z][\w-]*)', help_text)
            result.probe_cli_flags = sorted(set(flags))[:40]
            result.probe_help_text = help_text
            # Classify the input surface from the help text
            result.probe_input_surface = _classify_input_surface(help_text, result.probe_binary_path)

        elif line.startswith('PROBE_CRASHED='):
            result.probe_crash_observed = line[len('PROBE_CRASHED='):] == '1'

        elif line.startswith('PROBE_SIGNAL='):
            result.probe_crash_signal = line[len('PROBE_SIGNAL='):]

        elif line.startswith('PROBE_INPUT='):
            result.probe_crash_input = line[len('PROBE_INPUT='):]

        elif line.startswith('PROBE_BASELINE_RC='):
            try:
                result.probe_baseline_exit_code = int(line[len('PROBE_BASELINE_RC='):])
            except (ValueError, TypeError):
                result.probe_baseline_exit_code = -1

        elif line.startswith('PROBE_BASELINE_STDERR='):
            result.probe_baseline_stderr = line[len('PROBE_BASELINE_STDERR='):].replace('|', '\n')

        elif line.startswith('PROBE_SURFACE_TYPE='):
            result.probe_surface_type = line[len('PROBE_SURFACE_TYPE='):].strip()

        elif line.startswith('PROBE_ENTRY_CMD='):
            result.probe_entry_command = line[len('PROBE_ENTRY_CMD='):].strip()

        elif line.startswith('PROBE_INSTALL_OK='):
            result.probe_install_ok = line[len('PROBE_INSTALL_OK='):].strip() == '1'

        elif line.startswith('PROBE_BASE_URL='):
            result.probe_base_url = line[len('PROBE_BASE_URL='):].strip()

        elif line.startswith('PROBE_EXPORTS='):
            result.probe_exports = line[len('PROBE_EXPORTS='):].strip()

        elif line.strip() == 'PROBE_CRASH_OUT_BEGIN':
            crash_out_lines: List[str] = []
            while idx < n:
                l = lines[idx].strip()
                idx += 1
                if l == 'PROBE_CRASH_OUT_END':
                    break
                crash_out_lines.append(l)
            result.probe_crash_output = '\n'.join(crash_out_lines)

        elif line.strip() == 'PROBE_STRINGS_BEGIN':
            str_lines: List[str] = []
            while idx < n:
                l = lines[idx]
                idx += 1
                if l.strip() == 'PROBE_STRINGS_END':
                    break
                if l.strip():
                    str_lines.append(l.strip())
            result.probe_interesting_strings = str_lines[:20]

    # probe_build_succeeded: set by PROBE_BUILD_STATUS sentinel; fall back to
    # binary presence if the sentinel wasn't emitted (older probe script versions).
    if not result.probe_build_log:
        result.probe_build_succeeded = bool(result.probe_binary_path)
    return result


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_probe(
    codebase_path: str,
    scan_id: str,
    exploit_contract: Optional[Dict[str, Any]] = None,
    *,
    timeout: int = 300,  # 5 min — enough for a CMake build inside the probe container
    runtime_profile: str = 'native',
) -> ProbeResult:
    """Run the preflight probe against the codebase and return a ProbeResult.

    The probe executes inside the appropriate proof container to ensure
    consistent tooling (ldd, strings, clang, etc.).  It is non-fatal: if Docker
    is unavailable or the probe script errors, a ProbeResult with
    probe_skipped=True is returned so the pipeline can continue without it.

    Parameters
    ----------
    codebase_path : str
        Absolute path to the codebase on the host (will be tar'd into the container).
    scan_id : str
        Used for temp-dir naming only.
    exploit_contract : dict, optional
        May contain 'repo_name' to help the binary locator.
    timeout : int
        Max seconds to wait for the probe container (default 90).
    runtime_profile : str
        Language profile hint ('native', 'python', 'java', 'node', etc.).
        Selects the Docker image used for the probe container.
    """
    result = ProbeResult()
    start = datetime.utcnow()

    if not DOCKER_AVAILABLE:
        result.probe_skipped = True
        result.probe_skip_reason = 'docker_not_available'
        return result

    if not codebase_path or not os.path.isdir(codebase_path):
        result.probe_skipped = True
        result.probe_skip_reason = 'codebase_not_found'
        return result

    contract = exploit_contract or {}
    repo_name = (
        str(contract.get('repo_name') or '')
        or os.path.basename(codebase_path.rstrip('/\\'))
    ).lower()

    # Select the probe image based on runtime_profile so non-native repos
    # (Python/Java/Node) use the correct toolchain inside the container.
    _profile = str(runtime_profile or 'native').strip().lower()
    _image_map = {
        'python': settings.DOCKER_IMAGE,
        'java': settings.DOCKER_JAVA_IMAGE,
        'node': settings.DOCKER_NODE_IMAGE,
        'javascript': settings.DOCKER_NODE_IMAGE,
        'typescript': settings.DOCKER_NODE_IMAGE,
    }
    image = _image_map.get(_profile, settings.DOCKER_NATIVE_IMAGE)

    try:
        raw_output = _run_probe_container(
            codebase_path=codebase_path,
            repo_name=repo_name,
            image=image,
            timeout=timeout,
        )
        result = _parse_probe_output(raw_output)
    except Exception as ex:
        result.probe_skipped = True
        result.probe_skip_reason = 'exception'
        result.probe_error = str(ex)

    # For JS/Node repos where the probe script didn't find a binary (no ELF), derive
    # the input surface directly from package.json rather than leaving it 'unknown'.
    if _profile in ('node', 'javascript', 'typescript') and result.probe_input_surface == 'unknown':
        js_surface = _classify_js_input_surface(codebase_path)
        if js_surface != 'unknown':
            result.probe_input_surface = js_surface

    result.probe_duration_s = (datetime.utcnow() - start).total_seconds()
    return result


# ---------------------------------------------------------------------------
# Module-level singleton helpers
# ---------------------------------------------------------------------------

_probe_runner_instance = None


def get_probe_runner():
    """Return a module-level callable compatible with the agent_graph import pattern."""
    return run_probe

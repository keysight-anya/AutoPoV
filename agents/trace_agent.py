"""
AutoPoV Trace Agent
Lightweight dynamic trace step that runs AFTER the probe and BEFORE PoV generation.

Runs the target binary under strace (input surface detection) and valgrind
(memory error detection without ASan) inside the same Docker container used
by the probe.  Results are serialised into a TraceResult and injected into
exploit_contract['trace_context'] for every finding in the scan.

All steps are best-effort and non-fatal.  A failed trace simply returns an
empty TraceResult so downstream generation continues without trace data.

Public API
----------
    trace_result = run_trace(codebase_path, scan_id, exploit_contract)
    trace_context_str = format_trace_context(trace_result)
"""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import tempfile
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
# TraceResult schema
# ---------------------------------------------------------------------------

class TraceResult:
    """Results from the dynamic trace phase."""

    def __init__(self) -> None:
        self.trace_binary_path: str = ''
        # strace-derived fields
        self.trace_input_surface: str = ''     # 'file_argument' | 'stdin' | 'argv_only' | 'unknown'
        self.trace_opens_files: bool = False   # binary called open/openat with argv[1]
        self.trace_reads_stdin: bool = False   # binary called read on fd=0
        self.trace_interesting_syscalls: List[str] = []
        self.trace_file_extensions: List[str] = []  # extensions of files it tried to open
        # valgrind-derived fields
        self.trace_valgrind_errors: int = 0
        self.trace_valgrind_summary: str = ''
        self.trace_valgrind_error_types: List[str] = []  # e.g. ['Invalid read', 'Use of uninitialised']
        # combined
        self.trace_memory_errors_detected: bool = False
        self.trace_crash_input: str = ''       # input that caused valgrind errors
        self.trace_duration_s: float = 0.0
        self.trace_skipped: bool = False
        self.trace_skip_reason: str = ''
        self.trace_error: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'trace_binary_path': self.trace_binary_path,
            'trace_input_surface': self.trace_input_surface,
            'trace_opens_files': self.trace_opens_files,
            'trace_reads_stdin': self.trace_reads_stdin,
            'trace_interesting_syscalls': self.trace_interesting_syscalls,
            'trace_file_extensions': self.trace_file_extensions,
            'trace_valgrind_errors': self.trace_valgrind_errors,
            'trace_valgrind_summary': self.trace_valgrind_summary,
            'trace_valgrind_error_types': self.trace_valgrind_error_types,
            'trace_memory_errors_detected': self.trace_memory_errors_detected,
            'trace_crash_input': self.trace_crash_input,
            'trace_duration_s': self.trace_duration_s,
            'trace_skipped': self.trace_skipped,
            'trace_skip_reason': self.trace_skip_reason,
            'trace_error': self.trace_error,
        }


# ---------------------------------------------------------------------------
# Embedded trace shell script
# ---------------------------------------------------------------------------

_TRACE_SHELL_SCRIPT = r"""#!/bin/bash
set -e
CB="${1:-/workspace/codebase}"
PROBE_BIN=""

# ── Locate target binary (prefer AUTOPOV_PROBE_BINARY from env) ────────────
if [ -n "${AUTOPOV_PROBE_BINARY:-}" ] && [ -x "$AUTOPOV_PROBE_BINARY" ]; then
  PROBE_BIN="$AUTOPOV_PROBE_BINARY"
else
  PROBE_BIN=$(find "$CB" -maxdepth 4 -type f -executable \
    ! -name "*.so" ! -name "*.so.*" ! -name "*.a" ! -name "*.py" \
    ! -name "*.sh" ! -name "*.js" \
    -not -path "*/.git/*" \
    -not -path "*/CMakeFiles/*" \
    -not -path "*/_codeql_build_dir/*" \
    -not -path "*/CompilerIdC/*" \
    2>/dev/null \
    | head -1)
fi

if [ -z "$PROBE_BIN" ]; then
  echo "TRACE_SKIPPED=no_binary"
  exit 0
fi

echo "TRACE_BINARY=$PROBE_BIN"

# ── Step 1: strace to detect input surface ─────────────────────────────────
set +e
TRACE_OPENS_FILES=0
TRACE_READS_STDIN=0
TRACE_INTERESTING_SYSCALLS=""
TRACE_FILE_EXTS=""

if command -v strace >/dev/null 2>&1; then
  # Create a tiny temp file to use as argv[1] candidate
  _TMPF=$(mktemp /tmp/trace_input_XXXXXX)
  printf '<root/>' > "$_TMPF"

  # Run strace with file_argument candidate
  STRACE_OUT=$(timeout 5 strace -f -e trace=openat,open,read,write \
    "$PROBE_BIN" "$_TMPF" 2>&1 || true)

  # Did binary try to open the file we passed as argv[1]?
  if echo "$STRACE_OUT" | grep -q "$_TMPF"; then
    TRACE_OPENS_FILES=1
    TRACE_INPUT_SURFACE="file_argument"
  fi

  # Extract file extensions from open calls to understand expected format
  TRACE_FILE_EXTS=$(echo "$STRACE_OUT" \
    | grep -oE '"[^"]+\.[a-z]{2,5}"' \
    | grep -oE '\.[a-z]{2,5}' \
    | sort -u | head -8 | tr '\n' ',' | sed 's/,$//')

  # Run again with stdin input
  STRACE_STDIN_OUT=$(printf 'AAAAAAAAAA' \
    | timeout 5 strace -f -e trace=openat,open,read \
    "$PROBE_BIN" 2>&1 || true)

  # Did binary read from fd=0 (stdin)?
  if echo "$STRACE_STDIN_OUT" | grep -qE 'read\(0,'; then
    TRACE_READS_STDIN=1
    if [ "$TRACE_OPENS_FILES" = "0" ]; then
      TRACE_INPUT_SURFACE="stdin"
    fi
  fi

  if [ "$TRACE_OPENS_FILES" = "0" ] && [ "$TRACE_READS_STDIN" = "0" ]; then
    TRACE_INPUT_SURFACE="argv_only"
  fi

  # Collect interesting syscall names (mmap, mprotect anomalies, execve children)
  TRACE_INTERESTING_SYSCALLS=$(echo "$STRACE_OUT" \
    | grep -oE '(mmap|mprotect|execve|fork|clone|socket|connect|bind|send|recv)\(' \
    | sort -u | head -10 | tr '\n' ',' | sed 's/,$//')

  rm -f "$_TMPF"
else
  TRACE_INPUT_SURFACE="unknown"
fi

echo "TRACE_OPENS_FILES=$TRACE_OPENS_FILES"
echo "TRACE_READS_STDIN=$TRACE_READS_STDIN"
echo "TRACE_INPUT_SURFACE=$TRACE_INPUT_SURFACE"
[ -n "$TRACE_FILE_EXTS" ] && echo "TRACE_FILE_EXTS=$TRACE_FILE_EXTS"
[ -n "$TRACE_INTERESTING_SYSCALLS" ] && echo "TRACE_INTERESTING_SYSCALLS=$TRACE_INTERESTING_SYSCALLS"

# ── Step 2: valgrind memory error detection ────────────────────────────────
TRACE_VALGRIND_ERRORS=0
TRACE_VALGRIND_SUMMARY=""
TRACE_VALGRIND_TYPES=""

if command -v valgrind >/dev/null 2>&1; then
  # Try up to 3 inputs: empty args, stdin bytes, file argument
  _INPUTS=("" "stdin" "file")
  for _INPUT_MODE in "${_INPUTS[@]}"; do
    _TMPF2=$(mktemp /tmp/valgrind_input_XXXXXX)
    printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00BBBBBBBB' > "$_TMPF2"

    if [ "$_INPUT_MODE" = "stdin" ]; then
      VG_OUT=$(timeout 15 valgrind --tool=memcheck \
        --error-exitcode=42 \
        --suppressions=/dev/null \
        --quiet \
        --num-callers=4 \
        "$PROBE_BIN" < "$_TMPF2" 2>&1 || true)
    elif [ "$_INPUT_MODE" = "file" ] && [ "$TRACE_OPENS_FILES" = "1" ]; then
      VG_OUT=$(timeout 15 valgrind --tool=memcheck \
        --error-exitcode=42 \
        --quiet \
        --num-callers=4 \
        "$PROBE_BIN" "$_TMPF2" 2>&1 || true)
    else
      VG_OUT=$(timeout 15 valgrind --tool=memcheck \
        --error-exitcode=42 \
        --quiet \
        --num-callers=4 \
        "$PROBE_BIN" 2>&1 || true)
    fi

    _VG_ERRS=$(echo "$VG_OUT" | grep -cE '^==.*ERROR SUMMARY:.*[1-9]' || true)
    _VG_ERRS2=$(echo "$VG_OUT" | grep -cE '(Invalid (read|write)|Use of uninitialised|Conditional jump|definitely lost:.*[1-9])' || true)

    if [ "${_VG_ERRS:-0}" -gt 0 ] || [ "${_VG_ERRS2:-0}" -gt 0 ]; then
      TRACE_VALGRIND_ERRORS=$(( ${_VG_ERRS:-0} + ${_VG_ERRS2:-0} ))
      TRACE_VALGRIND_SUMMARY=$(echo "$VG_OUT" | grep -E 'ERROR SUMMARY|definitely lost|Invalid|uninitialised' | head -5 | tr '\n' '|')
      TRACE_VALGRIND_TYPES=$(echo "$VG_OUT" | grep -oE '(Invalid (read|write)|Use of uninitialised|Conditional jump|definitely lost)' | sort -u | head -5 | tr '\n' ',' | sed 's/,$//')
      TRACE_CRASH_INPUT="$_INPUT_MODE"
      rm -f "$_TMPF2"
      break
    fi
    rm -f "$_TMPF2"
  done
fi

echo "TRACE_VALGRIND_ERRORS=$TRACE_VALGRIND_ERRORS"
[ -n "$TRACE_VALGRIND_SUMMARY" ] && echo "TRACE_VALGRIND_SUMMARY=$TRACE_VALGRIND_SUMMARY"
[ -n "$TRACE_VALGRIND_TYPES" ]   && echo "TRACE_VALGRIND_TYPES=$TRACE_VALGRIND_TYPES"
[ -n "$TRACE_CRASH_INPUT" ]      && echo "TRACE_CRASH_INPUT=$TRACE_CRASH_INPUT"

set -e
echo "TRACE_DONE=1"
"""


# ---------------------------------------------------------------------------
# Container execution
# ---------------------------------------------------------------------------

def _run_trace_container(
    codebase_path: str,
    probe_binary_path: str,
    repo_name: str,
    image: str,
    timeout: int = 120,
) -> str:
    """Run the trace shell script inside a Docker container and return stdout."""
    if not DOCKER_AVAILABLE:
        return 'TRACE_SKIPPED=docker_not_available'

    temp_dir = tempfile.mkdtemp(prefix='autopov_trace_')
    client = None
    container = None
    try:
        client = docker.from_env(timeout=30)
        try:
            client.images.get(image)
        except ImageNotFound:
            return f'TRACE_SKIPPED=image_not_found:{image}'

        script_path = os.path.join(temp_dir, 'trace.sh')
        with open(script_path, 'w') as f:
            f.write(_TRACE_SHELL_SCRIPT)

        archive_buf = io.BytesIO()
        with tarfile.open(fileobj=archive_buf, mode='w') as tar:
            tar.add(script_path, arcname='trace/trace.sh')
            if codebase_path and os.path.isdir(codebase_path):
                tar.add(codebase_path, arcname='workspace/codebase', recursive=True)
        archive_buf.seek(0)

        env = {
            'AUTOPOV_REPO_NAME': repo_name,
            'DEBIAN_FRONTEND': 'noninteractive',
        }
        if probe_binary_path:
            # Map host path → container path
            if codebase_path and probe_binary_path.startswith(codebase_path):
                rel = os.path.relpath(probe_binary_path, codebase_path)
                env['AUTOPOV_PROBE_BINARY'] = f'/workspace/codebase/{rel}'
            else:
                env['AUTOPOV_PROBE_BINARY'] = probe_binary_path

        container = client.containers.create(
            image=image,
            command=['bash', '-lc', 'chmod +x /trace/trace.sh && /trace/trace.sh /workspace/codebase'],
            working_dir='/',
            mem_limit='1g',
            cpu_quota=100000,
            network_mode='none',  # trace doesn't need network
            environment=env,
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

        logs = container.logs(stdout=True, stderr=True)
        return logs.decode('utf-8', errors='replace') if isinstance(logs, bytes) else str(logs)

    except Exception as exc:
        return f'TRACE_SKIPPED=container_error:{exc}'
    finally:
        if container:
            try:
                container.remove(force=True)
            except Exception:
                pass
        import shutil
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Output parser
# ---------------------------------------------------------------------------

def _parse_trace_output(raw_output: str) -> TraceResult:
    result = TraceResult()
    if not raw_output:
        result.trace_skipped = True
        result.trace_skip_reason = 'empty_output'
        return result

    for line in raw_output.splitlines():
        line = line.strip()
        if line.startswith('TRACE_SKIPPED='):
            result.trace_skipped = True
            result.trace_skip_reason = line[len('TRACE_SKIPPED='):]
        elif line.startswith('TRACE_BINARY='):
            result.trace_binary_path = line[len('TRACE_BINARY='):]
        elif line.startswith('TRACE_INPUT_SURFACE='):
            result.trace_input_surface = line[len('TRACE_INPUT_SURFACE='):]
        elif line.startswith('TRACE_OPENS_FILES='):
            result.trace_opens_files = line[len('TRACE_OPENS_FILES='):] == '1'
        elif line.startswith('TRACE_READS_STDIN='):
            result.trace_reads_stdin = line[len('TRACE_READS_STDIN='):] == '1'
        elif line.startswith('TRACE_FILE_EXTS='):
            val = line[len('TRACE_FILE_EXTS='):].strip()
            result.trace_file_extensions = [e.strip() for e in val.split(',') if e.strip()]
        elif line.startswith('TRACE_INTERESTING_SYSCALLS='):
            val = line[len('TRACE_INTERESTING_SYSCALLS='):].strip()
            result.trace_interesting_syscalls = [s.strip() for s in val.split(',') if s.strip()]
        elif line.startswith('TRACE_VALGRIND_ERRORS='):
            try:
                result.trace_valgrind_errors = int(line[len('TRACE_VALGRIND_ERRORS='):])
            except ValueError:
                pass
        elif line.startswith('TRACE_VALGRIND_SUMMARY='):
            result.trace_valgrind_summary = line[len('TRACE_VALGRIND_SUMMARY='):]
        elif line.startswith('TRACE_VALGRIND_TYPES='):
            val = line[len('TRACE_VALGRIND_TYPES='):].strip()
            result.trace_valgrind_error_types = [t.strip() for t in val.split(',') if t.strip()]
        elif line.startswith('TRACE_CRASH_INPUT='):
            result.trace_crash_input = line[len('TRACE_CRASH_INPUT='):]

    if result.trace_valgrind_errors > 0:
        result.trace_memory_errors_detected = True

    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_trace(
    codebase_path: str,
    scan_id: str,
    exploit_contract: Optional[Dict[str, Any]] = None,
    repo_surface_class: str = '',
) -> TraceResult:
    """Run the dynamic trace phase and return a TraceResult.

    Only runs for native C/C++ targets (cli_tool_c or library_c).
    All errors are caught and returned as a skipped TraceResult.
    """
    import time as _time
    t_start = _time.monotonic()
    result = TraceResult()

    # Only trace native C/C++ repos
    _cls = str(repo_surface_class or '').strip().lower()
    if _cls not in ('cli_tool_c', 'library_c', 'unknown', ''):
        result.trace_skipped = True
        result.trace_skip_reason = f'non_native_surface:{_cls}'
        return result

    if not codebase_path or not os.path.isdir(codebase_path):
        result.trace_skipped = True
        result.trace_skip_reason = 'no_codebase'
        return result

    contract = exploit_contract or {}
    probe_binary_path = str(contract.get('probe_binary_path') or '').strip()
    repo_name = Path(codebase_path).name

    # Determine image — use native proof image
    native_image = getattr(settings, 'NATIVE_PROOF_IMAGE', None) or \
                   getattr(settings, 'PROOF_IMAGES', {}).get('native') or \
                   'autopov/proof-native:latest'

    try:
        raw = _run_trace_container(
            codebase_path=codebase_path,
            probe_binary_path=probe_binary_path,
            repo_name=repo_name,
            image=native_image,
            timeout=120,
        )
        result = _parse_trace_output(raw)
    except Exception as exc:
        result.trace_skipped = True
        result.trace_skip_reason = f'exception:{exc}'
        result.trace_error = str(exc)

    result.trace_duration_s = _time.monotonic() - t_start
    return result


def format_trace_context(trace: TraceResult) -> str:
    """Serialise a TraceResult into a compact string for prompt injection."""
    if not trace or trace.trace_skipped:
        return ''

    lines = ['=== DYNAMIC TRACE RESULTS ===']

    if trace.trace_input_surface and trace.trace_input_surface != 'unknown':
        lines.append(f'INPUT SURFACE (confirmed by strace): {trace.trace_input_surface}')
        if trace.trace_input_surface == 'file_argument':
            lines.append('  -> Binary opens argv[1] as a file. Write payload to a temp file and pass its path.')
        elif trace.trace_input_surface == 'stdin':
            lines.append('  -> Binary reads from stdin (fd=0). Pipe payload via subprocess stdin.')
        elif trace.trace_input_surface == 'argv_only':
            lines.append('  -> Binary does not open files or read stdin. Payload goes in argv.')

    if trace.trace_file_extensions:
        lines.append(f'FILE EXTENSIONS OBSERVED: {", ".join(trace.trace_file_extensions)}')
        lines.append('  -> Use one of these extensions when creating the temp payload file.')

    if trace.trace_interesting_syscalls:
        lines.append(f'INTERESTING SYSCALLS: {", ".join(trace.trace_interesting_syscalls)}')

    if trace.trace_memory_errors_detected:
        lines.append(f'VALGRIND MEMORY ERRORS: {trace.trace_valgrind_errors} error(s) detected')
        if trace.trace_valgrind_error_types:
            lines.append(f'ERROR TYPES: {", ".join(trace.trace_valgrind_error_types)}')
        if trace.trace_valgrind_summary:
            # Truncate to keep prompt short
            lines.append(f'SUMMARY: {trace.trace_valgrind_summary[:300]}')
        lines.append('  -> Memory errors confirmed without ASan. PoV that reaches this code path will trigger them.')
        if trace.trace_crash_input:
            lines.append(f'  -> Triggered with input mode: {trace.trace_crash_input}')

    lines.append('=== END TRACE ===')
    return '\n'.join(lines)

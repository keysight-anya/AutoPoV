"""
pov_sanitizer.py — Pre-validation PoV script transformer.

Deterministically fixes C/C++ harness string-escaping issues produced by LLMs
before the PoV is handed to the validator.  This is language-agnostic at the
caller level: it is a no-op for any PoV that does not write a .c/.cpp file, so
it is safe to apply to every generated script unconditionally.

Problem being solved
---------------------
LLMs frequently generate Python scripts that write C source code using either:
  (a) Triple-quoted strings with real newlines:
        src = \"\"\"
        fprintf(stderr, "hello\\n");
        \"\"\"
  (b) Single/double-quoted strings with real literal newlines (syntax error in
      Python, but sometimes present in raw JSON output):
        src = "fprintf(stderr, \\"hello\\n\\");"
  (c) String concatenation where each C line is a quoted literal but the C
      string argument itself contains a real newline:
        src = (
            "fprintf(stderr, \\"hello\\n\\");"
        )

None of these produce a bad *Python* script — Python handles multi-line C source
inside triple-quoted strings just fine.  The problem arises when the C string
*argument* (the format string inside fprintf/printf/etc.) itself contains a bare
newline character, which is a syntax error in C:

  BROKEN:   fprintf(stderr, "hello
                     world");   ← bare newline inside C string literal

  CORRECT:  fprintf(stderr, "hello\\nworld");

This sanitizer detects and repairs that specific pattern without touching
anything else.

Strategy
--------
1. Verify the script is valid Python (ast.parse).
2. If no .c/.cpp write pattern is present, return unchanged (fast path).
3. Collect all string constant values that are written to .c/.cpp files by
   searching for the assignment variable used in write_text() / open().write().
4. For each such string, scan C-string arguments for bare newlines and replace
   them with \\n escape sequences.
5. Rewrite the script replacing the original string literal with a raw
   triple-quoted block that contains the repaired C source.  Raw triple-quoted
   strings (r\"\"\") can never suffer from escaping confusion: backslashes are
   literal, and the C source is stored verbatim.

This approach is repo-independent and language-general: it works for any C/C++
project because it operates purely on the generated Python script's string
content.
"""

from __future__ import annotations

import ast
import re
import textwrap
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

SANITIZER_MARKER = "# __pov_sanitizer_applied__"


def sanitize_pov_script(script: str) -> str:
    """
    Detect and repair C-harness string-escaping issues in a generated PoV script.

    Returns the (possibly repaired) script.  Never raises — on any unexpected
    error it logs a warning and returns the original unchanged.

    Safe to call unconditionally on every generated PoV: it is a no-op when the
    script does not write any .c/.cpp file.
    """
    if not script or not isinstance(script, str):
        return script

    # Already sanitized by a previous pass — skip.
    if SANITIZER_MARKER in script:
        return script

    try:
        return _sanitize(script)
    except Exception as exc:
        logger.warning("pov_sanitizer: unexpected error (returning original): %s", exc)
        return script


# ---------------------------------------------------------------------------
# Internal implementation
# ---------------------------------------------------------------------------

_C_FILE_WRITE_RE = re.compile(
    r'(?:write_text|\.write)\s*\(',
    re.IGNORECASE,
)

_C_FILE_REF_RE = re.compile(
    r'["\'].*?\.(c|cpp|h)["\']',
    re.IGNORECASE,
)

# Matches a C string argument that contains a real (bare) newline inside quotes.
# We look for: opening quote, any chars (non-quote), actual \n, any chars, closing quote.
# This matches across lines because the C source may span many lines.
_BARE_NL_IN_C_STRING_RE = re.compile(
    r'("(?:[^"\\]|\\.)*?\n(?:[^"\\]|\\.)*?")',
    re.DOTALL,
)


def _has_c_file_write(script: str) -> bool:
    """
    Quick pre-check: does this script write a .c/.cpp file?

    Deliberately conservative: only triggers when the script contains an
    explicit .c or .cpp filename reference (in quotes) AND a write call.
    This avoids false-positive sanitisation of Python/JS/Go/Ruby/PHP PoVs
    that happen to contain the word 'harness' in a comment or variable name.
    """
    lower = script.lower()
    # Must contain an explicit C/C++ file reference in quotes
    has_c_file_ref = (
        '.c"' in lower or ".c'" in lower
        or '.cpp"' in lower or ".cpp'" in lower
        or '.c)' in lower  # Path('...') / 'h.c' etc.
        or 'harness.c' in lower
        or 'evil.c' in lower
        or 'exploit.c' in lower
        or 'test.c' in lower
        or '/ "harness"' in lower  # path join patterns
    )
    has_write = 'write_text(' in lower or '.write(' in lower or 'open(' in lower
    return has_c_file_ref and has_write


def _repair_c_source(c_src: str) -> str:
    """
    Given a string containing C source code, replace every bare newline that
    appears inside a C string literal with the \\n escape sequence.

    Bare newlines OUTSIDE string literals (i.e. between statements) are left
    alone — they are structurally necessary for the C source to be readable and
    compile correctly.
    """
    result: list[str] = []
    i = 0
    length = len(c_src)

    while i < length:
        ch = c_src[i]

        # ── Line comment: // ... newline ──────────────────────────────────────
        if ch == '/' and i + 1 < length and c_src[i + 1] == '/':
            j = i
            while j < length and c_src[j] != '\n':
                j += 1
            result.append(c_src[i:j])  # include up to (but not including) newline
            i = j
            continue

        # ── Block comment: /* ... */ ──────────────────────────────────────────
        if ch == '/' and i + 1 < length and c_src[i + 1] == '*':
            end = c_src.find('*/', i + 2)
            if end == -1:
                result.append(c_src[i:])
                break
            result.append(c_src[i:end + 2])
            i = end + 2
            continue

        # ── C string literal: "..." ───────────────────────────────────────────
        if ch == '"':
            # Consume the string, replacing bare \n with \\n
            j = i + 1
            buf = ['"']
            while j < length:
                sc = c_src[j]
                if sc == '\\':
                    # Escape sequence — consume both chars verbatim
                    if j + 1 < length:
                        buf.append(sc)
                        buf.append(c_src[j + 1])
                        j += 2
                    else:
                        buf.append(sc)
                        j += 1
                elif sc == '"':
                    buf.append('"')
                    j += 1
                    break
                elif sc == '\n':
                    # BARE NEWLINE inside a C string — replace with \n escape
                    buf.append('\\n')
                    j += 1
                else:
                    buf.append(sc)
                    j += 1
            result.append(''.join(buf))
            i = j
            continue

        # ── C character literal: '.' ──────────────────────────────────────────
        if ch == "'":
            j = i + 1
            buf = ["'"]
            while j < length:
                sc = c_src[j]
                if sc == '\\':
                    if j + 1 < length:
                        buf.append(sc)
                        buf.append(c_src[j + 1])
                        j += 2
                    else:
                        buf.append(sc)
                        j += 1
                elif sc == "'":
                    buf.append("'")
                    j += 1
                    break
                elif sc == '\n':
                    buf.append('\\n')
                    j += 1
                else:
                    buf.append(sc)
                    j += 1
            result.append(''.join(buf))
            i = j
            continue

        result.append(ch)
        i += 1

    return ''.join(result)


def _make_raw_block(varname: str, c_src: str) -> str:
    """
    Emit:
        <varname> = r\"\"\"\\
        <c_src>
        \"\"\"
    choosing a delimiter that does not appear in c_src.
    """
    # Choose quote style that doesn't conflict
    if '"""' not in c_src:
        delim = '"""'
    elif "'''" not in c_src:
        delim = "'''"
    else:
        # Escape by chunking — extremely rare; fall back to repr()
        return f"{varname} = {repr(c_src)}"

    # Ensure source ends with a newline so the closing delimiter is on its own line
    if not c_src.endswith('\n'):
        c_src = c_src + '\n'

    return f'{varname} = r{delim}\\\n{c_src}{delim}'


# ---------------------------------------------------------------------------
# AST-based variable-tracking approach
# ---------------------------------------------------------------------------

def _find_c_source_vars(script: str) -> set[str]:
    """
    Parse the script with ast and return the set of variable names whose values
    are written to a .c/.cpp file via write_text() or open(...).write().

    Also returns names that appear in assignments where the value is clearly C
    source (contains #include, int main, or similar C landmarks).
    """
    try:
        tree = ast.parse(script)
    except SyntaxError:
        return set()

    c_vars: set[str] = set()

    # Walk all call nodes — find write_text(var) and open(...).write(var) etc.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Pattern: something.write_text(var_or_str, ...)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in ('write_text', 'write_bytes', 'write')
            and node.args
        ):
            arg0 = node.args[0]
            # Direct variable reference
            if isinstance(arg0, ast.Name):
                c_vars.add(arg0.id)
            # Or it might be a method call chain — extract inner name
            elif isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Attribute):
                if isinstance(arg0.func.value, ast.Name):
                    c_vars.add(arg0.func.value.id)

    return c_vars


def _extract_assignment_span(script: str, varname: str) -> Optional[tuple[int, int, str]]:
    """
    Find the source span of the assignment `varname = <expr>` in the script.
    Returns (start_pos, end_pos, original_text) or None.

    We use a line-by-line approach because AST line numbers are 1-based and we
    need byte positions for string replacement.
    """
    lines = script.splitlines(keepends=True)

    # Find the start line
    start_line_idx = None
    for i, line in enumerate(lines):
        stripped = line.lstrip()
        if stripped.startswith(varname + ' =') or stripped.startswith(varname + '='):
            # Make sure it's not inside a longer word (e.g. `evil_src` not `src`)
            col = line.index(stripped[0])
            before = line[:col]
            if not before.strip() or before.strip()[-1] in ('(', ',', '='):
                start_line_idx = i
                break

    if start_line_idx is None:
        return None

    # Collect lines until we have a syntactically complete assignment.
    # Strategy: try to parse `varname = <collected>` with ast.parse; grow until valid.
    collected_lines = []
    for i in range(start_line_idx, len(lines)):
        collected_lines.append(lines[i])
        candidate = ''.join(collected_lines)
        try:
            ast.parse(candidate)
            # Parsed successfully — this is the complete assignment
            start_pos = sum(len(l) for l in lines[:start_line_idx])
            end_pos = start_pos + len(candidate)
            return (start_pos, end_pos, candidate)
        except SyntaxError:
            continue

    return None


def _extract_string_value(assignment_src: str, varname: str) -> Optional[str]:
    """
    Given the source text of an assignment `varname = <expr>`, evaluate the
    expression safely using ast.literal_eval to get the actual string value.
    """
    # Strip the varname prefix
    idx = assignment_src.find('=')
    if idx == -1:
        return None
    rhs = assignment_src[idx + 1:].strip()
    try:
        val = ast.literal_eval(rhs)
        if isinstance(val, str):
            return val
        # Could be bytes
        if isinstance(val, bytes):
            return val.decode('utf-8', errors='replace')
    except (ValueError, SyntaxError):
        pass
    return None


def _sanitize(script: str) -> str:
    """Core sanitization logic."""

    # Fast path: no C file writes at all
    if not _has_c_file_write(script):
        return script

    # Find which variable names hold C source content
    c_src_vars = _find_c_source_vars(script)

    if not c_src_vars:
        # Fall back: look for any triple-quoted assignment containing C landmarks
        c_src_vars = _fallback_find_c_vars(script)

    if not c_src_vars:
        return script

    modified = script
    repaired_any = False

    for varname in c_src_vars:
        span = _extract_assignment_span(modified, varname)
        if span is None:
            continue

        start, end, original_text = span
        c_src = _extract_string_value(original_text, varname)

        if c_src is None:
            # Can't safely evaluate — try heuristic repair directly on the text
            repaired_text = _heuristic_repair_assignment(original_text, varname)
            if repaired_text != original_text:
                modified = modified[:start] + repaired_text + modified[end:]
                repaired_any = True
            continue

        # Check if the C source contains bare newlines inside string literals
        repaired_c_src = _repair_c_source(c_src)

        if repaired_c_src == c_src:
            # No repair needed for this variable
            continue

        # Rewrite the assignment as a raw triple-quoted block
        new_assignment = _make_raw_block(varname, repaired_c_src)
        # Preserve any leading indentation from the original assignment
        orig_indent = _get_indent(original_text)
        if orig_indent:
            new_assignment = textwrap.indent(new_assignment, orig_indent)

        modified = modified[:start] + new_assignment + '\n' + modified[end:]
        repaired_any = True
        logger.debug("pov_sanitizer: repaired variable '%s' (bare newlines in C strings)", varname)

    if repaired_any:
        # Add marker so we skip on re-entry, and log what happened
        modified = modified.rstrip('\n') + '\n' + SANITIZER_MARKER + '\n'
        logger.info("pov_sanitizer: script repaired (bare newlines in C string literals fixed)")

    return modified


def _fallback_find_c_vars(script: str) -> set[str]:
    """
    Heuristic: find variable names assigned multi-line strings that look like C.
    Used when AST walk found no explicit write_text/write calls.
    """
    c_landmarks = ('#include', 'int main', 'void main', '#define', 'static void',
                   'static int', 'static char', 'fprintf(', 'printf(')
    found: set[str] = set()

    # Match: varname = """...""" or varname = '''...''' or varname = ( "..." "..." )
    triple_re = re.compile(
        r'^[ \t]*(\w+)\s*=\s*(?:r?"""[\s\S]*?"""|r?\'\'\'[\s\S]*?\'\'\')',
        re.MULTILINE,
    )
    for m in triple_re.finditer(script):
        content = m.group(0)
        if any(lm in content for lm in c_landmarks):
            found.add(m.group(1))

    # Match concatenated string assignment: varname = (\n    "..."\n    "..."\n)
    concat_re = re.compile(
        r'^[ \t]*(\w+)\s*=\s*\(',
        re.MULTILINE,
    )
    for m in concat_re.finditer(script):
        # Grab until closing paren
        start = m.start()
        depth = 0
        i = script.index('(', start)
        end = i
        for j in range(i, min(i + 8000, len(script))):
            if script[j] == '(':
                depth += 1
            elif script[j] == ')':
                depth -= 1
                if depth == 0:
                    end = j + 1
                    break
        block = script[start:end]
        if any(lm in block for lm in c_landmarks):
            found.add(m.group(1))

    return found


def _heuristic_repair_assignment(text: str, varname: str) -> str:
    """
    Last-resort repair: directly scan the assignment text for bare newlines
    inside C string arguments and replace them with \\n.

    This operates on the Python source text (not the string value), so we must
    be careful to only touch content inside string literals.
    """
    # Only apply if we can identify C string arguments with bare newlines
    if not _BARE_NL_IN_C_STRING_RE.search(text):
        return text

    def _fix_c_str(m: re.Match) -> str:
        # m.group(1) is the C string contents including surrounding quotes
        content = m.group(1)
        # Replace bare newlines not already escaped
        fixed = re.sub(r'(?<!\\)\n', r'\\n', content)
        return fixed

    return _BARE_NL_IN_C_STRING_RE.sub(_fix_c_str, text)


def _get_indent(text: str) -> str:
    """Return the leading whitespace of the first non-empty line."""
    for line in text.splitlines():
        if line.strip():
            return line[: len(line) - len(line.lstrip())]
    return ''

"""
Generate AutoPoV Application Flow PDF
Clean, readable, no markdown artefacts
"""

from pathlib import Path
import re
import textwrap

DST = Path('/home/user/AutoPoV/DOCS_APPLICATION_FLOW.pdf')

PAGE_W = 612
PAGE_H = 792
MARGIN_L = 60
MARGIN_R = 60
MARGIN_T = 60
MARGIN_B = 60
USABLE_W = PAGE_W - MARGIN_L - MARGIN_R

FONT_TITLE   = 18
FONT_H1      = 14
FONT_H2      = 12
FONT_BODY    = 11
FONT_CODE    = 10
FONT_TABLE   = 10
FONT_SMALL   = 9

LEAD_TITLE   = 26
LEAD_H1      = 22
LEAD_H2      = 18
LEAD_BODY    = 16
LEAD_CODE    = 14
LEAD_TABLE   = 14

# ---------------------------------------------------------------------------
# Content definition  (plain text, no markdown, no em-dashes)
# ---------------------------------------------------------------------------

CONTENT = [

    # (type, text/rows)
    # types: title, h1, h2, body, bullet, code, table, spacer, rule, newpage

    ("title", "AutoPoV"),
    ("body",  "Automated Proof-of-Vulnerability Framework"),
    ("body",  "Application Flow and System Reference"),
    ("spacer", 20),
    ("rule",  ""),
    ("spacer", 10),

    # ---- Overview ----
    ("h1", "1.  System Overview"),
    ("body",
     "AutoPoV is a multi-agent vulnerability scanner. It takes a codebase, finds security "
     "weaknesses, confirms whether each one is real, and generates a working proof that the "
     "weakness can be triggered. Everything runs autonomously once a scan is submitted."),
    ("spacer", 6),
    ("body",
     "The system is built on a LangGraph state machine. The graph is compiled once at startup "
     "and shared across all scans. When a scan starts, the graph is given an initial state and "
     "runs to completion on its own. Each node in the graph reads the state, does its work, "
     "updates the state, and passes control to the next node."),
    ("spacer", 6),
    ("body", "The agent loop at a high level:"),
    ("bullet", "Read current state"),
    ("bullet", "Decide what to do next (routing condition)"),
    ("bullet", "Do the work (call a tool or a language model)"),
    ("bullet", "Write results back into state"),
    ("bullet", "Route to the next node and repeat"),
    ("spacer", 10),
    ("rule", ""),

    # ---- Stage 1 ----
    ("h1", "2.  Stage 1 -- Scan Intake"),
    ("body",
     "A scan can be started from four different places:"),
    ("spacer", 4),
    ("table", {
        "headers": ["Entry Point", "API Endpoint", "Source"],
        "rows": [
            ["Git repository",  "POST /api/scan/git",    "Cloned from a URL"],
            ["ZIP archive",     "POST /api/scan/zip",    "Uploaded file"],
            ["Raw code paste",  "POST /api/scan/paste",  "Inline text string"],
            ["Webhook event",   "POST /api/webhook/github  or  /gitlab", "Push or pull-request"],
        ],
        "widths": [120, 190, 150],
    }),
    ("spacer", 8),
    ("body", "When a scan is submitted, the API layer does the following:"),
    ("bullet", "Validates the API key using a SHA-256 hash comparison"),
    ("bullet", "Checks the per-key rate limit (10 scans per 60 seconds)"),
    ("bullet", "Creates a scan record with a unique scan ID and status 'created'"),
    ("bullet", "Clones the repo, extracts the ZIP, or saves the pasted code to disk"),
    ("bullet", "Starts the agent graph in a background thread"),
    ("bullet", "Returns the scan ID immediately so the caller does not have to wait"),
    ("spacer", 10),
    ("rule", ""),

    # ---- Stage 2 ----
    ("h1", "3.  Stage 2 -- Code Ingestion"),
    ("body",
     "Before any analysis begins, the Ingestion Agent prepares the codebase for semantic "
     "search. This lets every later agent retrieve the exact code context it needs without "
     "reading whole files."),
    ("spacer", 6),
    ("body", "What the Ingestion Agent does:"),
    ("bullet", "Walks every file in the codebase, skipping binaries and build folders"),
    ("bullet", "Splits each file into overlapping chunks (4,000 characters with 200-character overlap, "
               "splitting on class and function boundaries first)"),
    ("bullet", "Embeds each chunk using 'openai/text-embedding-3-small' (online mode) or "
               "'sentence-transformers/all-MiniLM-L6-v2' (offline mode)"),
    ("bullet", "Stores the chunks and their embeddings in ChromaDB under a collection "
               "scoped to the scan ID"),
    ("spacer", 6),
    ("body",
     "If embedding fails for any reason, the scan continues. Later agents fall back to "
     "reading files directly from disk."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Stage 3 ----
    ("h1", "4.  Stage 3 -- Vulnerability Discovery"),
    ("body",
     "Three strategies run in sequence. Their results are merged and any duplicate "
     "findings at the same file, line, and CWE are removed."),
    ("spacer", 8),

    ("h2", "4a.  CodeQL Static Discovery"),
    ("body",
     "CodeQL is a static analysis tool that builds a database from the source code and then "
     "runs structured queries against it. It understands data flow and the code's syntax tree, "
     "so it can follow a variable from user input all the way to a dangerous function call."),
    ("spacer", 4),
    ("body", "Steps:"),
    ("bullet", "Detect the main programming language from file extensions"),
    ("bullet", "Build a CodeQL database from the source root"),
    ("bullet", "Run one query per requested CWE (SQL injection, path traversal, XSS, etc.)"),
    ("bullet", "Parse the SARIF output -- each result becomes a candidate finding with 0.8 confidence"),
    ("bullet", "Remove the database when all queries are done"),
    ("spacer", 4),
    ("body",
     "If CodeQL is not installed, the system skips this step and relies on the other two methods."),
    ("spacer", 8),

    ("h2", "4b.  Heuristic Scout"),
    ("body",
     "The Heuristic Scout runs regex patterns against every code file. It covers all 20 "
     "supported CWEs and runs in milliseconds with no cost. It catches issues that CodeQL "
     "can miss, such as Python-specific string formatting in SQL queries."),
    ("spacer", 4),
    ("body",
     "Findings from the Heuristic Scout have a confidence of 0.35. They are candidates that "
     "the Investigator Agent must confirm before they go any further."),
    ("spacer", 8),

    ("h2", "4c.  LLM Scout"),
    ("body",
     "If the LLM Scout is enabled, it sends batches of file snippets to the language model "
     "and asks it to identify potential vulnerabilities. It is used as a last resort when "
     "neither CodeQL nor heuristics find anything."),
    ("spacer", 4),
    ("body", "It respects a cost limit (SCOUT_MAX_COST_USD) and stops if it would exceed it."),
    ("spacer", 6),
    ("body",
     "Supported CWEs: CWE-89 (SQL Injection), CWE-79 (XSS), CWE-22 (Path Traversal), "
     "CWE-78 (Command Injection), CWE-94 (Code Injection), CWE-502 (Unsafe Deserialization), "
     "CWE-798 (Hardcoded Credentials), CWE-312 (Cleartext Storage), CWE-327 (Weak Crypto), "
     "CWE-352 (CSRF), CWE-287 (Auth Failure), CWE-306 (Missing Auth), CWE-601 (Open Redirect), "
     "CWE-918 (SSRF), CWE-434 (File Upload), CWE-611 (XXE), CWE-400 (Resource Exhaustion), "
     "CWE-384 (Session Fixation), CWE-200 (Info Disclosure), CWE-20 (Input Validation)."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Stage 4 ----
    ("h1", "5.  Stage 4 -- Investigation"),
    ("body",
     "The Investigator Agent reviews each candidate finding one at a time. It assembles "
     "context and asks a language model to decide whether the finding is a real vulnerability "
     "or a false positive."),
    ("spacer", 6),
    ("body", "For each finding the agent:"),
    ("bullet", "Reads the 50 lines of source code surrounding the flagged line"),
    ("bullet", "Queries ChromaDB for semantically related code chunks from the same codebase"),
    ("bullet", "For CWE-416 (Use-After-Free) only: runs Joern to trace data flow in the call graph"),
    ("bullet", "Sends all context to the language model with a structured prompt"),
    ("bullet", "Parses the response to get a verdict (REAL or FALSE_POSITIVE), a confidence "
               "score between 0 and 1, an explanation, and the exact vulnerable code snippet"),
    ("bullet", "Records the model used, cost, verdict, and confidence to the Learning Store"),
    ("spacer", 8),

    ("h2", "5a.  Model Selection (Policy Agent)"),
    ("body",
     "Before each investigation call, the Policy Agent picks which language model to use. "
     "There are three routing modes:"),
    ("spacer", 4),
    ("table", {
        "headers": ["Mode",    "Behaviour"],
        "rows": [
            ["auto",     "OpenRouter picks the best available model automatically"],
            ["fixed",    "Always uses the model set in MODEL_NAME"],
            ["learning", "Picks the model with the best confirmed-vulnerability-to-cost ratio "
                         "for this CWE and language, based on past scans in the Learning Store"],
        ],
        "widths": [80, 360],
    }),
    ("spacer", 8),
    ("body",
     "Only findings where the verdict is REAL and confidence is 0.7 or higher move forward "
     "to PoV generation. Everything else is marked as skipped."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Stage 5 ----
    ("h1", "6.  Stage 5 -- Proof-of-Vulnerability Generation"),
    ("body",
     "For each confirmed finding, the PoV Generator Agent writes a script that actually "
     "triggers the vulnerability. The goal is not just to identify the problem but to "
     "prove it can be exploited."),
    ("spacer", 6),
    ("body", "The agent:"),
    ("bullet", "Retrieves the full source file from ChromaDB or disk"),
    ("bullet", "Detects the target codebase language"),
    ("bullet", "Sends the vulnerable code, the explanation, and the language context to "
               "the language model"),
    ("bullet", "Instructs the model that the script must print VULNERABILITY TRIGGERED "
               "when it successfully triggers the issue"),
    ("bullet", "Strips markdown formatting from the response and stores the clean script"),
    ("spacer", 6),
    ("body",
     "PoV scripts must use only the Python standard library. No third-party packages are "
     "allowed, so the script can run in any isolated environment without setup."),
    ("spacer", 6),
    ("body",
     "If generation fails, the finding is marked pov_generation_failed and the scan moves on."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Stage 6 ----
    ("h1", "7.  Stage 6 -- Validation"),
    ("body",
     "The Validation Agent checks that the generated PoV script is actually correct. "
     "It uses three methods in order, stopping as soon as one gives a confident answer."),
    ("spacer", 6),
    ("table", {
        "headers": ["Tier", "Method", "When it stops"],
        "rows": [
            ["1 -- Static",    "Checks the script for correct exploit patterns, "
                               "required print statement, stdlib-only imports, and "
                               "CWE-specific logic",
             "Confidence >= 80% -> confirmed"],
            ["2 -- Unit Test", "Runs the PoV in an isolated subprocess with the "
                               "vulnerable code injected into its namespace",
             "VULNERABILITY TRIGGERED in stdout -> confirmed"],
            ["3 -- Docker",    "Runs the PoV in a sandboxed container (no network, "
                               "512 MB RAM, 1 CPU, 60-second timeout)",
             "VULNERABILITY TRIGGERED in container stdout -> confirmed"],
        ],
        "widths": [80, 230, 150],
    }),
    ("spacer", 8),
    ("body",
     "If validation fails, the PoV Generator Agent is called again with feedback about "
     "what went wrong. This retry loop runs up to 2 times before the finding is marked failed."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Stage 7 ----
    ("h1", "8.  Stage 7 -- Loop Routing"),
    ("body",
     "After each finding is resolved (confirmed, skipped, or failed), the graph's router:"),
    ("bullet", "Increments the finding index"),
    ("bullet", "Checks if more findings remain"),
    ("bullet", "If yes: routes back to the Investigator Agent for the next finding"),
    ("bullet", "If no: marks the scan as completed and exits"),
    ("spacer", 6),
    ("body",
     "This loop is what makes the system agentic. The graph does not run linearly. "
     "It cycles through each finding, running the full investigation and validation "
     "pipeline for each one, until all findings are resolved."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Stage 8 ----
    ("h1", "9.  Stage 8 -- Results and Reports"),
    ("body",
     "When the agent graph finishes, the Scan Manager saves the results:"),
    ("bullet", "Full result JSON saved to results/runs/<scan_id>.json"),
    ("bullet", "A summary row appended to results/runs/scan_history.csv"),
    ("bullet", "Confirmed PoV scripts saved to results/povs/"),
    ("bullet", "Optional codebase snapshot at results/snapshots/<scan_id>/ "
               "(enabled by SAVE_CODEBASE_SNAPSHOT=true, needed for replay)"),
    ("spacer", 6),
    ("body",
     "Reports can be downloaded at any time via GET /api/report/<scan_id>?format=json "
     "or ?format=pdf. The PDF includes an executive summary, confirmed vulnerabilities "
     "with PoV scripts, false positive analysis, model usage, and cost breakdown."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Observability ----
    ("h1", "10.  Real-Time Observability"),
    ("body",
     "Every log message written by an agent is:"),
    ("bullet", "Appended to the LangGraph state's log list"),
    ("bullet", "Written immediately to the Scan Manager's in-memory log buffer (thread-safe)"),
    ("bullet", "Streamed to any connected client via Server-Sent Events (SSE) at "
               "GET /api/scan/<scan_id>/stream"),
    ("spacer", 6),
    ("body",
     "Both the web dashboard and the CLI connect to this stream and display live agent "
     "activity as the scan runs."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Learning Store ----
    ("h1", "11.  Self-Improvement via the Learning Store"),
    ("body",
     "Every investigation and PoV run is recorded in SQLite at data/learning.db. "
     "The Policy Agent queries this database when selecting a model:"),
    ("spacer", 6),
    ("code", "SELECT model, confirmed / (cost + 0.01) AS score"),
    ("code", "FROM   investigations"),
    ("code", "WHERE  cwe = ? AND language = ?"),
    ("code", "GROUP  BY model ORDER BY score DESC"),
    ("spacer", 6),
    ("body",
     "In learning routing mode, the top-scoring model is picked automatically. "
     "The more scans the system runs, the more accurate its model selection becomes."),
    ("spacer", 10),
    ("rule", ""),

    # ---- API ----
    ("h1", "12.  API Reference"),
    ("table", {
        "headers": ["Method", "Endpoint", "Auth", "Description"],
        "rows": [
            ["POST",   "/api/scan/git",           "API Key",    "Scan a Git repository"],
            ["POST",   "/api/scan/zip",            "API Key",    "Scan a ZIP archive"],
            ["POST",   "/api/scan/paste",          "API Key",    "Scan pasted code"],
            ["GET",    "/api/scan/{id}",           "API Key",    "Get scan status and findings"],
            ["GET",    "/api/scan/{id}/stream",    "API Key*",   "Stream live agent logs (SSE)"],
            ["POST",   "/api/scan/{id}/cancel",    "API Key",    "Cancel a running scan"],
            ["POST",   "/api/scan/{id}/replay",    "API Key",    "Re-run findings against new models"],
            ["GET",    "/api/history",             "API Key",    "Paginated scan history"],
            ["GET",    "/api/report/{id}",         "API Key",    "Download report (JSON or PDF)"],
            ["GET",    "/api/learning/summary",    "API Key",    "Model performance stats"],
            ["GET",    "/api/metrics",             "API Key",    "System-wide metrics"],
            ["GET",    "/api/config",              "API Key",    "Config and tool availability"],
            ["GET",    "/api/health",              "None",       "Health check"],
            ["POST",   "/api/keys/generate",       "Admin Key",  "Create a new API key"],
            ["GET",    "/api/keys",                "Admin Key",  "List all API keys"],
            ["DELETE", "/api/keys/{id}",           "Admin Key",  "Revoke an API key"],
            ["POST",   "/api/admin/cleanup",       "Admin Key",  "Remove old result files"],
            ["POST",   "/api/webhook/github",      "HMAC",       "GitHub push triggers a scan"],
            ["POST",   "/api/webhook/gitlab",      "Token",      "GitLab push triggers a scan"],
        ],
        "widths": [48, 160, 72, 170],
    }),
    ("spacer", 6),
    ("body", "* SSE endpoint accepts the API key as a query parameter: ?api_key=..."),
    ("body", "Interactive docs available at: http://localhost:8000/api/docs"),
    ("spacer", 10),
    ("rule", ""),

    # ---- Auth ----
    ("h1", "13.  Authentication"),
    ("table", {
        "headers": ["Key Type", "Stored As", "Rate Limit", "Used For"],
        "rows": [
            ["Admin Key", "Plaintext in .env",           "None",              "Key management endpoints"],
            ["API Key",   "SHA-256 hash in api_keys.json", "10 scans / 60s",  "All scan and data endpoints"],
        ],
        "widths": [80, 140, 100, 140],
    }),
    ("spacer", 6),
    ("body",
     "API keys are compared using SHA-256 hashing. The last-used timestamp is batched "
     "in memory and flushed to disk every 30 seconds to avoid constant disk writes."),
    ("spacer", 10),
    ("rule", ""),

    # ---- Components ----
    ("h1", "14.  Component Summary"),
    ("table", {
        "headers": ["Component", "File", "Responsibility"],
        "rows": [
            ["Scan Manager",      "app/scan_manager.py",       "Scan lifecycle, state, history, metrics"],
            ["Agent Graph",       "app/agent_graph.py",        "LangGraph state machine, all agent nodes"],
            ["Investigator",      "agents/investigator.py",    "LLM-based verdict on each finding"],
            ["Verifier",          "agents/verifier.py",        "PoV generation and validation"],
            ["Heuristic Scout",   "agents/heuristic_scout.py", "Regex-based candidate discovery"],
            ["LLM Scout",         "agents/llm_scout.py",       "LLM-based candidate discovery"],
            ["Code Ingester",     "agents/ingest_codebase.py", "ChromaDB embedding and retrieval"],
            ["Static Validator",  "agents/static_validator.py","Pattern-based PoV verification"],
            ["Unit Test Runner",  "agents/unit_test_runner.py","Subprocess-based PoV execution"],
            ["Docker Runner",     "agents/docker_runner.py",   "Sandboxed container PoV execution"],
            ["Policy Agent",      "app/policy.py",             "Model routing decisions"],
            ["Learning Store",    "app/learning_store.py",     "SQLite performance history"],
            ["Report Generator",  "app/report_generator.py",   "JSON and PDF report output"],
            ["Git Handler",       "app/git_handler.py",        "Repository cloning and validation"],
            ["Source Handler",    "app/source_handler.py",     "ZIP extraction and code paste handling"],
            ["Webhook Handler",   "app/webhook_handler.py",    "GitHub and GitLab webhook processing"],
            ["Auth",              "app/auth.py",               "API key validation and rate limiting"],
            ["Config",            "app/config.py",             "All environment settings"],
            ["Prompts",           "prompts.py",                "All LLM prompt templates"],
        ],
        "widths": [110, 165, 175],
    }),
    ("spacer", 10),
    ("rule", ""),

    # ---- Pipeline diagram ----
    ("h1", "15.  Pipeline at a Glance"),
    ("code", "Code Input  (Git / ZIP / Paste / Webhook)"),
    ("code", "     |"),
    ("code", "     v"),
    ("code", "[Ingestion Agent]  -->  ChromaDB vector store"),
    ("code", "     |"),
    ("code", "     v"),
    ("code", "[Discovery]"),
    ("code", "  |-- CodeQL        (AST + dataflow queries, SARIF output)"),
    ("code", "  |-- Heuristic Scout (regex patterns, all 20 CWEs, zero cost)"),
    ("code", "  +-- LLM Scout      (language model, fallback only)"),
    ("code", "     |"),
    ("code", "     v  merged + deduplicated"),
    ("code", "[Investigator Agent]  <-- ChromaDB context + Policy Agent"),
    ("code", "     |  verdict: REAL, confidence >= 0.7"),
    ("code", "     v"),
    ("code", "[PoV Generator Agent]"),
    ("code", "     |"),
    ("code", "     v"),
    ("code", "[Validation Agent]"),
    ("code", "  |-- Tier 1: Static analysis"),
    ("code", "  |-- Tier 2: Unit test subprocess"),
    ("code", "  +-- Tier 3: Docker container (sandboxed)"),
    ("code", "     |"),
    ("code", "     v"),
    ("code", "[Learning Store]  <-- records every outcome"),
    ("code", "     |"),
    ("code", "     v"),
    ("code", "[Report Generator]  -->  JSON + PDF download"),
    ("spacer", 10),
]


# ---------------------------------------------------------------------------
# PDF builder (raw PDF 1.4, no external libraries needed)
# ---------------------------------------------------------------------------

objects = []

def add_obj(content: str) -> int:
    objects.append(content)
    return len(objects)


def esc(s: str) -> str:
    return s.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


class Page:
    def __init__(self):
        self.ops: list[str] = []
        self.y: float = PAGE_H - MARGIN_T

    def remaining(self) -> float:
        return self.y - MARGIN_B

    def _set_font(self, name: str, size: int):
        self.ops.append(f'/{name} {size} Tf')

    def text_line(self, x: float, y: float, text: str, font: str, size: int, leading: int):
        self.ops.append('BT')
        self._set_font(font, size)
        self.ops.append(f'{leading} TL')
        self.ops.append(f'{x:.1f} {y:.1f} Td')
        self.ops.append(f'({esc(text)}) Tj')
        self.ops.append('ET')
        self.y = y - leading

    def rule_line(self, y: float):
        self.ops.append(f'{MARGIN_L:.1f} {y:.1f} m {PAGE_W - MARGIN_R:.1f} {y:.1f} l S')
        self.y = y - 8

    def stream(self) -> str:
        return '\n'.join(self.ops)


def wrap_text(text: str, max_chars: int) -> list[str]:
    return textwrap.wrap(text, width=max_chars) or ['']


def char_width(font_size: int) -> float:
    # Helvetica average char width is roughly 0.5 * font_size
    return font_size * 0.52


def max_chars(font_size: int, width: float) -> int:
    return max(10, int(width / char_width(font_size)))


pages: list[Page] = []

def new_page() -> Page:
    p = Page()
    pages.append(p)
    return p


def ensure_space(page: Page, need: float) -> Page:
    if page.remaining() < need:
        return new_page()
    return page


def emit_body(page: Page, text: str, font='F1', size=FONT_BODY, leading=LEAD_BODY,
              indent=0, color_ops=None) -> Page:
    max_c = max_chars(size, USABLE_W - indent)
    lines = wrap_text(text, max_c)
    for line in lines:
        page = ensure_space(page, leading + 2)
        if color_ops:
            page.ops.extend(color_ops)
        page.text_line(MARGIN_L + indent, page.y, line, font, size, leading)
        if color_ops:
            page.ops.append('0 0 0 rg')  # reset to black
    return page


def emit_table(page: Page, headers, rows, widths) -> Page:
    row_h = LEAD_TABLE + 6
    header_h = row_h

    # Estimate total height
    def row_lines(row):
        mx = 0
        for i, cell in enumerate(row):
            w = widths[i] if i < len(widths) else 80
            mc = max_chars(FONT_TABLE, w - 6)
            mx = max(mx, len(wrap_text(str(cell), mc)))
        return mx

    total_h = header_h + sum(row_lines(r) * row_h + 4 for r in rows) + 10

    if page.remaining() < min(total_h, 150):
        page = new_page()

    y = page.y
    x0 = MARGIN_L
    table_w = sum(widths)

    # Header background (light gray)
    page.ops.append('0.88 0.88 0.88 rg')
    page.ops.append(f'{x0:.1f} {y - header_h + 4:.1f} {table_w:.1f} {header_h:.1f} re f')
    page.ops.append('0 0 0 rg')

    # Header text
    x = x0
    for i, h in enumerate(headers):
        w = widths[i] if i < len(widths) else 80
        mc = max_chars(FONT_TABLE, w - 6)
        cell_lines = wrap_text(str(h).upper(), mc)
        cy = y - 2
        for cl in cell_lines:
            page.ops.append('BT')
            page.ops.append(f'/F2 {FONT_TABLE} Tf')
            page.ops.append(f'{x + 3:.1f} {cy:.1f} Td')
            page.ops.append(f'({esc(cl)}) Tj')
            page.ops.append('ET')
            cy -= LEAD_TABLE
        x += w

    y -= header_h
    page.ops.append(f'0.7 0.7 0.7 RG 0.5 w')
    page.ops.append(f'{x0:.1f} {y:.1f} m {x0 + table_w:.1f} {y:.1f} l S')
    page.ops.append('0 0 0 RG 1 w')

    # Rows
    for ri, row in enumerate(rows):
        # Compute height of this row
        max_l = row_lines(row)
        rh = max_l * row_h + 4

        if page.remaining() < rh + 4:
            page = new_page()
            y = page.y

        # Alternating row background
        if ri % 2 == 0:
            page.ops.append('0.96 0.96 0.96 rg')
            page.ops.append(f'{x0:.1f} {y - rh:.1f} {table_w:.1f} {rh:.1f} re f')
            page.ops.append('0 0 0 rg')

        x = x0
        for i, cell in enumerate(row):
            w = widths[i] if i < len(widths) else 80
            mc = max_chars(FONT_TABLE, w - 6)
            cell_lines = wrap_text(str(cell), mc)
            cy = y - 4
            for cl in cell_lines:
                page.ops.append('BT')
                page.ops.append(f'/F1 {FONT_TABLE} Tf')
                page.ops.append(f'{x + 3:.1f} {cy:.1f} Td')
                page.ops.append(f'({esc(cl)}) Tj')
                page.ops.append('ET')
                cy -= LEAD_TABLE
            x += w

        y -= rh
        # Row divider
        page.ops.append(f'0.85 0.85 0.85 RG 0.3 w')
        page.ops.append(f'{x0:.1f} {y:.1f} m {x0 + table_w:.1f} {y:.1f} l S')
        page.ops.append('0 0 0 RG 1 w')

    page.y = y - 6
    return page


# ---- Build pages ----
page = new_page()

for item in CONTENT:
    kind = item[0]
    data = item[1]

    if kind == 'title':
        page = ensure_space(page, LEAD_TITLE + 4)
        page.text_line(MARGIN_L, page.y, data, 'F2', FONT_TITLE, LEAD_TITLE)

    elif kind == 'h1':
        page = ensure_space(page, LEAD_H1 + 8)
        page.y -= 4
        page.text_line(MARGIN_L, page.y, data, 'F2', FONT_H1, LEAD_H1)
        # underline
        uy = page.y + 2
        page.ops.append(f'0.3 0.3 0.3 RG 0.5 w')
        page.ops.append(f'{MARGIN_L:.1f} {uy:.1f} m {PAGE_W - MARGIN_R:.1f} {uy:.1f} l S')
        page.ops.append('0 0 0 RG 1 w')
        page.y -= 4

    elif kind == 'h2':
        page = ensure_space(page, LEAD_H2 + 4)
        page.y -= 2
        page.text_line(MARGIN_L, page.y, data, 'F2', FONT_H2, LEAD_H2)

    elif kind == 'body':
        page = emit_body(page, data)

    elif kind == 'bullet':
        page = ensure_space(page, LEAD_BODY + 2)
        page = emit_body(page, f'  * {data}', size=FONT_BODY, indent=4)

    elif kind == 'code':
        page = ensure_space(page, LEAD_CODE + 2)
        page = emit_body(page, data, font='F3', size=FONT_CODE, leading=LEAD_CODE, indent=16)

    elif kind == 'table':
        page = emit_table(page, data['headers'], data['rows'], data['widths'])

    elif kind == 'spacer':
        amt = data if isinstance(data, (int, float)) else 8
        page.y -= amt
        if page.y < MARGIN_B:
            page = new_page()

    elif kind == 'rule':
        page = ensure_space(page, 14)
        page.ops.append(f'0.7 0.7 0.7 RG 0.5 w')
        page.ops.append(f'{MARGIN_L:.1f} {page.y:.1f} m '
                        f'{PAGE_W - MARGIN_R:.1f} {page.y:.1f} l S')
        page.ops.append('0 0 0 RG 1 w')
        page.y -= 10

    elif kind == 'newpage':
        page = new_page()


# ---- Write PDF ----
font_reg  = add_obj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>')
font_bold = add_obj('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>')
font_mono = add_obj('<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>')

pages_parent_idx = len(objects) + 1 + len(pages)  # will be the Pages dict

page_obj_ids = []
for pg in pages:
    stream = pg.stream()
    stream_bytes = stream.encode('latin-1', errors='replace')
    content_id = add_obj(
        f'<< /Length {len(stream_bytes)} >>\nstream\n{stream}\nendstream'
    )
    page_id = add_obj(
        f'<< /Type /Page /Parent {pages_parent_idx} 0 R '
        f'/Resources << /Font << /F1 {font_reg} 0 R /F2 {font_bold} 0 R /F3 {font_mono} 0 R >> >> '
        f'/MediaBox [0 0 {PAGE_W} {PAGE_H}] /Contents {content_id} 0 R >>'
    )
    page_obj_ids.append(page_id)

kids = ' '.join(f'{p} 0 R' for p in page_obj_ids)
pages_dict_id = add_obj(f'<< /Type /Pages /Kids [{kids}] /Count {len(page_obj_ids)} >>')

catalog_id = add_obj(f'<< /Type /Catalog /Pages {pages_dict_id} 0 R >>')

xref_pos = []
with DST.open('wb') as f:
    f.write(b'%PDF-1.4\n')
    for i, obj in enumerate(objects, start=1):
        xref_pos.append(f.tell())
        f.write(f'{i} 0 obj\n'.encode())
        f.write(obj.encode('latin-1', errors='replace'))
        f.write(b'\nendobj\n')
    xref_start = f.tell()
    f.write(f'xref\n0 {len(objects) + 1}\n'.encode())
    f.write(b'0000000000 65535 f \n')
    for pos in xref_pos:
        f.write(f'{pos:010d} 00000 n \n'.encode())
    f.write(b'trailer\n')
    f.write(f'<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n'.encode())
    f.write(b'startxref\n')
    f.write(f'{xref_start}\n'.encode())
    f.write(b'%%EOF\n')

print(f'Done: {DST}  ({len(pages)} pages)')

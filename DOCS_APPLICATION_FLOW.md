# AutoPoV Application Flow (End-to-End)

This document explains how AutoPoV works from start to finish, based on the current code paths.

## 1. Scan is started
A scan can be triggered in three ways:
- **Git repo** (`/api/scan/git`)
- **ZIP upload** (`/api/scan/zip`)
- **Paste code** (`/api/scan/paste`)

The backend creates a scan record with a new `scan_id` and initializes status + logs.

## 2. Source preparation
- **Git**: repository is cloned into a scan workspace.
- **ZIP**: archive is extracted into a scan workspace.
- **Paste**: code is saved to a file in a scan workspace.

The scan record is updated with `codebase_path`.

## 3. Ingestion
The codebase is chunked and indexed for analysis (vector store). Logs record file counts and chunk counts.

## 4. Discovery (candidate findings)
AutoPoV finds candidate issues by combining:
- **CodeQL** (if available)
- **Heuristic scout** (rule-based patterns)
- **LLM scout** (optional LLM analysis)

Candidates are merged and deduplicated.

## 5. Investigation (LLM validation)
Each candidate is analyzed by a routed model:
- Verdict: `REAL` or `FALSE_POSITIVE`
- Confidence score
- Explanation + vulnerable snippet
- Cost + model used

Only `REAL` findings continue to PoV generation.

## 6. PoV generation
A PoV script is generated for confirmed findings:
- Uses the routed model (OpenRouter auto by default)
- Script must print **`VULNERABILITY TRIGGERED`** when successful
- Script is designed to execute directly against the vulnerable code context

## 7. PoV validation
AutoPoV validates PoVs using a hybrid flow:
1. **Static validation** (fast)
2. **Unit-test execution** (isolated harness)
3. **LLM validation** (fallback)

If PoV does not conclusively validate, it proceeds to Docker execution.

## 8. PoV execution (proof step)
PoVs are run in an isolated Docker container:
- If output contains **`VULNERABILITY TRIGGERED`**, the vulnerability is proven.
- Results (stdout/stderr, exit code) are stored.

## 9. Results + reports saved
Results are saved to:
- `results/runs/<scan_id>.json`
- `results/<scan_id>_report.json`
- `results/<scan_id>_report.pdf`

PoV scripts are saved to:
- `results/povs/` (only for confirmed findings)

## 10. UI results
The UI displays:
- Summary metrics (total, confirmed, cost, PoV success)
- Per-finding details (explanation, vulnerable code, PoV status)
- Validation method and PoV execution output
- Reports (JSON + PDF)

---

## Key API Endpoints
- Start scan (Git): `POST /api/scan/git`
- Start scan (ZIP): `POST /api/scan/zip`
- Start scan (Paste): `POST /api/scan/paste`
- Scan status: `GET /api/scan/{scan_id}`
- Live logs (SSE): `GET /api/scan/{scan_id}/stream`
- Reports: `GET /api/report/{scan_id}?format=pdf|json`
- System config: `GET /api/config`

---

## Notes on Model Routing
Model selection is automatic by policy:
- `ROUTING_MODE=auto` uses `AUTO_ROUTER_MODEL` (OpenRouter auto)
- `ROUTING_MODE=fixed` uses `MODEL_NAME`
- `ROUTING_MODE=learning` uses the learning store if available, otherwise auto

The UI no longer asks for a model because the system already chooses the best one.

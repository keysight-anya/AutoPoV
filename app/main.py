"""
AutoPoV FastAPI Application
Main entry point for the REST API
"""

import os
import json
import asyncio
import secrets
from typing import Optional, List
from datetime import datetime
from urllib.parse import urlparse
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, UploadFile, File, Form, Header, Request
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.auth import (
    verify_api_key, verify_api_key_with_rate_limit, verify_api_key_optional,
    verify_api_key_or_system, verify_api_key_or_system_with_rate_limit,
    get_api_key_manager
)
from app.git_handler import get_git_handler
from app.source_handler import get_source_handler
from app.webhook_handler import get_webhook_handler
from app.scan_manager import get_scan_manager, ScanResult
from app.agent_graph import get_agent_graph
from app.report_generator import get_report_generator
from app.learning_store import get_learning_store


# Pydantic models for API
class ScanGitRequest(BaseModel):
    url: str
    token: Optional[str] = None
    branch: Optional[str] = None
    model: Optional[str] = Field(default=None)


class ScanPasteRequest(BaseModel):
    code: str
    language: Optional[str] = None
    filename: Optional[str] = None
    model: Optional[str] = Field(default=None)


class ReplayRequest(BaseModel):
    models: List[str]
    include_failed: bool = False
    max_findings: int = 50


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: int
    logs: List[str]
    result: Optional[dict] = None
    findings: List[dict] = []
    error: Optional[str] = None


class APIKeyResponse(BaseModel):
    key: str
    message: str


class APIKeyListResponse(BaseModel):
    keys: List[dict]


class HealthResponse(BaseModel):
    status: str
    version: str
    docker_available: bool
    codeql_available: bool
    joern_available: bool


class WebhookResponse(BaseModel):
    status: str
    message: str
    scan_id: Optional[str] = None


# Helper function to get the configured model
def get_configured_model() -> str:
    """Get the configured model name, raising an error if not explicitly set."""
    selected_model = (settings.MODEL_NAME or "").strip()
    if not selected_model:
        raise HTTPException(
            status_code=400,
            detail="No model configured. Please go to Settings > Model Config and select a model before running scans."
        )
    try:
        settings.resolve_model_mode(selected_model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return selected_model


def ensure_model_runtime_ready(model: str) -> None:
    """Validate that the selected model can actually run before creating a scan."""
    selected_model = (model or "").strip()
    if not selected_model:
        raise HTTPException(status_code=400, detail="No model configured. Select a model in Settings before running scans.")

    try:
        model_mode = settings.resolve_model_mode(selected_model)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if model_mode == "offline":
        from urllib.parse import urljoin
        import requests

        base_url = settings.get_effective_ollama_base_url().rstrip("/")
        tags_url = urljoin(base_url + "/", "api/tags")
        try:
            response = requests.get(tags_url, timeout=5)
            response.raise_for_status()
            payload = response.json() or {}
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Offline model runtime is unavailable: {exc}") from exc

        installed = {m.get("name", "").split(":", 1)[0] for m in payload.get("models", [])}
        if selected_model not in installed:
            raise HTTPException(status_code=400, detail=f"Offline model '{selected_model}' is not installed in Ollama.")
        return

    if not settings.get_openrouter_api_key():
        raise HTTPException(status_code=400, detail="OpenRouter API key is not configured for online scanning.")


# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    settings.ensure_directories()
    
    # Register webhook callback
    async def webhook_scan_callback(**kwargs):
        return await trigger_scan_from_webhook(**kwargs)
    
    get_webhook_handler().register_scan_callback(webhook_scan_callback)
    
    yield
    
    # Shutdown
    print("Shutting down...")


# Create FastAPI app
app = FastAPI(
    title=settings.APP_NAME,
    description="Autonomous Proof-of-Vulnerability Framework for LLM Benchmarking",
    version=settings.APP_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_allowed_frontend_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"]
)


# CSRF cookie helper for web UI
def _origin_matches_frontend(request: Request) -> bool:
    origin = request.headers.get("origin") or request.headers.get("referer")
    if not origin:
        return False
    parsed = urlparse(origin)
    origin_base = f"{parsed.scheme}://{parsed.netloc}"
    return origin_base in settings.get_allowed_frontend_origins()


@app.middleware("http")
async def csrf_cookie_middleware(request: Request, call_next):
    response = await call_next(request)
    if _origin_matches_frontend(request):
        if "autopov_csrf" not in request.cookies:
            token = secrets.token_urlsafe(32)
            secure = urlparse(settings.get_frontend_origin() or settings.FRONTEND_URL).scheme == "https"
            response.set_cookie(
                "autopov_csrf",
                token,
                httponly=False,
                samesite="Strict",
                secure=secure,
                path="/"
            )
    return response


async def trigger_scan_from_webhook(
    source_type: str,
    source_url: str,
    branch: Optional[str] = None,
    commit: Optional[str] = None,
    triggered_by: str = "webhook"
) -> str:
    """Trigger scan from webhook callback"""
    model = get_configured_model()
    scan_id = get_scan_manager().create_scan(
        codebase_path="",  # Will be set after clone
        model_name=model,
        cwes=[],
        triggered_by=triggered_by
    )
    
    # Clone and run scan in background
    async def run_webhook_scan():
        try:
            # Clone repository
            path, provider = get_git_handler().clone_repository(
                url=source_url,
                scan_id=scan_id,
                branch=branch,
                commit=commit
            )
            
            # Update scan with path
            scan_info = get_scan_manager().get_scan(scan_id)
            if scan_info:
                get_scan_manager().update_scan(scan_id, codebase_path=path, progress=12)
            
            # Run scan
            await get_scan_manager().run_scan_async(scan_id)
            
        except Exception as e:
            print(f"Webhook scan failed: {e}")
    
    asyncio.create_task(run_webhook_scan())
    
    return scan_id


# Health check endpoint
@app.get("/api/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        version=settings.APP_VERSION,
        docker_available=settings.is_docker_available(),
        codeql_available=settings.is_codeql_available(),
        joern_available=settings.is_joern_available()
    )


@app.get("/api/config")
async def get_config(auth: Optional[tuple] = Depends(verify_api_key_optional)):
    """Get system configuration for discovery-first scans"""
    config = {
        "app_version": settings.APP_VERSION,
        "codeql_available": settings.is_codeql_available(),
        "docker_available": settings.is_docker_available(),
        "routing_mode": "fixed",
        "model_mode": settings.resolve_model_mode(settings.MODEL_NAME) if settings.MODEL_NAME else settings.MODEL_MODE,
        "model_name": settings.MODEL_NAME,
        "token_tracking_enabled": settings.TOKEN_TRACKING_ENABLED,
        "discovery_mode": "open-ended",
        "cwe_agnostic": True
    }
    
    return config


# Scan endpoints
@app.post("/api/scan/git", response_model=ScanResponse)
async def scan_git(
    request: ScanGitRequest,
    background_tasks: BackgroundTasks,
    auth: tuple = Depends(verify_api_key_or_system_with_rate_limit)
):
    """Scan a Git repository"""
    model = request.model or get_configured_model()
    ensure_model_runtime_ready(model)
    scan_id = get_scan_manager().create_scan(
        codebase_path="",  # Will be set after clone
        model_name=model,
        cwes=[]
    )
    
    def run_scan():
        import traceback
        scan_manager = get_scan_manager()
        scan_info = scan_manager.get_scan(scan_id)
        
        try:
            # Step 1: Check repository accessibility
            if scan_info:
                scan_manager.update_scan(scan_id, status="checking", progress=2)
                scan_manager.append_log(scan_id, f"Checking repository: {request.url}")
            
            is_accessible, message, repo_info = get_git_handler().check_repo_accessibility(request.url, request.branch)
            
            if scan_info:
                scan_manager.append_log(scan_id, message)
            
            if not is_accessible:
                if scan_info:
                    scan_manager.update_scan(scan_id, status="failed", progress=100, error=message)
                print(f"Scan {scan_id} failed: {message}")
                return
            
            # Step 2: Clone repository
            if scan_info:
                scan_manager.update_scan(scan_id, status="cloning", progress=8)
                scan_manager.append_log(scan_id, f"Cloning repository: {request.url}")
                if repo_info.get("size_mb"):
                    scan_manager.append_log(scan_id, f"Repository size: {repo_info['size_mb']:.1f} MB")
            
            path, provider = get_git_handler().clone_repository(
                url=request.url,
                scan_id=scan_id,
                branch=request.branch
            )
            
            # Update scan with path
            if scan_info:
                scan_manager.update_scan(scan_id, codebase_path=path, progress=12)
                scan_manager.append_log(scan_id, f"Repository cloned to: {path}")
                scan_manager.append_log(scan_id, "Starting vulnerability scan...")
            
            # Run scan synchronously in background using asyncio.run in a new event loop
            # Create a new event loop for this thread
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                loop.run_until_complete(scan_manager.run_scan_async(scan_id))
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                finally:
                    loop.close()
            
        except Exception as e:
            error_msg = f"{str(e)}\n{traceback.format_exc()}"
            if scan_info:
                scan_manager.update_scan(scan_id, status="failed", progress=100, error=str(e))
                scan_manager.append_log(scan_id, f"ERROR: {str(e)}")
            print(f"Scan {scan_id} failed: {error_msg}")
    
    background_tasks.add_task(run_scan)
    
    return ScanResponse(
        scan_id=scan_id,
        status="created",
        message="Git repository scan initiated"
    )


@app.post("/api/scan/zip", response_model=ScanResponse)
async def scan_zip(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    model: Optional[str] = Form(None),
    auth: tuple = Depends(verify_api_key_or_system_with_rate_limit)
):
    """Scan a ZIP file upload"""
    model = model or get_configured_model()
    ensure_model_runtime_ready(model)
    scan_id = get_scan_manager().create_scan(
        codebase_path="",
        model_name=model,
        cwes=[]
    )
    
    # Read file content before passing to background task (UploadFile is not thread-safe)
    file_content = await file.read()

    def run_scan():
        try:
            # Save uploaded file
            temp_path = f"/tmp/autopov/{scan_id}/upload.zip"
            os.makedirs(os.path.dirname(temp_path), exist_ok=True)
            
            with open(temp_path, "wb") as f_out:
                f_out.write(file_content)
            
            # Extract
            path = get_source_handler().handle_zip_upload(temp_path, scan_id)
            
            # Update scan
            scan_info = get_scan_manager().get_scan(scan_id)
            if scan_info:
                get_scan_manager().update_scan(scan_id, codebase_path=path, progress=12)
            
            # Run scan using a new event loop (same pattern as scan_git)
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                loop.run_until_complete(get_scan_manager().run_scan_async(scan_id))
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                finally:
                    loop.close()
            
        except Exception as e:
            scan_info = get_scan_manager().get_scan(scan_id)
            if scan_info:
                get_scan_manager().update_scan(scan_id, status="failed", progress=100, error=str(e))
    
    background_tasks.add_task(run_scan)
    
    return ScanResponse(
        scan_id=scan_id,
        status="created",
        message="ZIP file scan initiated"
    )


@app.post("/api/scan/paste", response_model=ScanResponse)
async def scan_paste(
    request: ScanPasteRequest,
    background_tasks: BackgroundTasks,
    auth: tuple = Depends(verify_api_key_or_system_with_rate_limit)
):
    """Scan pasted code"""
    model = request.model or get_configured_model()
    ensure_model_runtime_ready(model)
    scan_id = get_scan_manager().create_scan(
        codebase_path="",
        model_name=model,
        cwes=[]
    )
    
    def run_scan():
        try:
            # Save code to file
            path = get_source_handler().handle_raw_code(
                code=request.code,
                scan_id=scan_id,
                language=request.language,
                filename=request.filename
            )
            
            # Update scan
            scan_info = get_scan_manager().get_scan(scan_id)
            scan_info["codebase_path"] = path
            
            # Run scan using a new event loop (same pattern as scan_git)
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                loop.run_until_complete(get_scan_manager().run_scan_async(scan_id))
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                finally:
                    loop.close()
            
        except Exception as e:
            scan_info = get_scan_manager().get_scan(scan_id)
            if scan_info:
                get_scan_manager().update_scan(scan_id, status="failed", progress=100, error=str(e))
    
    background_tasks.add_task(run_scan)
    
    return ScanResponse(
        scan_id=scan_id,
        status="created",
        message="Code paste scan initiated"
    )



@app.post("/api/scan/{scan_id}/replay")
async def replay_scan(
    scan_id: str,
    request: ReplayRequest,
    background_tasks: BackgroundTasks,
    auth: tuple = Depends(verify_api_key_or_system_with_rate_limit)
):
    result = get_scan_manager().get_scan_result(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")

    if not request.models:
        raise HTTPException(status_code=400, detail="No models provided")

    findings = result.findings or []
    if not request.include_failed:
        findings = [f for f in findings if f.get("final_status") == "confirmed"]

    findings = findings[: request.max_findings]
    if not findings:
        raise HTTPException(status_code=400, detail="No findings available for replay")

    codebase_path = result.codebase_path
    if not codebase_path or not os.path.exists(codebase_path):
        snapshot_path = os.path.join(settings.SNAPSHOT_DIR, scan_id)
        if os.path.exists(snapshot_path):
            codebase_path = snapshot_path
        else:
            raise HTTPException(status_code=400, detail="Codebase path is not available for replay")

    replay_findings = []
    for f in findings:
        replay_findings.append({
            "cwe_type": f.get("cwe_type", ""),
            "filepath": f.get("filepath", ""),
            "line_number": f.get("line_number", 0),
            "code_chunk": f.get("code_chunk", ""),
            "llm_verdict": "",
            "llm_explanation": "",
            "confidence": f.get("confidence", 0.5),
            "pov_script": None,
            "pov_path": None,
            "pov_result": None,
            "retry_count": 0,
            "inference_time_s": 0.0,
            "cost_usd": 0.0,
            "final_status": "",
            "alert_message": "replay",
            "source": "replay",
            "language": f.get("language", "unknown")
        })

    detected_language = get_agent_graph()._detect_language(codebase_path)

    # Use the currently configured model for replay
    configured_model = get_configured_model()
    
    replay_ids = []
    # Create one replay scan with the configured model
    replay_id = get_scan_manager().create_scan(
        codebase_path=codebase_path,
        model_name=configured_model,
        cwes=result.cwes
    )
    scan_info = get_scan_manager().get_scan(replay_id)
    if scan_info:
        scan_info["triggered_by"] = "replay"
        scan_info["replay_of"] = scan_id

        def run_replay(replay_id=replay_id):
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                loop.run_until_complete(
                    get_scan_manager().run_scan_with_findings_async(
                        replay_id,
                        replay_findings,
                        detected_language=detected_language
                    )
                )
            finally:
                try:
                    loop.run_until_complete(loop.shutdown_asyncgens())
                finally:
                    loop.close()

        background_tasks.add_task(run_replay)
        replay_ids.append(replay_id)

    return {"status": "replay_started", "replay_ids": replay_ids}

@app.post("/api/scan/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Cancel a running scan"""
    success, message = get_scan_manager().cancel_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404 if "not found" in message else 409, detail=message)
    return {"scan_id": scan_id, "status": "cancelled", "message": message}


@app.post("/api/scan/{scan_id}/stop")
async def stop_scan(
    scan_id: str,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Force stop a running scan immediately"""
    success, message = get_scan_manager().stop_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404 if "not found" in message else 409, detail=message)
    return {"scan_id": scan_id, "status": "stopped", "message": message}


@app.delete("/api/scan/{scan_id}")
async def delete_scan(
    scan_id: str,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Delete a scan and all its associated data"""
    success, message = get_scan_manager().delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404 if "not found" in message else 409, detail=message)
    return {"scan_id": scan_id, "status": "deleted", "message": message}


@app.get("/api/scans/active")
async def get_active_scans(auth: tuple = Depends(verify_api_key_or_system)):
    """Get list of all active/in-progress scans"""
    active_scans = get_scan_manager().get_active_scans()
    return {"active_scans": active_scans, "count": len(active_scans)}


@app.post("/api/scans/cleanup")
async def cleanup_stuck_scans(auth: tuple = Depends(verify_api_key_or_system)):
    """Clean up stuck/interrupted scans by deleting them"""
    scan_manager = get_scan_manager()
    deleted = []
    failed = []
    
    # Get all scans including stuck ones from active_scans
    all_scan_ids = list(scan_manager._active_scans.keys())
    
    for scan_id in all_scan_ids:
        scan_info = scan_manager._active_scans.get(scan_id)
        if not scan_info:
            continue
        
        status = scan_info.get("status", "unknown")
        # Clean up stuck/interrupted scans
        if status in {"interrupted", "stopped"}:
            success, message = scan_manager.delete_scan(scan_id)
            if success:
                deleted.append(scan_id)
            else:
                failed.append({"scan_id": scan_id, "error": message})
    
    # Also check for stuck scans in results folder (scans with status like investigating, running, etc. but not in active_scans)
    import os
    import json
    runs_dir = scan_manager._runs_dir
    stuck_statuses = {"investigating", "running", "generating_pov", "validating_pov", "running_pov", "checking", "cloning", "created", "ingesting"}
    
    try:
        for fname in os.listdir(runs_dir):
            if not fname.endswith(".json") or fname == "scan_history.csv":
                continue
            scan_id = fname[:-5]  # Remove .json
            if scan_id in deleted:
                continue  # Already deleted
            
            try:
                fpath = os.path.join(runs_dir, fname)
                with open(fpath, 'r') as f:
                    data = json.load(f)
                
                status = data.get("status", "")
                if status in stuck_statuses:
                    # Delete this stuck scan
                    try:
                        os.remove(fpath)
                        deleted.append(scan_id)
                    except Exception as e:
                        failed.append({"scan_id": scan_id, "error": str(e)})
            except Exception:
                continue  # Skip files that can't be read
    except Exception:
        pass  # Ignore errors reading runs_dir
    
    return {
        "deleted": deleted,
        "failed": failed,
        "count": len(deleted),
        "message": f"Cleaned up {len(deleted)} stuck scans"
    }


@app.get("/api/cache/stats")
async def get_cache_stats(auth: tuple = Depends(verify_api_key_or_system)):
    """Get cache statistics"""
    from app.analysis_cache import get_analysis_cache
    cache = get_analysis_cache()
    return cache.get_stats()


@app.post("/api/cache/clear")
async def clear_cache(auth: tuple = Depends(verify_api_key_or_system)):
    """Clear all cache entries"""
    from app.analysis_cache import get_analysis_cache
    cache = get_analysis_cache()
    prompts_cleared, results_cleared = cache.clear_all()
    return {
        "prompts_cleared": prompts_cleared,
        "results_cleared": results_cleared,
        "message": f"Cleared {prompts_cleared} prompt cache entries and {results_cleared} result cache entries"
    }


# Scan status and results
@app.get("/api/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Get scan status and results"""
    scan_manager = get_scan_manager()
    scan_info = scan_manager.get_scan(scan_id)

    if scan_info and scan_info.get("status") in {"completed", "failed", "cancelled", "stopped"}:
        result = scan_manager.get_scan_result(scan_id)
        if result:
            return ScanStatusResponse(
                scan_id=scan_id,
                status=result.status,
                progress=100,
                logs=result.logs if hasattr(result, 'logs') else [],
                result=result.__dict__
            )
        fallback_result = scan_info.get("result")
        if isinstance(fallback_result, dict):
            return ScanStatusResponse(
                scan_id=scan_id,
                status=fallback_result.get("status", scan_info.get("status", "unknown")),
                progress=100,
                logs=fallback_result.get("logs") or scan_info.get("logs", []),
                result=fallback_result,
                findings=fallback_result.get("findings") or scan_info.get("findings", []),
                error=scan_info.get("error")
            )

    if not scan_info:
        # Try to load from saved results
        result = scan_manager.get_scan_result(scan_id)
        if result:
            return ScanStatusResponse(
                scan_id=scan_id,
                status=result.status,
                progress=100,
                logs=result.logs if hasattr(result, 'logs') else [],
                result=result.__dict__
            )
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Get findings from scan info if available
    findings = []
    if scan_info.get("findings"):
        findings = [f.__dict__ if hasattr(f, '__dict__') else f for f in scan_info.get("findings", [])]
    
    return ScanStatusResponse(
        scan_id=scan_id,
        status=scan_info.get("status", "unknown"),
        progress=scan_info.get("progress", 0),
        logs=scan_info.get("logs", []),
        result=scan_info.get("result").__dict__ if scan_info.get("result") else None,
        findings=findings,
        error=scan_info.get("error")
    )


@app.get("/api/scan/{scan_id}/artifacts/{finding_index}")
async def list_finding_artifacts(
    scan_id: str,
    finding_index: int,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """List saved proof artifact files for a specific finding."""
    scan_manager = get_scan_manager()
    files = scan_manager.list_proof_artifacts(scan_id, finding_index)
    artifact_dir = scan_manager.get_proof_artifact_dir(scan_id, finding_index)
    if not files or not artifact_dir:
        raise HTTPException(status_code=404, detail="Proof artifacts not found for this finding")
    return {
        "scan_id": scan_id,
        "finding_index": finding_index,
        "artifact_dir": artifact_dir,
        "files": files,
    }


@app.get("/api/scan/{scan_id}/artifacts/{finding_index}/file")
async def get_finding_artifact_file(
    scan_id: str,
    finding_index: int,
    name: str,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Read a saved proof artifact file for a specific finding."""
    artifact = get_scan_manager().read_proof_artifact(scan_id, finding_index, name)
    if not artifact:
        raise HTTPException(status_code=404, detail="Artifact file not found")
    return artifact


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan_logs(
    scan_id: str,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Stream scan logs via SSE"""
    async def event_generator():
        last_log_count = 0
        
        while True:
            scan_manager = get_scan_manager()
            scan_info = scan_manager.get_scan(scan_id)
            
            if not scan_info:
                result = scan_manager.get_scan_result(scan_id)
                if result:
                    yield f"data: {json.dumps({'type': 'complete', 'result': result.__dict__})}\n\n"
                    break
                yield f"data: {json.dumps({'type': 'error', 'message': 'Scan not found'})}\n\n"
                break
            
            logs = scan_info.get("logs", [])
            
            # Send new logs
            for log in logs[last_log_count:]:
                yield f"data: {json.dumps({'type': 'log', 'message': log})}\n\n"
            
            last_log_count = len(logs)
            
            # Check if scan is complete
            if scan_info.get("status") in ["completed", "failed", "cancelled"]:
                result = scan_info.get("result")
                yield f"data: {json.dumps({'type': 'complete', 'result': result.__dict__ if result else None})}\n\n"
                break
            
            await asyncio.sleep(1)
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream"
    )


# History endpoint
@app.get("/api/history")
async def get_history(
    limit: int = 100,
    offset: int = 0,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Get scan history"""
    history = get_scan_manager().get_scan_history(limit=limit, offset=offset)
    return {"history": history}


# Report endpoints
@app.get("/api/report/{scan_id}")
async def get_report(
    scan_id: str,
    format: str = "json",
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Get scan report"""
    result = get_scan_manager().get_scan_result(scan_id)
    
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    
    try:
        if format == "json":
            report_path = get_report_generator().generate_json_report(result)
            return FileResponse(
                report_path,
                media_type="application/json",
                filename=f"{scan_id}_report.json",
                headers={
                    "Access-Control-Expose-Headers": "Content-Disposition, Content-Type",
                    "Content-Disposition": f"attachment; filename={scan_id}_report.json",
                    "Content-Type": "application/json"
                }
            )
        
        elif format == "pdf":
            report_path = get_report_generator().generate_pdf_report(result)
            return FileResponse(
                report_path,
                media_type="application/pdf",
                filename=f"{scan_id}_report.pdf",
                headers={
                    "Access-Control-Expose-Headers": "Content-Disposition, Content-Type",
                    "Content-Disposition": f"attachment; filename={scan_id}_report.pdf",
                    "Content-Type": "application/pdf"
                }
            )
        
        else:
            raise HTTPException(status_code=400, detail="Invalid format. Use 'json' or 'pdf'")
    except Exception as e:
        import traceback
        print(f"[Report Error] {str(e)}\n{traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")


# Webhook endpoints
@app.post("/api/webhook/github", response_model=WebhookResponse)
async def github_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None)
):
    """GitHub webhook endpoint"""
    body = await request.body()
    
    result = await get_webhook_handler().handle_github_webhook(
        signature=x_hub_signature_256 or "",
        event_type=x_github_event or "",
        payload=body
    )
    
    return WebhookResponse(
        status=result.get("status", "error"),
        message=result.get("message", ""),
        scan_id=result.get("scan_id")
    )


@app.post("/api/webhook/gitlab", response_model=WebhookResponse)
async def gitlab_webhook(
    request: Request,
    x_gitlab_token: Optional[str] = Header(None),
    x_gitlab_event: Optional[str] = Header(None)
):
    """GitLab webhook endpoint"""
    body = await request.body()
    
    result = await get_webhook_handler().handle_gitlab_webhook(
        token=x_gitlab_token or "",
        event_type=x_gitlab_event or "",
        payload=body
    )
    
    return WebhookResponse(
        status=result.get("status", "error"),
        message=result.get("message", ""),
        scan_id=result.get("scan_id")
    )


# API Key management
@app.post("/api/keys/generate", response_model=APIKeyResponse)
async def generate_api_key(name: str = "default", auth: tuple = Depends(verify_api_key_or_system)):
    """Generate new API key (public endpoint)"""
    key = get_api_key_manager().generate_key(name)
    return APIKeyResponse(
        key=key,
        message="API key generated successfully. Save this key - it won't be shown again."
    )


@app.get("/api/keys", response_model=APIKeyListResponse)
async def list_api_keys(auth: tuple = Depends(verify_api_key_or_system)):
    """List API keys (public endpoint - returns key names only, not full keys)"""
    keys = get_api_key_manager().list_keys()
    return APIKeyListResponse(keys=keys)


@app.delete("/api/keys/{key_id}")
async def revoke_api_key(key_id: str, auth: tuple = Depends(verify_api_key_or_system)):
    """Revoke an API key (public endpoint)"""
    success = get_api_key_manager().revoke_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"message": "API key revoked"}


@app.post("/api/admin/cleanup")
async def cleanup_results(
    max_age_days: int = 30,
    max_results: int = 500,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Clean up old scan result files (public endpoint)"""
    files_removed, bytes_freed = get_scan_manager().cleanup_old_results(
        max_age_days=max_age_days,
        max_results=max_results
    )
    return {
        "files_removed": files_removed,
        "bytes_freed": bytes_freed,
        "message": f"Removed {files_removed} files, freed {bytes_freed / 1024:.1f} KB"
    }



@app.get("/api/learning/summary")
async def learning_summary(auth: Optional[tuple] = Depends(verify_api_key_optional)):
    store = get_learning_store()
    return {
        "summary": store.get_summary(),
        "models": store.get_model_stats()
    }

# Metrics endpoint
@app.get("/api/metrics")
async def get_metrics(auth: tuple = Depends(verify_api_key_or_system)):
    """Get system metrics"""
    return get_scan_manager().get_metrics()


# Settings endpoints
@app.get("/api/settings")
async def get_settings(auth: tuple = Depends(verify_api_key_or_system)):
    """Get current system settings (excluding sensitive values)"""
    # Determine current model mode and selected model
    selected_model = settings.MODEL_NAME
    model_mode = settings.resolve_model_mode(selected_model) if selected_model else settings.MODEL_MODE
    
    return {
        # OpenRouter configuration
        "openrouter_key_from_env": settings.is_openrouter_key_from_env(),
        "openrouter_key_configured": bool(settings.get_openrouter_api_key()),
        
        # Simplified model selection
        "model_mode": model_mode,
        "selected_model": selected_model,
        
        "routing_mode": "fixed",
        "available_online_models": settings.ONLINE_MODELS,
        "available_offline_models": settings.OFFLINE_MODELS,
    }


@app.post("/api/settings")
async def update_settings(
    request: dict,
    auth: tuple = Depends(verify_api_key_or_system)
):
    """Update system settings"""
    # Update OpenRouter API key (UI-configured only if env var not set)
    if "openrouter_api_key" in request and not settings.is_openrouter_key_from_env():
        settings.OPENROUTER_API_KEY_UI = request["openrouter_api_key"]
    
    # Update simplified model selection
    if "selected_model" in request:
        selected = (request["selected_model"] or "").strip()
        if not selected:
            raise HTTPException(status_code=400, detail="An explicit model selection is required")
        try:
            resolved_mode = settings.resolve_model_mode(selected)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        requested_mode = request.get("model_mode")
        if requested_mode and requested_mode != resolved_mode:
            raise HTTPException(status_code=400, detail=f"Model '{selected}' must use '{resolved_mode}' mode.")
        settings.MODEL_NAME = selected
        settings.MODEL_MODE = resolved_mode
        settings.ROUTING_MODE = "fixed"
    elif "model_mode" in request:
        requested_mode = request["model_mode"]
        if requested_mode not in {"online", "offline"}:
            raise HTTPException(status_code=400, detail="model_mode must be 'online' or 'offline'")
        settings.MODEL_MODE = requested_mode
    
    return {"status": "updated"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )

"""
AutoPoV FastAPI Application
Main entry point for the REST API
"""

import os
import json
import asyncio
from typing import Optional, List
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, UploadFile, File, Form, Header, Request
from fastapi.security import HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field

from app.config import settings
from app.auth import verify_api_key, verify_admin_key, get_api_key_manager
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
    model: str = Field(default="openai/gpt-4o")
    cwes: List[str] = Field(default=["CWE-89", "CWE-119", "CWE-190", "CWE-416"])


class ScanPasteRequest(BaseModel):
    code: str
    language: Optional[str] = None
    filename: Optional[str] = None
    model: str = Field(default="openai/gpt-4o")
    cwes: List[str] = Field(default=["CWE-89", "CWE-119", "CWE-190", "CWE-416"])



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
    allow_origins=[settings.FRONTEND_URL, "http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://localhost:5175"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


async def trigger_scan_from_webhook(
    source_type: str,
    source_url: str,
    branch: Optional[str] = None,
    commit: Optional[str] = None,
    triggered_by: str = "webhook"
) -> str:
    """Trigger scan from webhook callback"""
    scan_id = get_scan_manager().create_scan(
        codebase_path="",  # Will be set after clone
        model_name=settings.MODEL_NAME if settings.ROUTING_MODE == "fixed" else settings.AUTO_ROUTER_MODEL,
        cwes=settings.SUPPORTED_CWES,
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
            scan_info["codebase_path"] = path
            
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
async def get_config(api_key: str = Depends(verify_api_key)):
    """Get system configuration including supported CWEs"""
    return {
        "supported_cwes": settings.SUPPORTED_CWES,
        "app_version": settings.APP_VERSION,
        "codeql_available": settings.is_codeql_available(),
        "docker_available": settings.is_docker_available(),
        "routing_mode": settings.ROUTING_MODE,
        "auto_router_model": settings.AUTO_ROUTER_MODEL,
        "model_mode": settings.MODEL_MODE,
        "model_name": settings.MODEL_NAME
    }


# Scan endpoints
@app.post("/api/scan/git", response_model=ScanResponse)
async def scan_git(
    request: ScanGitRequest,
    background_tasks: BackgroundTasks,
    api_key: str = Depends(verify_api_key)
):
    """Scan a Git repository"""
    scan_id = get_scan_manager().create_scan(
        codebase_path="",  # Will be set after clone
        model_name=settings.MODEL_NAME if settings.ROUTING_MODE == "fixed" else settings.AUTO_ROUTER_MODEL,
        cwes=request.cwes
    )
    
    def run_scan():
        import traceback
        scan_manager = get_scan_manager()
        scan_info = scan_manager.get_scan(scan_id)
        
        try:
            # Step 1: Check repository accessibility
            if scan_info:
                scan_info["status"] = "checking"
                scan_manager.append_log(scan_id, f"Checking repository: {request.url}")
            
            is_accessible, message, repo_info = get_git_handler().check_repo_accessibility(request.url, request.branch)
            
            if scan_info:
                scan_manager.append_log(scan_id, message)
            
            if not is_accessible:
                if scan_info:
                    scan_info["status"] = "failed"
                    scan_info["error"] = message
                print(f"Scan {scan_id} failed: {message}")
                return
            
            # Step 2: Clone repository
            if scan_info:
                scan_info["status"] = "cloning"
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
                scan_info["codebase_path"] = path
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
                scan_info["status"] = "failed"
                scan_info["error"] = str(e)
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
    model: str = Form("openai/gpt-4o"),
    cwes: str = Form("CWE-89,CWE-119,CWE-190,CWE-416"),
    api_key: str = Depends(verify_api_key)
):
    """Scan a ZIP file upload"""
    cwe_list = cwes.split(",")
    
    scan_id = get_scan_manager().create_scan(
        codebase_path="",
        model_name=settings.MODEL_NAME if settings.ROUTING_MODE == "fixed" else settings.AUTO_ROUTER_MODEL,
        cwes=cwe_list
    )
    
    def run_scan():
        try:
            # Save uploaded file
            temp_path = f"/tmp/autopov/{scan_id}/upload.zip"
            os.makedirs(os.path.dirname(temp_path), exist_ok=True)
            
            with open(temp_path, "wb") as f:
                content = file.file.read()
                f.write(content)
            
            # Extract
            path = get_source_handler().handle_zip_upload(temp_path, scan_id)
            
            # Update scan
            scan_info = get_scan_manager().get_scan(scan_id)
            scan_info["codebase_path"] = path
            
            # Run scan
            asyncio.run(get_scan_manager().run_scan_async(scan_id))
            
        except Exception as e:
            scan_info = get_scan_manager().get_scan(scan_id)
            if scan_info:
                scan_info["status"] = "failed"
                scan_info["error"] = str(e)
    
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
    api_key: str = Depends(verify_api_key)
):
    """Scan pasted code"""
    scan_id = get_scan_manager().create_scan(
        codebase_path="",
        model_name=settings.MODEL_NAME if settings.ROUTING_MODE == "fixed" else settings.AUTO_ROUTER_MODEL,
        cwes=request.cwes
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
            
            # Run scan
            asyncio.run(get_scan_manager().run_scan_async(scan_id))
            
        except Exception as e:
            scan_info = get_scan_manager().get_scan(scan_id)
            if scan_info:
                scan_info["status"] = "failed"
                scan_info["error"] = str(e)
    
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
    api_key: str = Depends(verify_api_key)
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
            "final_status": "pending",
            "alert_message": "replay",
            "source": "replay",
            "language": f.get("language", "unknown")
        })

    detected_language = get_agent_graph()._detect_language(codebase_path)

    replay_ids = []
    for model in request.models:
        replay_id = get_scan_manager().create_scan(
            codebase_path=codebase_path,
            model_name=settings.MODEL_NAME if settings.ROUTING_MODE == "fixed" else settings.AUTO_ROUTER_MODEL,
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

# Scan status and results
@app.get("/api/scan/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Get scan status and results"""
    scan_info = get_scan_manager().get_scan(scan_id)
    
    if not scan_info:
        # Try to load from saved results
        result = get_scan_manager().get_scan_result(scan_id)
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


@app.get("/api/scan/{scan_id}/stream")
async def stream_scan_logs(
    scan_id: str,
    api_key: str = Depends(verify_api_key)
):
    """Stream scan logs via SSE"""
    async def event_generator():
        last_log_count = 0
        
        while True:
            scan_info = get_scan_manager().get_scan(scan_id)
            
            if not scan_info:
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
    api_key: str = Depends(verify_api_key)
):
    """Get scan history"""
    history = get_scan_manager().get_scan_history(limit=limit, offset=offset)
    return {"history": history}


# Report endpoints
@app.get("/api/report/{scan_id}")
async def get_report(
    scan_id: str,
    format: str = "json",
    api_key: str = Depends(verify_api_key)
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


# API Key management (admin only)
@app.post("/api/keys/generate", response_model=APIKeyResponse)
async def generate_api_key(
    name: str = "default",
    admin_key: str = Depends(verify_admin_key)
):
    """Generate new API key (admin only)"""
    key = get_api_key_manager().generate_key(name)
    return APIKeyResponse(
        key=key,
        message="API key generated successfully. Save this key - it won't be shown again."
    )


@app.get("/api/keys", response_model=APIKeyListResponse)
async def list_api_keys(
    admin_key: str = Depends(verify_admin_key)
):
    """List API keys (admin only)"""
    keys = get_api_key_manager().list_keys()
    return APIKeyListResponse(keys=keys)


@app.delete("/api/keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    admin_key: str = Depends(verify_admin_key)
):
    """Revoke an API key (admin only)"""
    success = get_api_key_manager().revoke_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    return {"message": "API key revoked"}



@app.get("/api/learning/summary")
async def learning_summary(api_key: str = Depends(verify_api_key)):
    store = get_learning_store()
    return {
        "summary": store.get_summary(),
        "models": store.get_model_stats()
    }

# Metrics endpoint
@app.get("/api/metrics")
async def get_metrics(api_key: str = Depends(verify_api_key)):
    """Get system metrics"""
    return get_scan_manager().get_metrics()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG
    )

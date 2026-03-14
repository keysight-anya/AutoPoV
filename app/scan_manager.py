"""
AutoPoV Scan Manager Module
Manages scan lifecycle, state, and background execution
"""

import os
import json
import csv
import uuid
import threading
import shutil
from typing import Dict, Any, List, Optional, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import asyncio
from concurrent.futures import ThreadPoolExecutor

from app.config import settings
from app.agent_graph import get_agent_graph, ScanState
from agents.ingest_codebase import get_code_ingester


@dataclass
class ScanResult:
    """Scan result data class"""
    scan_id: str
    status: str
    codebase_path: str
    model_name: str
    cwes: List[str]
    total_findings: int
    confirmed_vulns: int
    false_positives: int
    failed: int
    total_cost_usd: float
    duration_s: float
    start_time: str
    end_time: Optional[str]
    findings: List[Dict[str, Any]]
    detected_language: Optional[str] = None
    language_info: Optional[Dict[str, Any]] = None
    logs: List[str] = None
    
    def __post_init__(self):
        if self.logs is None:
            self.logs = []


class ScanManager:
    """Manages vulnerability scans"""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        """Singleton pattern to ensure single instance across threads"""
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self._active_scans: Dict[str, Dict[str, Any]] = {}
        self._scan_callbacks: Dict[str, List[Callable]] = {}
        self._executor = ThreadPoolExecutor(max_workers=3)
        self._runs_dir = settings.RUNS_DIR
        self._active_runs_dir = settings.ACTIVE_RUNS_DIR
        self._scan_locks: Dict[str, threading.Lock] = {}
        os.makedirs(self._runs_dir, exist_ok=True)
        os.makedirs(self._active_runs_dir, exist_ok=True)
        self._load_active_scan_snapshots()
    
    def create_scan(
        self,
        codebase_path: str,
        model_name: str,
        cwes: List[str],
        triggered_by: Optional[str] = None,
        lite: bool = False
    ) -> str:
        """
        Create a new scan
        
        Args:
            codebase_path: Path to codebase
            model_name: Model to use
            cwes: CWEs to check
            triggered_by: Who/what triggered the scan
            lite: Whether to run in lite mode (static analysis only)
        
        Returns:
            Scan ID
        """
        scan_id = str(uuid.uuid4())
        
        self._active_scans[scan_id] = {
            "scan_id": scan_id,
            "status": "created",
            "codebase_path": codebase_path,
            "model_name": model_name,
            "cwes": cwes,
            "triggered_by": triggered_by,
            "lite": lite,
            "created_at": datetime.utcnow().isoformat(),
            "logs": [],
            "progress": 0,
            "result": None
        }
        
        # Create a lock for this scan to ensure thread-safe log updates
        self._scan_locks[scan_id] = threading.Lock()
        self._persist_active_scan(scan_id)
        
        return scan_id
    

    def _active_scan_path(self, scan_id: str) -> str:
        return os.path.join(self._active_runs_dir, f"{scan_id}.json")

    def _serialize_scan_info(self, scan_info: Dict[str, Any]) -> Dict[str, Any]:
        data = dict(scan_info)
        result = data.get("result")
        if isinstance(result, ScanResult):
            data["result"] = asdict(result)
        findings = data.get("findings")
        if findings is not None:
            serialized = []
            for finding in findings:
                serialized.append(dict(finding) if isinstance(finding, dict) else finding.__dict__)
            data["findings"] = serialized
        return data

    def _persist_active_scan(self, scan_id: str):
        scan_info = self._active_scans.get(scan_id)
        if not scan_info:
            return
        try:
            with open(self._active_scan_path(scan_id), 'w') as f:
                json.dump(self._serialize_scan_info(scan_info), f, indent=2, default=str)
        except Exception as e:
            print(f"[ScanManager] Failed to persist active scan {scan_id}: {e}")

    def _remove_active_snapshot(self, scan_id: str):
        try:
            path = self._active_scan_path(scan_id)
            if os.path.exists(path):
                os.remove(path)
        except Exception as e:
            print(f"[ScanManager] Failed to remove active scan snapshot {scan_id}: {e}")

    def _load_active_scan_snapshots(self):
        if not os.path.exists(self._active_runs_dir):
            return
        for fname in os.listdir(self._active_runs_dir):
            if not fname.endswith('.json'):
                continue
            fpath = os.path.join(self._active_runs_dir, fname)
            try:
                with open(fpath, 'r') as f:
                    data = json.load(f)
                scan_id = data.get('scan_id')
                if not scan_id:
                    continue
                status = data.get('status', 'unknown')
                if status in {'running', 'checking', 'cloning', 'created', 'ingesting', 'investigating', 'generating_pov', 'validating_pov', 'running_pov'}:
                    data['status'] = 'interrupted'
                    logs = data.setdefault('logs', [])
                    logs.append(f"[{datetime.utcnow().isoformat()}] Backend restart detected while scan was in progress. Scan state restored as interrupted.")
                self._active_scans[scan_id] = data
                self._scan_locks[scan_id] = threading.Lock()
            except Exception as e:
                print(f"[ScanManager] Failed to load active scan snapshot {fpath}: {e}")

    def update_scan(self, scan_id: str, **updates) -> bool:
        scan_info = self._active_scans.get(scan_id)
        if not scan_info:
            return False
        lock = self._scan_locks.get(scan_id)
        if lock:
            with lock:
                scan_info.update(updates)
        else:
            scan_info.update(updates)
        self._persist_active_scan(scan_id)
        return True

    async def run_scan_with_findings_async(
        self,
        scan_id: str,
        findings: List[Dict[str, Any]],
        detected_language: Optional[str] = None
    ) -> ScanResult:
        """Run a replay scan using preloaded findings."""
        if scan_id not in self._active_scans:
            raise ValueError(f"Scan {scan_id} not found")

        scan_info = self._active_scans[scan_id]
        self.update_scan(scan_id, status="running", progress=5)

        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            self._executor,
            self._run_replay_sync,
            scan_id,
            findings,
            detected_language
        )

        return result

    def _run_replay_sync(
        self,
        scan_id: str,
        findings: List[Dict[str, Any]],
        detected_language: Optional[str] = None
    ) -> ScanResult:
        scan_info = self._active_scans[scan_id]

        try:
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Starting replay scan...")
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Model: {scan_info['model_name']}")
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Replay findings: {len(findings)}")

            agent = get_agent_graph()
            final_state = agent.run_scan(
                codebase_path=scan_info["codebase_path"],
                model_name=scan_info["model_name"],
                cwes=scan_info["cwes"],
                scan_id=scan_id,
                preloaded_findings=findings,
                detected_language=detected_language
            )

            if final_state.get("logs"):
                existing_logs = set(scan_info["logs"])
                for log in final_state["logs"]:
                    if log not in existing_logs:
                        scan_info["logs"].append(log)

            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Replay completed with status: {final_state['status']}")

            confirmed = sum(1 for f in final_state["findings"] if f["final_status"] == "confirmed")
            skipped = sum(1 for f in final_state["findings"] if f["final_status"] == "skipped")
            failed = sum(1 for f in final_state["findings"] if f["final_status"] == "failed")

            start = datetime.fromisoformat(final_state["start_time"])
            end = datetime.fromisoformat(final_state["end_time"]) if final_state["end_time"] else datetime.utcnow()
            duration = (end - start).total_seconds()

            result = ScanResult(
                scan_id=scan_id,
                status=final_state["status"],
                codebase_path=scan_info["codebase_path"],
                model_name=scan_info["model_name"],
                cwes=scan_info["cwes"],
                total_findings=len(final_state["findings"]),
                confirmed_vulns=confirmed,
                false_positives=skipped,
                failed=failed,
                total_cost_usd=final_state["total_cost_usd"],
                duration_s=duration,
                start_time=final_state["start_time"],
                end_time=final_state["end_time"],
                findings=[dict(f) for f in final_state["findings"]],
                detected_language=scan_info.get("detected_language"),
                language_info=scan_info.get("language_info"),
                logs=scan_info.get("logs", [])
            )

            self._save_result(result)
            self.update_scan(
                scan_id,
                status="completed",
                progress=100,
                result=result,
                findings=[dict(f) for f in final_state["findings"]]
            )
            self._remove_active_snapshot(scan_id)

            get_code_ingester().cleanup(scan_id)

            return result

        except Exception as e:
            import traceback
            error_msg = f"{str(e)}\n{traceback.format_exc()}"
            scan_info["status"] = "failed"
            scan_info["error"] = error_msg
            scan_info["logs"].append(f"ERROR: {str(e)}")
            self._persist_active_scan(scan_id)
            print(f"Replay {scan_id} failed: {error_msg}")

            result = ScanResult(
                scan_id=scan_id,
                status="failed",
                codebase_path=scan_info["codebase_path"],
                model_name=scan_info["model_name"],
                cwes=scan_info["cwes"],
                total_findings=0,
                confirmed_vulns=0,
                false_positives=0,
                failed=0,
                total_cost_usd=0.0,
                duration_s=0.0,
                start_time=scan_info["created_at"],
                end_time=datetime.utcnow().isoformat(),
                findings=[],
                detected_language=scan_info.get("detected_language"),
                language_info=scan_info.get("language_info")
            )

            self._save_result(result)
            self.update_scan(scan_id, status="failed", progress=100, result=result)
            self._remove_active_snapshot(scan_id)
            return result

    async def run_scan_async(
        self,
        scan_id: str,
        progress_callback: Optional[Callable] = None
    ) -> ScanResult:
        """
        Run a scan asynchronously
        
        Args:
            scan_id: Scan ID
            progress_callback: Optional callback for progress updates
        
        Returns:
            Scan result
        """
        if scan_id not in self._active_scans:
            raise ValueError(f"Scan {scan_id} not found")
        
        scan_info = self._active_scans[scan_id]
        self.update_scan(scan_id, status="running", progress=10)
        
        # Run scan in thread pool
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            self._executor,
            self._run_scan_sync,
            scan_id,
            progress_callback
        )
        
        return result
    
    def _run_scan_sync(
        self,
        scan_id: str,
        progress_callback: Optional[Callable] = None
    ) -> ScanResult:
        """Run scan synchronously (for thread pool)"""
        scan_info = self._active_scans[scan_id]
        
        try:
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Starting vulnerability scan...")
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Model: {scan_info['model_name']}")
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Discovery mode: open-ended vulnerability discovery")
            
            # Get agent graph
            agent = get_agent_graph()
            
            # Set scan manager reference for cancellation checks
            agent.set_scan_manager(self)
            
            # Detect all languages in the codebase
            lang_info = agent._detect_all_languages(scan_info["codebase_path"])
            detected_language = lang_info['primary']
            
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Detected primary language: {detected_language}")
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] All languages found: {', '.join(lang_info['all_languages'])}")
            for lang, count in sorted(lang_info['language_stats'].items(), key=lambda x: x[1], reverse=True):
                pct = (count / lang_info['total_files']) * 100 if lang_info['total_files'] > 0 else 0
                scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}]   - {lang}: {count} files ({pct:.1f}%)")
            
            # Store language info in scan state
            scan_info["detected_language"] = detected_language
            scan_info["language_info"] = lang_info
            scan_info["progress"] = 20
            self._persist_active_scan(scan_id)
            
            # Check for cancellation before starting scan
            if scan_info.get("status") == "cancelled":
                scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Scan cancelled before execution")
                raise InterruptedError("Scan cancelled by user")
            
            # Run the scan with detected language
            final_state = agent.run_scan(
                codebase_path=scan_info["codebase_path"],
                model_name=scan_info["model_name"],
                cwes=scan_info["cwes"],
                scan_id=scan_id,
                detected_language=detected_language
            )
            
            # Sync logs from agent graph state to scan_info (in case any were missed)
            scan_info["status"] = final_state["status"]
            scan_info["progress"] = 90
            scan_info["findings"] = [dict(f) for f in final_state.get("findings", [])]
            self._persist_active_scan(scan_id)
            if final_state.get("logs"):
                existing_logs = set(scan_info["logs"])
                for log in final_state["logs"]:
                    if log not in existing_logs:
                        scan_info["logs"].append(log)
            
            scan_info["logs"].append(f"[{datetime.utcnow().isoformat()}] Scan completed with status: {final_state['status']}")
            
            # Process results
            confirmed = sum(1 for f in final_state["findings"] if f["final_status"] == "confirmed")
            skipped = sum(1 for f in final_state["findings"] if f["final_status"] == "skipped")
            failed = sum(1 for f in final_state["findings"] if f["final_status"] == "failed")
            
            # Calculate duration
            start = datetime.fromisoformat(final_state["start_time"])
            end = datetime.fromisoformat(final_state["end_time"]) if final_state["end_time"] else datetime.utcnow()
            duration = (end - start).total_seconds()
            
            result = ScanResult(
                scan_id=scan_id,
                status=final_state["status"],
                codebase_path=scan_info["codebase_path"],
                model_name=scan_info["model_name"],
                cwes=scan_info["cwes"],
                total_findings=len(final_state["findings"]),
                confirmed_vulns=confirmed,
                false_positives=skipped,
                failed=failed,
                total_cost_usd=final_state["total_cost_usd"],
                duration_s=duration,
                start_time=final_state["start_time"],
                end_time=final_state["end_time"],
                findings=[dict(f) for f in final_state["findings"]],
                detected_language=scan_info.get("detected_language"),
                language_info=scan_info.get("language_info"),
                logs=scan_info.get("logs", [])
            )
            
            # Save result
            self._save_result(result)
            
            # Update scan info
            self.update_scan(
                scan_id,
                status="completed",
                progress=100,
                result=result,
                findings=[dict(f) for f in final_state["findings"]]
            )
            self._remove_active_snapshot(scan_id)
            
            # Cleanup vector store
            get_code_ingester().cleanup(scan_id)
            
            return result
            
        except Exception as e:
            import traceback
            error_msg = f"{str(e)}\n{traceback.format_exc()}"
            scan_info["status"] = "failed"
            scan_info["error"] = error_msg
            scan_info["logs"].append(f"ERROR: {str(e)}")
            self._persist_active_scan(scan_id)
            print(f"Scan {scan_id} failed: {error_msg}")
            
            result = ScanResult(
                scan_id=scan_id,
                status="failed",
                codebase_path=scan_info["codebase_path"],
                model_name=scan_info["model_name"],
                cwes=scan_info["cwes"],
                total_findings=0,
                confirmed_vulns=0,
                false_positives=0,
                failed=0,
                total_cost_usd=0.0,
                duration_s=0.0,
                start_time=scan_info["created_at"],
                end_time=datetime.utcnow().isoformat(),
                findings=[],
                detected_language=scan_info.get("detected_language"),
                language_info=scan_info.get("language_info")
            )
            
            self._save_result(result)
            self.update_scan(scan_id, status="failed", progress=100, result=result)
            self._remove_active_snapshot(scan_id)
            return result
    
    def _save_result(self, result: ScanResult):
        """Save scan result to file"""
        # Save as JSON
        json_path = os.path.join(self._runs_dir, f"{result.scan_id}.json")
        with open(json_path, 'w') as f:
            json.dump(asdict(result), f, indent=2, default=str)
        
        # Append to CSV log
        csv_path = os.path.join(self._runs_dir, "scan_history.csv")
        file_exists = os.path.exists(csv_path)
        
        with open(csv_path, 'a', newline='') as f:
            writer = csv.writer(f)
            
            if not file_exists:
                writer.writerow([
                    'scan_id', 'status', 'model_name', 'cwes', 'total_findings',
                    'confirmed_vulns', 'false_positives', 'failed', 'total_cost_usd',
                    'duration_s', 'start_time', 'end_time'
                ])
            
            writer.writerow([
                result.scan_id,
                result.status,
                result.model_name,
                ','.join(result.cwes),
                result.total_findings,
                result.confirmed_vulns,
                result.false_positives,
                result.failed,
                result.total_cost_usd,
                result.duration_s,
                result.start_time,
                result.end_time
            ])
        
        # Optional snapshot for replay support
        if settings.SAVE_CODEBASE_SNAPSHOT and result.codebase_path and os.path.exists(result.codebase_path):
            snapshot_path = os.path.join(settings.SNAPSHOT_DIR, result.scan_id)
            if not os.path.exists(snapshot_path):
                try:
                    shutil.copytree(
                        result.codebase_path,
                        snapshot_path,
                        ignore=shutil.ignore_patterns(
                            '.git', 'node_modules', 'venv', '.venv', '__pycache__',
                            '.pytest_cache', 'results', 'data', 'dist', 'build',
                            '_codeql_detected_source_root'  # Exclude CodeQL symlinks
                        )
                    )
                except Exception as e:
                    print(f"[Snapshot] Failed to copy codebase: {e}")
    
    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get scan information"""
        scan_info = self._active_scans.get(scan_id)
        if scan_info:
            return scan_info
        snapshot_path = self._active_scan_path(scan_id)
        if os.path.exists(snapshot_path):
            try:
                with open(snapshot_path, 'r') as f:
                    data = json.load(f)
                self._active_scans[scan_id] = data
                self._scan_locks.setdefault(scan_id, threading.Lock())
                return data
            except Exception as e:
                print(f"[ScanManager] Failed to load active scan {scan_id}: {e}")
        return None
    
    def append_log(self, scan_id: str, message: str) -> bool:
        """
        Thread-safe method to append a log message to a scan
        
        Args:
            scan_id: Scan ID
            message: Log message to append
            
        Returns:
            True if successful, False otherwise
        """
        try:
            scan_info = self._active_scans.get(scan_id)
            if scan_info:
                # Use the scan-specific lock if available
                lock = self._scan_locks.get(scan_id)
                if lock:
                    with lock:
                        scan_info["logs"].append(message)
                else:
                    scan_info["logs"].append(message)
                self._persist_active_scan(scan_id)
                return True
        except Exception:
            pass
        return False
    
    def get_scan_result(self, scan_id: str) -> Optional[ScanResult]:
        """Get scan result from file"""
        json_path = os.path.join(self._runs_dir, f"{scan_id}.json")
        
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                data = json.load(f)
                return ScanResult(**data)
        
        return None
    
    def get_scan_history(
        self,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get scan history"""
        history = []
        
        csv_path = os.path.join(self._runs_dir, "scan_history.csv")
        
        if os.path.exists(csv_path):
            with open(csv_path, 'r') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                # Reverse to get newest first
                rows.reverse()
                
                for row in rows[offset:offset + limit]:
                    history.append(row)
        
        return history
    
    def get_scan_logs(self, scan_id: str) -> List[str]:
        """Get scan logs"""
        if scan_id in self._active_scans:
            return self._active_scans[scan_id].get("logs", [])
        
        # Try to load from result
        result = self.get_scan_result(scan_id)
        if result:
            return result.logs if result.logs else []
        
        return []
    
    def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan"""
        if scan_id in self._active_scans:
            scan_info = self._active_scans[scan_id]
            if scan_info["status"] in {"running", "checking", "cloning", "created", "interrupted"}:
                scan_info["status"] = "cancelled"
                self._persist_active_scan(scan_id)
                return True
        return False
    
    def cleanup_scan(self, scan_id: str):
        """Clean up scan resources"""
        if scan_id in self._active_scans:
            del self._active_scans[scan_id]
        self._remove_active_snapshot(scan_id)
        
        # Cleanup vector store
        get_code_ingester().cleanup(scan_id)
    
    def cleanup_old_results(self, max_age_days: int = 30, max_results: int = 500) -> Tuple[int, int]:
        """
        Clean up old scan result files to prevent unbounded disk growth.

        Removes result JSON files that are either:
          - Older than max_age_days days, OR
          - Beyond the newest max_results entries (sorted by start_time desc)

        Also rebuilds scan_history.csv from the surviving files.

        Returns:
            (files_removed, bytes_freed) tuple
        """
        json_files = []
        for fname in os.listdir(self._runs_dir):
            if not fname.endswith(".json") or fname == "scan_history.csv":
                continue
            fpath = os.path.join(self._runs_dir, fname)
            try:
                with open(fpath, "r") as f:
                    data = json.load(f)
                start_time_str = data.get("start_time", "")
                start_dt = datetime.fromisoformat(start_time_str) if start_time_str else datetime.min
            except Exception:
                start_dt = datetime.min
            json_files.append((start_dt, fpath))

        # Sort newest-first
        json_files.sort(key=lambda x: x[0], reverse=True)

        cutoff = datetime.utcnow() - timedelta(days=max_age_days)
        files_removed = 0
        bytes_freed = 0

        for idx, (start_dt, fpath) in enumerate(json_files):
            should_remove = (start_dt < cutoff) or (idx >= max_results)
            if should_remove:
                try:
                    size = os.path.getsize(fpath)
                    os.remove(fpath)
                    files_removed += 1
                    bytes_freed += size
                except Exception as e:
                    print(f"[Cleanup] Could not remove {fpath}: {e}")

        # Rebuild CSV from surviving JSON files
        self._rebuild_scan_history_csv()

        print(f"[Cleanup] Removed {files_removed} result files, freed {bytes_freed / 1024:.1f} KB")
        return files_removed, bytes_freed

    def _rebuild_scan_history_csv(self):
        """Rebuild scan_history.csv from surviving JSON result files."""
        csv_path = os.path.join(self._runs_dir, "scan_history.csv")
        rows = []

        for fname in os.listdir(self._runs_dir):
            if not fname.endswith(".json") or fname == "scan_history.csv":
                continue
            fpath = os.path.join(self._runs_dir, fname)
            try:
                with open(fpath, "r") as f:
                    data = json.load(f)
                rows.append({
                    "scan_id": data.get("scan_id", ""),
                    "status": data.get("status", ""),
                    "model_name": data.get("model_name", ""),
                    "cwes": ",".join(data.get("cwes", [])),
                    "total_findings": data.get("total_findings", 0),
                    "confirmed_vulns": data.get("confirmed_vulns", 0),
                    "false_positives": data.get("false_positives", 0),
                    "failed": data.get("failed", 0),
                    "total_cost_usd": data.get("total_cost_usd", 0),
                    "duration_s": data.get("duration_s", 0),
                    "start_time": data.get("start_time", ""),
                    "end_time": data.get("end_time", ""),
                })
            except Exception:
                continue

        # Sort by start_time descending
        rows.sort(key=lambda r: r.get("start_time", ""), reverse=True)

        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "scan_id", "status", "model_name", "cwes", "total_findings",
                "confirmed_vulns", "false_positives", "failed", "total_cost_usd",
                "duration_s", "start_time", "end_time"
            ])
            writer.writeheader()
            writer.writerows(rows)

    def get_metrics(self) -> Dict[str, Any]:
        """Get overall metrics"""
        total_scans = 0
        completed_scans = 0
        failed_scans = 0
        total_confirmed = 0
        total_false_positives = 0
        total_findings = 0
        total_cost = 0.0
        total_duration = 0.0
        duration_count = 0

        csv_path = os.path.join(self._runs_dir, "scan_history.csv")

        if os.path.exists(csv_path):
            with open(csv_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    total_scans += 1

                    if row['status'] == 'completed':
                        completed_scans += 1
                        total_confirmed += int(row.get('confirmed_vulns', 0) or 0)
                        total_false_positives += int(row.get('false_positives', 0) or 0)
                        total_findings += int(row.get('total_findings', 0) or 0)
                        total_cost += float(row.get('total_cost_usd', 0) or 0)
                        dur = float(row.get('duration_s', 0) or 0)
                        if dur > 0:
                            total_duration += dur
                            duration_count += 1
                    elif row['status'] == 'failed':
                        failed_scans += 1

        avg_duration = total_duration / duration_count if duration_count > 0 else 0.0
        avg_cost = total_cost / completed_scans if completed_scans > 0 else 0.0

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "running_scans": len([s for s in self._active_scans.values() if s["status"] == "running"]),
            "active_scans": len([s for s in self._active_scans.values() if s["status"] == "running"]),
            "total_findings": total_findings,
            "total_confirmed_vulnerabilities": total_confirmed,
            "confirmed_vulns": total_confirmed,
            "false_positives": total_false_positives,
            "total_cost_usd": total_cost,
            "avg_cost_usd": avg_cost,
            "avg_duration_s": avg_duration,
        }


# Global scan manager instance
scan_manager = ScanManager()


def get_scan_manager() -> ScanManager:
    """Get the global scan manager instance"""
    return scan_manager

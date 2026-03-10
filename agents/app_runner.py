"""
AutoPoV Application Runner Module
Manages target application lifecycle for PoV testing
"""

import os
import subprocess
import time
import requests
from typing import Dict, Optional, Any
from datetime import datetime


class AppRunnerError(Exception):
    """Exception raised during application execution"""
    pass


class ApplicationRunner:
    """Runs target applications for PoV testing"""
    
    def __init__(self):
        self.running_apps = {}  # scan_id -> app_info
    
    def start_nodejs_app(
        self,
        scan_id: str,
        app_path: str,
        port: int = 3000,
        start_timeout: int = 60
    ) -> Dict[str, Any]:
        """
        Start a Node.js application (like juice-shop)
        
        Args:
            scan_id: Scan identifier
            app_path: Path to the application code
            port: Port to run the application on
            start_timeout: Timeout to wait for app to start
            
        Returns:
            Dictionary with app info and status
        """
        try:
            # Check if package.json exists
            package_json = os.path.join(app_path, 'package.json')
            if not os.path.exists(package_json):
                return {
                    "success": False,
                    "error": f"No package.json found in {app_path}",
                    "url": None,
                    "process": None
                }
            
            # Install dependencies if node_modules doesn't exist
            node_modules = os.path.join(app_path, 'node_modules')
            if not os.path.exists(node_modules):
                print(f"[AppRunner] Installing dependencies for {scan_id}...")
                install_result = subprocess.run(
                    ['npm', 'install'],
                    cwd=app_path,
                    capture_output=True,
                    text=True,
                    timeout=120
                )
                if install_result.returncode != 0:
                    return {
                        "success": False,
                        "error": f"npm install failed: {install_result.stderr}",
                        "url": None,
                        "process": None
                    }
            
            # Start the application
            print(f"[AppRunner] Starting Node.js app on port {port}...")
            env = os.environ.copy()
            env['PORT'] = str(port)
            
            process = subprocess.Popen(
                ['npm', 'start'],
                cwd=app_path,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True
            )
            
            # Wait for app to be ready
            url = f"http://localhost:{port}"
            start_time = time.time()
            ready = False
            
            while time.time() - start_time < start_timeout:
                try:
                    response = requests.get(url, timeout=2)
                    if response.status_code < 500:
                        ready = True
                        break
                except requests.exceptions.ConnectionError:
                    pass
                except requests.exceptions.Timeout:
                    pass
                time.sleep(1)
            
            if not ready:
                process.terminate()
                return {
                    "success": False,
                    "error": f"Application failed to start within {start_timeout}s",
                    "url": None,
                    "process": None
                }
            
            # Store app info
            app_info = {
                "scan_id": scan_id,
                "process": process,
                "url": url,
                "port": port,
                "app_path": app_path,
                "started_at": datetime.utcnow().isoformat(),
                "type": "nodejs"
            }
            self.running_apps[scan_id] = app_info
            
            print(f"[AppRunner] App started successfully at {url}")
            
            return {
                "success": True,
                "error": None,
                "url": url,
                "process": process
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Timeout during npm install",
                "url": None,
                "process": None
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "url": None,
                "process": None
            }
    
    def stop_app(self, scan_id: str) -> bool:
        """Stop a running application"""
        if scan_id not in self.running_apps:
            return False
        
        app_info = self.running_apps[scan_id]
        process = app_info.get("process")
        
        if process:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            except Exception:
                pass
        
        del self.running_apps[scan_id]
        print(f"[AppRunner] Stopped app for {scan_id}")
        return True
    
    def get_app_url(self, scan_id: str) -> Optional[str]:
        """Get the URL of a running application"""
        if scan_id in self.running_apps:
            return self.running_apps[scan_id].get("url")
        return None
    
    def is_app_running(self, scan_id: str) -> bool:
        """Check if an application is running"""
        if scan_id not in self.running_apps:
            return False
        
        process = self.running_apps[scan_id].get("process")
        if process:
            return process.poll() is None
        return False
    
    def cleanup_all(self):
        """Stop all running applications"""
        for scan_id in list(self.running_apps.keys()):
            self.stop_app(scan_id)


# Global application runner instance
app_runner = ApplicationRunner()


def get_app_runner() -> ApplicationRunner:
    """Get the global application runner instance"""
    return app_runner

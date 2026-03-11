"""
AutoPoV PoV Tester Module
Tests PoV scripts against running applications
"""

import os
import subprocess
import tempfile
import requests
from typing import Dict, Optional, Any
from datetime import datetime

from agents.app_runner import get_app_runner


class PoVTesterError(Exception):
    """Exception raised during PoV testing"""
    pass


class PoVTester:
    """Tests PoV scripts against running applications"""
    
    def test_pov_against_app(
        self,
        pov_script: str,
        scan_id: str,
        cwe_type: str,
        target_url: str,
        language: str = "python"
    ) -> Dict[str, Any]:
        """
        Test a PoV script against a running application
        
        Args:
            pov_script: The PoV script content
            scan_id: Scan identifier
            cwe_type: CWE type being tested
            target_url: URL of the running target application
            language: Language of the PoV script (python or javascript)
            
        Returns:
            Test result dictionary
        """
        start_time = datetime.utcnow()
        
        # Create temporary directory for PoV
        temp_dir = tempfile.mkdtemp(prefix=f"pov_{scan_id}_")
        
        try:
            # Write PoV script
            if language == "python":
                pov_filename = "pov.py"
                # Modify the script to use the correct target URL
                pov_script = self._patch_pov_url(pov_script, target_url)
            else:
                pov_filename = "pov.js"
            
            pov_path = os.path.join(temp_dir, pov_filename)
            with open(pov_path, 'w') as f:
                f.write(pov_script)
            
            # Run the PoV script
            if language == "python":
                result = self._run_python_pov(temp_dir, pov_filename, target_url)
            else:
                result = self._run_javascript_pov(temp_dir, pov_filename, target_url)
            
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            
            # Check if vulnerability was triggered
            vulnerability_triggered = (
                "VULNERABILITY TRIGGERED" in result.get("stdout", "") or
                result.get("vulnerability_triggered", False)
            )
            
            return {
                "success": True,
                "vulnerability_triggered": vulnerability_triggered,
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "exit_code": result.get("exit_code", -1),
                "execution_time_s": execution_time,
                "timestamp": end_time.isoformat(),
                "target_url": target_url
            }
            
        except Exception as e:
            end_time = datetime.utcnow()
            return {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "execution_time_s": (end_time - start_time).total_seconds(),
                "timestamp": end_time.isoformat(),
                "target_url": target_url
            }
        finally:
            # Cleanup
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def _patch_pov_url(self, pov_script: str, target_url: str) -> str:
        """Patch the PoV script to use the correct target URL"""
        # Replace common localhost patterns with the actual target URL
        import re
        
        # First, replace the {{target_url}} placeholder
        pov_script = pov_script.replace('{{target_url}}', target_url)
        pov_script = pov_script.replace('{target_url}', target_url)
        
        # Replace localhost:3000 or 127.0.0.1:3000 with the target URL
        pov_script = re.sub(
            r'http://localhost:\d+',
            target_url,
            pov_script
        )
        pov_script = re.sub(
            r'http://127\.0\.0\.1:\d+',
            target_url,
            pov_script
        )
        
        # Also replace just the port if it's in a variable
        pov_script = re.sub(
            r"base_url\s*=\s*['\"]http://localhost:\d+['\"]",
            f"base_url = '{target_url}'",
            pov_script
        )
        
        # Replace any remaining localhost references
        pov_script = pov_script.replace('localhost:3000', target_url.replace('http://', '').replace('https://', ''))
        
        return pov_script
    
    def _run_python_pov(
        self,
        temp_dir: str,
        pov_filename: str,
        target_url: str
    ) -> Dict[str, Any]:
        """Run a Python PoV script"""
        try:
            # Set environment variable for the target URL
            env = os.environ.copy()
            env['TARGET_URL'] = target_url
            
            result = subprocess.run(
                ['python3', pov_filename],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )
            
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "vulnerability_triggered": "VULNERABILITY TRIGGERED" in result.stdout
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": "PoV execution timed out",
                "exit_code": -1,
                "vulnerability_triggered": False
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "vulnerability_triggered": False
            }
    
    def _run_javascript_pov(
        self,
        temp_dir: str,
        pov_filename: str,
        target_url: str
    ) -> Dict[str, Any]:
        """Run a JavaScript PoV script"""
        try:
            # Set environment variable for the target URL
            env = os.environ.copy()
            env['TARGET_URL'] = target_url
            
            result = subprocess.run(
                ['node', pov_filename],
                cwd=temp_dir,
                capture_output=True,
                text=True,
                timeout=30,
                env=env
            )
            
            return {
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode,
                "vulnerability_triggered": "VULNERABILITY TRIGGERED" in result.stdout
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": "PoV execution timed out",
                "exit_code": -1,
                "vulnerability_triggered": False
            }
        except Exception as e:
            return {
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "vulnerability_triggered": False
            }
    
    def test_with_app_lifecycle(
        self,
        pov_script: str,
        scan_id: str,
        cwe_type: str,
        app_path: str,
        language: str = "python",
        app_port: int = 3000
    ) -> Dict[str, Any]:
        """
        Full lifecycle: Start app, test PoV, stop app
        
        Args:
            pov_script: The PoV script content
            scan_id: Scan identifier
            cwe_type: CWE type being tested
            app_path: Path to the application code
            language: Language of the PoV script
            app_port: Port to run the application on
            
        Returns:
            Test result dictionary
        """
        app_runner = get_app_runner()
        
        # Start the application
        print(f"[PoVTester] Starting application for {scan_id}...")
        app_result = app_runner.start_nodejs_app(
            scan_id=scan_id,
            app_path=app_path,
            port=app_port
        )
        
        if not app_result["success"]:
            return {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": f"Failed to start app: {app_result.get('error')}",
                "exit_code": -1,
                "execution_time_s": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        try:
            # Test the PoV against the running app
            target_url = app_result["url"]
            print(f"[PoVTester] Testing PoV against {target_url}...")
            
            result = self.test_pov_against_app(
                pov_script=pov_script,
                scan_id=scan_id,
                cwe_type=cwe_type,
                target_url=target_url,
                language=language
            )
            
            return result
            
        finally:
            # Always stop the application
            print(f"[PoVTester] Stopping application...")
            app_runner.stop_app(scan_id)


# Global PoV tester instance
pov_tester = PoVTester()


def get_pov_tester() -> PoVTester:
    """Get the global PoV tester instance"""
    return pov_tester

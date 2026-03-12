"""
AutoPoV Unit Test Runner Module
Runs PoV scripts against isolated vulnerable code snippets
"""

import os
import re
import ast
import tempfile
import subprocess
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime


@dataclass
class TestResult:
    """Result of unit test validation"""
    success: bool
    vulnerability_triggered: bool
    execution_time_s: float
    stdout: str
    stderr: str
    exit_code: int
    details: Dict[str, Any]


class UnitTestRunner:
    """Runs PoV scripts against isolated code in unit test style"""
    
    # CWE-specific validation oracles
    CWE_ORACLES = {
        "CWE-22": {  # Path Traversal
            "side_effect_files": ["/tmp/autopov_traversal_test", "/tmp/autopov_path_test"],
            "expected_content_patterns": ["root:x:0:0:", "etc/passwd", "windows/system32"],
        },
        "CWE-78": {  # Command Injection
            "side_effect_files": ["/tmp/autopov_rce", "/tmp/autopov_cmd_injection"],
            "expected_output_patterns": ["uid=", "root", "bin/bash"],
        },
        "CWE-89": {  # SQL Injection
            "expected_output_patterns": ["MariaDB", "MySQL", "SQLite", "PostgreSQL", "version", "@@version"],
            "timing_threshold_s": 5.0,  # Time-based detection
        },
        "CWE-94": {  # Code Injection
            "side_effect_files": ["/tmp/autopov_code_exec"],
            "expected_output_patterns": ["eval executed", "exec completed", "code injected"],
        },
    }
    
    def __init__(self):
        self.test_history = []
    
    def test_vulnerable_function(
        self,
        pov_script: str,
        vulnerable_code: str,
        cwe_type: str,
        scan_id: str
    ) -> TestResult:
        """
        Test PoV against isolated vulnerable function
        
        Args:
            pov_script: The PoV script content
            vulnerable_code: The vulnerable code snippet
            cwe_type: CWE type being tested
            scan_id: Scan identifier
            
        Returns:
            TestResult with execution details
        """
        start_time = datetime.utcnow()
        
        try:
            # Extract the vulnerable function from the code
            extracted_func = self._extract_function(vulnerable_code)
            
            if not extracted_func:
                return TestResult(
                    success=False,
                    vulnerability_triggered=False,
                    execution_time_s=0,
                    stdout="",
                    stderr="Could not extract function from vulnerable code",
                    exit_code=-1,
                    details={"error": "extraction_failed"}
                )
            
            # Create test harness
            test_harness = self._create_test_harness(
                pov_script=pov_script,
                vulnerable_function=extracted_func,
                cwe_type=cwe_type
            )
            
            # Run in isolated subprocess
            result = self._run_isolated_test(test_harness, scan_id)
            
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            
            # Check if vulnerability was triggered using CWE-specific oracles
            vuln_triggered = self._check_cwe_oracle(
                cwe_type=cwe_type,
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                execution_time=execution_time
            )
            
            test_result = TestResult(
                success=result.get("success", False),
                vulnerability_triggered=vuln_triggered,
                execution_time_s=execution_time,
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                exit_code=result.get("exit_code", -1),
                details={
                    "cwe_type": cwe_type,
                    "extraction_success": True,
                    "test_method": "isolated_function"
                }
            )
            
            self.test_history.append(test_result)
            return test_result
            
        except Exception as e:
            end_time = datetime.utcnow()
            return TestResult(
                success=False,
                vulnerability_triggered=False,
                execution_time_s=(end_time - start_time).total_seconds(),
                stdout="",
                stderr=str(e),
                exit_code=-1,
                details={"error": str(e)}
            )
    
    def _extract_function(self, code: str) -> Optional[str]:
        """Extract the main vulnerable function from code snippet"""
        if not code or not code.strip():
            return None
        
        # Try to find function definitions
        lines = code.split('\n')
        
        # Look for common function patterns
        func_patterns = [
            r'def\s+(\w+)\s*\(',
            r'function\s+(\w+)\s*\(',
            r'(\w+)\s*=\s*function\s*\(',
            r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>',
            r'async\s+function\s+(\w+)',
        ]
        
        for line in lines:
            for pattern in func_patterns:
                match = re.search(pattern, line)
                if match:
                    # Return the entire code as the function context
                    return code
        
        # If no function found, return the code as-is (might be inline code)
        return code
    
    def _create_test_harness(
        self,
        pov_script: str,
        vulnerable_function: str,
        cwe_type: str
    ) -> str:
        """Create a test harness that combines vulnerable code with PoV"""
        
        # Create a safe test environment
        harness = f'''#!/usr/bin/env python3
"""
AutoPoV Test Harness
Isolated test of vulnerable code with PoV
"""

import sys
import io
import traceback
from contextlib import redirect_stdout, redirect_stderr

# Capture original stdout/stderr
original_stdout = sys.stdout
original_stderr = sys.stderr

# Create string buffers to capture output
stdout_buffer = io.StringIO()
stderr_buffer = io.StringIO()

try:
    # Set up the vulnerable code context
    vulnerable_code_context = """
{vulnerable_code}
"""
    
    # Provide helpers for PoV scripts
    vulnerable_code = vulnerable_code_context
    target_url = "http://localhost"
    TARGET_URL = target_url
    
    # Execute vulnerable code in isolated namespace
    vulnerable_namespace = {{}}
    exec(vulnerable_code_context, vulnerable_namespace)
    
    # Make vulnerable functions available globally
    globals().update(vulnerable_namespace)
    
    # Now run the PoV script
    pov_code = """
{pov_code}
"""
    
    # Redirect output for PoV execution
    with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
        # Execute PoV
        pov_namespace = {{
            **vulnerable_namespace,  # Make vulnerable functions available
            '__name__': '__main__'
        }}
        exec(pov_code, pov_namespace)
    
    # Check results
    stdout_output = stdout_buffer.getvalue()
    stderr_output = stderr_buffer.getvalue()
    
    # Print captured output
    print(stdout_output, file=original_stdout)
    print(stderr_output, file=original_stderr)
    
    # Check if vulnerability was triggered
    if "VULNERABILITY TRIGGERED" in stdout_output:
        print("\\n[TEST RESULT] Vulnerability successfully triggered", file=original_stdout)
        sys.exit(0)
    else:
        print("\\n[TEST RESULT] Vulnerability not triggered", file=original_stdout)
        sys.exit(1)
        
except Exception as e:
    error_msg = f"Test harness error: {{str(e)}}\\n{{traceback.format_exc()}}"
    print(error_msg, file=original_stderr)
    sys.exit(2)
'''
        
        # Escape the code to safely embed in the harness
        escaped_vulnerable = vulnerable_function.replace('\\', '\\\\').replace('"""', '\\"\\"\\"').replace("'''", "\\'\\'\\'")
        escaped_pov = pov_script.replace('\\', '\\\\').replace('"""', '\\"\\"\\"').replace("'''", "\\'\\'\\'")
        
        return harness.format(
            vulnerable_code=escaped_vulnerable,
            pov_code=escaped_pov
        )
    
    def _run_isolated_test(self, test_harness: str, scan_id: str) -> Dict[str, Any]:
        """Run the test harness in an isolated subprocess"""
        
        # Create temporary file for test harness
        temp_dir = tempfile.mkdtemp(prefix=f"autopov_test_{scan_id}_")
        harness_path = os.path.join(temp_dir, "test_harness.py")
        
        try:
            # Write harness to file
            with open(harness_path, 'w') as f:
                f.write(test_harness)
            
            # Run in isolated subprocess with restrictions
            result = subprocess.run(
                ["python3", harness_path],
                capture_output=True,
                text=True,
                timeout=30,  # 30 second timeout
                # Security: limit resources
                env={"PYTHONPATH": "", "PATH": "/usr/bin:/bin"}
            )
            
            return {
                "success": result.returncode == 0,
                "vulnerability_triggered": result.returncode == 0 and "VULNERABILITY TRIGGERED" in result.stdout,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "exit_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": "Test execution timed out (30s)",
                "exit_code": -1
            }
        except Exception as e:
            return {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": f"Test execution failed: {str(e)}",
                "exit_code": -1
            }
        finally:
            # Cleanup
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
    
    def test_with_mock_data(
        self,
        pov_script: str,
        cwe_type: str,
        mock_inputs: List[str]
    ) -> List[TestResult]:
        """Test PoV against mock inputs without real vulnerable code"""
        results = []
        
        for mock_input in mock_inputs:
            # Create a simple test that feeds mock input to the PoV
            test_code = f'''
import sys
sys.stdin = io.StringIO("""{mock_input}""")

# Run PoV
{pov_script}
'''
            result = self._run_isolated_test(test_code, f"mock_{hash(mock_input)}")
            
            results.append(TestResult(
                success=result.get("success", False),
                vulnerability_triggered=result.get("vulnerability_triggered", False),
                execution_time_s=0,
                stdout=result.get("stdout", ""),
                stderr=result.get("stderr", ""),
                exit_code=result.get("exit_code", -1),
                details={"mock_input": mock_input, "test_type": "mock"}
            ))
        
        return results
    
    def _check_cwe_oracle(
        self,
        cwe_type: str,
        stdout: str,
        stderr: str,
        execution_time: float
    ) -> bool:
        """
        Check if vulnerability was triggered using CWE-specific oracles.
        
        Returns True if the oracle indicates successful exploitation.
        """
        combined_output = (stdout + stderr).lower()
        
        # Always check for the basic indicator first
        if "VULNERABILITY TRIGGERED" in stdout:
            return True
        
        # Get oracle config for this CWE
        oracle = self.CWE_ORACLES.get(cwe_type, {})
        if not oracle:
            # No specific oracle, fall back to basic check
            return "VULNERABILITY TRIGGERED" in stdout
        
        # Check for expected output patterns
        expected_patterns = oracle.get("expected_output_patterns", [])
        for pattern in expected_patterns:
            if pattern.lower() in combined_output:
                return True
        
        # Check for side-effect files (for file-based oracles)
        side_effect_files = oracle.get("side_effect_files", [])
        for file_path in side_effect_files:
            try:
                if os.path.exists(file_path):
                    # File was created - potential RCE/path traversal
                    return True
            except Exception:
                pass
        
        # Check timing for time-based detection (SQL injection)
        timing_threshold = oracle.get("timing_threshold_s")
        if timing_threshold and execution_time >= timing_threshold:
            return True
        
        return False
    
    def validate_syntax(self, pov_script: str) -> Dict[str, Any]:
        """Validate PoV script syntax without execution"""
        try:
            ast.parse(pov_script)
            return {
                "valid": True,
                "error": None,
                "has_main": "if __name__" in pov_script or "def main" in pov_script
            }
        except SyntaxError as e:
            return {
                "valid": False,
                "error": f"Syntax error at line {e.lineno}: {e.msg}",
                "has_main": False
            }


# Global runner instance
unit_test_runner = UnitTestRunner()


def get_unit_test_runner() -> UnitTestRunner:
    """Get the global unit test runner instance"""
    return unit_test_runner

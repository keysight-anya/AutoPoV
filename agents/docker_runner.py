"""
AutoPoV Docker Runner Module
Executes PoV scripts in isolated Docker containers
"""

import os
import tempfile
import shutil
from typing import Dict, Optional, Any, List
from datetime import datetime

try:
    import docker
    from docker.errors import DockerException, ContainerError, ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False

from app.config import settings


class DockerRunnerError(Exception):
    """Exception raised during Docker execution"""
    pass


class DockerRunner:
    """Runs PoV scripts in Docker containers"""
    
    def __init__(self):
        self._client = None
        self.image = settings.DOCKER_IMAGE
        self.timeout = settings.DOCKER_TIMEOUT
        self.memory_limit = settings.DOCKER_MEMORY_LIMIT
        self.cpu_limit = settings.DOCKER_CPU_LIMIT
    
    def _get_client(self):
        """Get Docker client"""
        if not DOCKER_AVAILABLE:
            raise DockerRunnerError("docker-py not available. Install docker")
        
        if self._client is None:
            try:
                self._client = docker.from_env()
            except DockerException as e:
                raise DockerRunnerError(f"Could not connect to Docker: {e}")
        
        return self._client
    
    def is_available(self) -> bool:
        """Check if Docker is available"""
        if not settings.is_docker_available():
            return False
        
        try:
            client = self._get_client()
            client.ping()
            return True
        except Exception:
            return False
    
    def run_pov(
        self,
        pov_script: str,
        scan_id: str,
        pov_id: str,
        extra_files: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """
        Run a PoV script in Docker
        
        Args:
            pov_script: Python script content
            scan_id: Scan identifier
            pov_id: PoV identifier
            extra_files: Additional files to include {filename: content}
        
        Returns:
            Execution result dictionary
        """
        if not self.is_available():
            return {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": "Docker not available",
                "exit_code": -1,
                "execution_time_s": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Create temporary directory for PoV files
        temp_dir = tempfile.mkdtemp(prefix=f"autopov_{scan_id}_")
        
        try:
            # Write PoV script
            pov_filename = f"pov_{pov_id}.py"
            pov_path = os.path.join(temp_dir, pov_filename)
            
            with open(pov_path, 'w') as f:
                f.write(pov_script)
            
            # Write extra files
            if extra_files:
                for filename, content in extra_files.items():
                    file_path = os.path.join(temp_dir, filename)
                    with open(file_path, 'w') as f:
                        f.write(content)
            
            # Run in Docker
            client = self._get_client()
            
            # Ensure image exists
            try:
                client.images.get(self.image)
            except ImageNotFound:
                client.images.pull(self.image)
            
            start_time = datetime.utcnow()
            
            # Run container
            container = client.containers.run(
                image=self.image,
                command=["python", pov_filename],
                volumes={temp_dir: {'bind': '/pov', 'mode': 'ro'}},
                working_dir='/pov',
                mem_limit=self.memory_limit,
                cpu_quota=int(self.cpu_limit * 100000),
                network_mode='none',  # No network access for security
                detach=True,
                stdout=True,
                stderr=True
            )
            
            # Wait for completion with timeout
            try:
                result = container.wait(timeout=self.timeout)
                exit_code = result['StatusCode']
            except Exception as e:
                # Timeout or error
                container.kill()
                exit_code = -1
                result = {'Error': str(e)}
            
            # Get logs
            stdout = container.logs(stdout=True, stderr=False).decode('utf-8', errors='ignore')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8', errors='ignore')
            
            # Cleanup container
            container.remove(force=True)
            
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            
            # Check for vulnerability trigger
            vulnerability_triggered = "VULNERABILITY TRIGGERED" in stdout
            
            return {
                "success": exit_code == 0 or vulnerability_triggered,
                "vulnerability_triggered": vulnerability_triggered,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "execution_time_s": execution_time,
                "timestamp": end_time.isoformat()
            }
            
        except ContainerError as e:
            return {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": e.stdout.decode('utf-8', errors='ignore') if e.stdout else "",
                "stderr": e.stderr.decode('utf-8', errors='ignore') if e.stderr else str(e),
                "exit_code": e.exit_status,
                "execution_time_s": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "vulnerability_triggered": False,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "execution_time_s": 0,
                "timestamp": datetime.utcnow().isoformat()
            }
        finally:
            # Cleanup temp directory
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
    
    def run_with_input(
        self,
        pov_script: str,
        input_data: str,
        scan_id: str,
        pov_id: str
    ) -> Dict[str, Any]:
        """
        Run PoV with input data piped to stdin
        
        Args:
            pov_script: Python script content
            input_data: Data to pipe to stdin
            scan_id: Scan identifier
            pov_id: PoV identifier
        
        Returns:
            Execution result dictionary
        """
        # Write input data to a separate file to avoid string escaping issues
        extra_files = {
            'input_data.txt': input_data,
            'pov_script.py': pov_script
        }
        
        # Create wrapper script that reads from file
        wrapper_script = '''
import sys
import subprocess

# Run the actual PoV
exec(open('/pov/pov_script.py').read())
'''
        extra_files['wrapper.py'] = wrapper_script
        
        return self.run_pov(wrapper_script, scan_id, pov_id, extra_files)
    
    def run_binary_pov(
        self,
        pov_script: str,
        binary_data: bytes,
        scan_id: str,
        pov_id: str
    ) -> Dict[str, Any]:
        """
        Run PoV with binary input data
        
        Args:
            pov_script: Python script content
            binary_data: Binary data to provide
            scan_id: Scan identifier
            pov_id: PoV identifier
        
        Returns:
            Execution result dictionary
        """
        temp_dir = tempfile.mkdtemp(prefix=f"autopov_{scan_id}_")
        
        try:
            # Write binary data
            binary_path = os.path.join(temp_dir, "input.bin")
            with open(binary_path, 'wb') as f:
                f.write(binary_data)
            
            # Write PoV script
            pov_path = os.path.join(temp_dir, "pov.py")
            with open(pov_path, 'w') as f:
                f.write(pov_script)
            
            # Run in Docker
            client = self._get_client()
            
            start_time = datetime.utcnow()
            
            container = client.containers.run(
                image=self.image,
                command=["python", "pov.py"],
                volumes={temp_dir: {'bind': '/pov', 'mode': 'ro'}},
                working_dir='/pov',
                mem_limit=self.memory_limit,
                cpu_quota=int(self.cpu_limit * 100000),
                network_mode='none',
                detach=True,
                stdout=True,
                stderr=True
            )
            
            try:
                result = container.wait(timeout=self.timeout)
                exit_code = result['StatusCode']
            except Exception:
                container.kill()
                exit_code = -1
            
            stdout = container.logs(stdout=True, stderr=False).decode('utf-8', errors='ignore')
            stderr = container.logs(stdout=False, stderr=True).decode('utf-8', errors='ignore')
            
            container.remove(force=True)
            
            end_time = datetime.utcnow()
            execution_time = (end_time - start_time).total_seconds()
            
            vulnerability_triggered = "VULNERABILITY TRIGGERED" in stdout
            
            return {
                "success": exit_code == 0 or vulnerability_triggered,
                "vulnerability_triggered": vulnerability_triggered,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "execution_time_s": execution_time,
                "timestamp": end_time.isoformat()
            }
            
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
    
    def batch_run(
        self,
        pov_scripts: List[Dict[str, Any]],
        scan_id: str,
        progress_callback: Optional[callable] = None
    ) -> List[Dict[str, Any]]:
        """
        Run multiple PoV scripts
        
        Args:
            pov_scripts: List of PoV script dictionaries
            scan_id: Scan identifier
            progress_callback: Optional progress callback
        
        Returns:
            List of execution results
        """
        results = []
        
        for i, pov_info in enumerate(pov_scripts):
            result = self.run_pov(
                pov_script=pov_info['script'],
                scan_id=scan_id,
                pov_id=pov_info.get('id', str(i))
            )
            
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, len(pov_scripts), result)
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get Docker stats"""
        if not self.is_available():
            return {"available": False}
        
        try:
            client = self._get_client()
            info = client.info()
            
            return {
                "available": True,
                "version": info.get('ServerVersion', 'unknown'),
                "containers_running": info.get('ContainersRunning', 0),
                "containers_total": info.get('Containers', 0),
                "images": info.get('Images', 0),
                "memory_limit": self.memory_limit,
                "cpu_limit": self.cpu_limit,
                "timeout": self.timeout
            }
        except Exception as e:
            return {
                "available": False,
                "error": str(e)
            }


# Global Docker runner instance
docker_runner = DockerRunner()


def get_docker_runner() -> DockerRunner:
    """Get the global Docker runner instance"""
    return docker_runner

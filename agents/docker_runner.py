"""
AutoPoV Docker Runner Module
Executes PoV scripts in isolated Docker containers
"""

import io
import os
import tarfile
import tempfile
import shutil
from typing import Dict, Optional, Any, List, Tuple
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
    
    def _resolve_runtime(self, execution_profile: Optional[str], target_language: Optional[str]) -> Tuple[str, List[str], str]:
        """Resolve the container image, command, and filename for a PoV runtime."""
        profile = (execution_profile or "").strip().lower()
        language = (target_language or "").strip().lower()

        if profile in {"javascript", "node"} or language in {"javascript", "typescript", "jsx", "tsx"}:
            return ("node:22-slim", ["node"], "pov.js")
        if profile in {"shell", "bash", "sh"}:
            return ("ubuntu:24.04", ["bash"], "pov.sh")
        return (self.image, ["python"], "pov.py")

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
        extra_files: Optional[Dict[str, str]] = None,
        execution_profile: Optional[str] = None,
        target_language: Optional[str] = None,
        exploit_contract: Optional[Dict[str, Any]] = None
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
            image, runtime_command, pov_filename = self._resolve_runtime(execution_profile, target_language)

            # Write PoV script
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
                client.images.get(image)
            except ImageNotFound:
                client.images.pull(image)
            
            start_time = datetime.utcnow()
            
            exec_cmd = "mkdir -p /pov && " + " ".join(runtime_command + [f"/pov/{pov_filename}"])
            container = client.containers.create(
                image=image,
                command=["sh", "-lc", exec_cmd],
                working_dir='/',
                mem_limit=self.memory_limit,
                cpu_quota=int(self.cpu_limit * 100000),
                network_mode='none',
                detach=True
            )

            archive_buffer = io.BytesIO()
            with tarfile.open(fileobj=archive_buffer, mode='w') as tar:
                for name in os.listdir(temp_dir):
                    full_path = os.path.join(temp_dir, name)
                    tar.add(full_path, arcname=f'pov/{name}')
            archive_buffer.seek(0)
            container.put_archive('/', archive_buffer.getvalue())
            container.start()
            
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
            
            # Check for vulnerability trigger using both generic and contract-specific indicators
            indicators = ["VULNERABILITY TRIGGERED"]
            contract = exploit_contract or {}
            indicators.extend(contract.get("success_indicators", []) or [])
            indicators.extend(contract.get("side_effects", []) or [])
            haystack = (stdout + "\n" + stderr).lower()
            vulnerability_triggered = any(str(ind).strip().lower() in haystack for ind in indicators if str(ind).strip())
            
            return {
                "success": exit_code == 0 or vulnerability_triggered,
                "vulnerability_triggered": vulnerability_triggered,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
                "execution_time_s": execution_time,
                "timestamp": end_time.isoformat(),
                "execution_profile": execution_profile or target_language or "python",
                "runtime_image": image,
                "validation_method": "generic_container_runtime"
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
            
            # Cleanup Docker resources used by this PoV
            self._cleanup_pov_resources(scan_id, pov_id)
    
    def _cleanup_pov_resources(self, scan_id: str, pov_id: str):
        """
        Clean up Docker resources after PoV execution.
        Removes containers and images specific to this PoV.
        """
        try:
            client = self._get_client()
            
            # Find and remove containers with this scan/pov ID
            container_pattern = f"autopov_{scan_id}_{pov_id}"
            
            # Remove stopped containers with autopov prefix
            containers = client.containers.list(
                all=True,
                filters={"name": container_pattern}
            )
            for container in containers:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            
            # Clean up dangling images created during this run
            # This removes intermediate build layers
            try:
                client.images.prune(filters={"dangling": True})
            except Exception:
                pass
            
            # Clean up unused volumes created during this run
            try:
                client.volumes.prune()
            except Exception:
                pass
                
        except Exception:
            # Don't fail if cleanup fails
            pass
    
    def cleanup_all_pov_resources(self, scan_id: Optional[str] = None):
        """
        Clean up all Docker resources used by PoV testing.
        
        Args:
            scan_id: Optional scan ID to cleanup specific scan, or None for all
        """
        try:
            client = self._get_client()
            
            # Pattern for containers
            pattern = f"autopov_{scan_id}" if scan_id else "autopov_"
            
            # Stop and remove containers
            containers = client.containers.list(
                all=True,
                filters={"name": pattern}
            )
            
            for container in containers:
                try:
                    container.stop(timeout=5)
                    container.remove(force=True)
                except Exception:
                    pass
            
            # Remove dangling images
            try:
                client.images.prune(filters={"dangling": True})
            except Exception:
                pass
            
            # Clean up build cache
            try:
                client.api.prune_builds()
            except Exception:
                pass
                
        except Exception as e:
            print(f"Warning: Docker cleanup failed: {e}")
    
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
        pov_id: str,
        exploit_contract: Optional[Dict[str, Any]] = None
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
                detach=True
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
            
            indicators = ["VULNERABILITY TRIGGERED"]
            if exploit_contract:
                indicators.extend(exploit_contract.get("success_indicators", []) or [])
                indicators.extend(exploit_contract.get("side_effects", []) or [])
            haystack = (stdout + "\n" + stderr).lower()
            vulnerability_triggered = any(str(ind).strip().lower() in haystack for ind in indicators if str(ind).strip())
            
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
            
            # Cleanup Docker resources
            self._cleanup_pov_resources(scan_id, pov_id)
    
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

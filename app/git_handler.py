"""
AutoPoV Git Handler Module
Handles cloning from GitHub, GitLab, and Bitbucket with credential injection
"""

import os
import re
import shutil
import tempfile
from typing import Optional, Tuple, Dict
from urllib.parse import urlparse
import subprocess
import requests
import git
from git import Repo, GitCommandError

from app.config import settings


class GitHandler:
    """Handles Git repository operations"""
    
    def __init__(self):
        self.temp_base = settings.TEMP_DIR
        os.makedirs(self.temp_base, exist_ok=True)
    
    def _inject_credentials(self, url: str, provider: str) -> str:
        """Inject credentials into Git URL"""
        parsed = urlparse(url)
        
        if provider == "github" and settings.GITHUB_TOKEN:
            # https://token@github.com/owner/repo.git
            return f"https://{settings.GITHUB_TOKEN}@{parsed.netloc}{parsed.path}"
        
        elif provider == "gitlab" and settings.GITLAB_TOKEN:
            # https://oauth2:token@gitlab.com/owner/repo.git
            return f"https://oauth2:{settings.GITLAB_TOKEN}@{parsed.netloc}{parsed.path}"
        
        elif provider == "bitbucket" and settings.BITBUCKET_TOKEN:
            # https://x-token-auth:token@bitbucket.org/owner/repo.git
            return f"https://x-token-auth:{settings.BITBUCKET_TOKEN}@{parsed.netloc}{parsed.path}"
        
        return url
    
    def _detect_provider(self, url: str) -> str:
        """Detect Git provider from URL"""
        url_lower = url.lower()
        
        if "github.com" in url_lower:
            return "github"
        elif "gitlab.com" in url_lower or "gitlab" in url_lower:
            return "gitlab"
        elif "bitbucket.org" in url_lower or "bitbucket" in url_lower:
            return "bitbucket"
        else:
            return "unknown"
    
    def _sanitize_scan_id(self, scan_id: str) -> str:
        """Sanitize scan ID for use in path"""
        return re.sub(r'[^a-zA-Z0-9_-]', '_', scan_id)
    
    def _parse_github_url(self, url: str) -> Tuple[str, str]:
        """Parse GitHub URL to extract owner and repo"""
        # Remove .git suffix if present
        url = url.rstrip('/').replace('.git', '')
        parsed = urlparse(url)
        path_parts = parsed.path.strip('/').split('/')
        if len(path_parts) >= 2:
            return path_parts[0], path_parts[1]
        return None, None
    
    def get_github_repo_info(self, url: str) -> Dict:
        """
        Get repository information from GitHub API
        
        Returns:
            Dict with repo info including size, visibility, default_branch, etc.
        """
        owner, repo = self._parse_github_url(url)
        if not owner or not repo:
            return {"error": "Invalid GitHub URL format"}
        
        api_url = f"https://api.github.com/repos/{owner}/{repo}"
        headers = {}
        
        # Add authentication if available
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"
        
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return {
                    "exists": True,
                    "name": data.get("name"),
                    "full_name": data.get("full_name"),
                    "description": data.get("description"),
                    "private": data.get("private"),
                    "size_kb": data.get("size"),  # Size in KB
                    "size_mb": data.get("size", 0) / 1024,  # Size in MB
                    "default_branch": data.get("default_branch"),
                    "language": data.get("language"),
                    "stargazers_count": data.get("stargazers_count"),
                    "forks_count": data.get("forks_count"),
                    "open_issues_count": data.get("open_issues_count"),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "pushed_at": data.get("pushed_at"),
                    "clone_url": data.get("clone_url"),
                    "html_url": data.get("html_url"),
                    "is_accessible": True
                }
            elif response.status_code == 404:
                return {"exists": False, "error": "Repository not found", "is_accessible": False}
            elif response.status_code == 403:
                return {"exists": False, "error": "API rate limit exceeded or authentication required", "is_accessible": False}
            else:
                return {"exists": False, "error": f"GitHub API error: {response.status_code}", "is_accessible": False}
                
        except requests.Timeout:
            return {"exists": False, "error": "GitHub API request timed out", "is_accessible": False}
        except Exception as e:
            return {"exists": False, "error": f"Failed to fetch repo info: {str(e)}", "is_accessible": False}
    
    def check_branch_exists(self, url: str, branch: str) -> Tuple[bool, str]:
        """
        Check if a specific branch exists in the repository
        
        Returns:
            Tuple of (exists, message)
        """
        owner, repo = self._parse_github_url(url)
        if not owner or not repo:
            return False, "Invalid URL format"
        
        api_url = f"https://api.github.com/repos/{owner}/{repo}/branches/{branch}"
        headers = {}
        
        if settings.GITHUB_TOKEN:
            headers["Authorization"] = f"token {settings.GITHUB_TOKEN}"
        
        try:
            response = requests.get(api_url, headers=headers, timeout=10)
            if response.status_code == 200:
                return True, "Branch exists"
            elif response.status_code == 404:
                return False, f"Branch '{branch}' not found in repository"
            else:
                return False, f"Could not verify branch: {response.status_code}"
        except Exception as e:
            return False, f"Error checking branch: {str(e)}"
    
    def check_repo_accessibility(self, url: str, branch: Optional[str] = None) -> Tuple[bool, str, Dict]:
        """
        Check if repository is accessible and get basic info
        
        Returns:
            Tuple of (is_accessible, message, repo_info)
        """
        provider = self._detect_provider(url)
        
        if provider == "github":
            info = self.get_github_repo_info(url)

            if not info.get("exists"):
                error = info.get("error", "Repository not found")
                # 401/rate-limit from GitHub API shouldn't block the scan —
                # the repo may still be publicly cloneable. Fall through.
                if "401" in error or "403" in error or "rate limit" in error.lower() or "timed out" in error.lower():
                    return True, f"GitHub API unavailable ({error}), attempting clone directly", {}
                return False, error, info
            
            if info.get("private") and not settings.GITHUB_TOKEN:
                return False, "Repository is private. Please configure GITHUB_TOKEN in settings.", info
            
            size_mb = info.get("size_mb", 0)
            if size_mb > 500:
                return False, f"Repository is very large ({size_mb:.1f} MB). Consider using ZIP upload for large repositories.", info
            
            # Check if specific branch exists
            default_branch = info.get("default_branch", "master")
            if branch and branch != default_branch:
                branch_exists, branch_msg = self.check_branch_exists(url, branch)
                if not branch_exists:
                    suggested = f" Try using '--branch {default_branch}' instead."
                    return False, f"{branch_msg}.{suggested}", info
            
            message = f"Repository found: {info['full_name']} ({size_mb:.1f} MB, {info['language'] or 'Unknown language'})"
            return True, message, info
        
        elif provider == "gitlab":
            # TODO: Add GitLab API support
            return True, "GitLab repository - skipping pre-check", {}
        
        elif provider == "bitbucket":
            # TODO: Add Bitbucket API support
            return True, "Bitbucket repository - skipping pre-check", {}
        
        else:
            return True, "Unknown provider - attempting direct clone", {}
    
    def clone_repository(
        self,
        url: str,
        scan_id: str,
        branch: Optional[str] = None,
        commit: Optional[str] = None,
        depth: Optional[int] = None
    ) -> Tuple[str, str]:
        """
        Clone a Git repository
        
        Args:
            url: Repository URL
            scan_id: Unique scan identifier
            branch: Branch to checkout (optional)
            commit: Specific commit to checkout (optional)
            depth: Clone depth for shallow clone (optional)
        
        Returns:
            Tuple of (local_path, provider)
        
        Raises:
            git.GitCommandError: If clone fails
        """
        provider = self._detect_provider(url)
        auth_url = self._inject_credentials(url, provider)
        
        # Create target directory
        safe_scan_id = self._sanitize_scan_id(scan_id)
        target_path = os.path.join(self.temp_base, safe_scan_id)
        
        # Clean up if exists
        if os.path.exists(target_path):
            shutil.rmtree(target_path)
        
        os.makedirs(target_path)
        
        # Clone options
        clone_kwargs = {}
        if branch:
            clone_kwargs["branch"] = branch
        if depth:
            clone_kwargs["depth"] = depth
        
        try:
            # Clone repository with timeout
            # Use subprocess with timeout to prevent hanging
            cmd = ["git", "clone", "--single-branch", "--depth", "1"]
            if branch:
                cmd.extend(["--branch", branch])
            cmd.extend([auth_url, target_path])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for very large repos
            )
            
            if result.returncode != 0:
                error_msg = result.stderr.lower() if result.stderr else ""
                stdout_msg = result.stdout.lower() if result.stdout else ""
                combined = error_msg + stdout_msg
                
                if "authentication" in combined or "permission" in combined or "403" in combined:
                    raise GitCommandError(f"Repository access denied. Check if the repository is private and requires authentication.")
                elif "not found" in combined or "404" in combined:
                    raise GitCommandError(f"Repository or branch not found. URL: {url}, Branch: {branch or 'default'}")
                elif "could not resolve" in combined or "unable to access" in combined:
                    raise GitCommandError(f"Network error: Could not reach repository. Check your internet connection.")
                elif "timeout" in combined:
                    raise GitCommandError(f"Repository clone timed out after 5 minutes. The repository may be too large (>100MB) or the connection is slow. Consider scanning a smaller subset or using ZIP upload instead.")
                else:
                    # Show actual error for debugging
                    actual_error = result.stderr or result.stdout or "Unknown error"
                    raise GitCommandError(f"Git clone failed (exit code {result.returncode}): {actual_error}")
            
            repo = Repo(target_path)
            
            # Checkout specific commit if provided
            if commit:
                repo.git.checkout(commit)
            
            # Remove .git directory to save space
            git_dir = os.path.join(target_path, ".git")
            if os.path.exists(git_dir):
                shutil.rmtree(git_dir)
            
            return target_path, provider
            
        except git.GitCommandError as e:
            # Clean up on failure
            if os.path.exists(target_path):
                shutil.rmtree(target_path)
            raise e
    
    def cleanup(self, scan_id: str):
        """Clean up cloned repository"""
        safe_scan_id = self._sanitize_scan_id(scan_id)
        target_path = os.path.join(self.temp_base, safe_scan_id)
        
        if os.path.exists(target_path):
            shutil.rmtree(target_path)
    
    def get_repo_info(self, path: str) -> dict:
        """Get repository information from cloned path"""
        info = {
            "total_files": 0,
            "total_lines": 0,
            "languages": {}
        }
        
        for root, dirs, files in os.walk(path):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip binary files
                if self._is_binary(file_path):
                    continue
                
                # Detect language
                ext = os.path.splitext(file)[1].lower()
                lang = self._get_language_from_ext(ext)
                
                if lang:
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            lines = len(f.readlines())
                            info["total_files"] += 1
                            info["total_lines"] += lines
                            info["languages"][lang] = info["languages"].get(lang, 0) + lines
                    except Exception:
                        pass
        
        return info
    
    def _is_binary(self, file_path: str, chunk_size: int = 1024) -> bool:
        """Check if file is binary"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(chunk_size)
                return b'\0' in chunk
        except Exception:
            return True
    
    def _get_language_from_ext(self, ext: str) -> Optional[str]:
        """Get programming language from file extension"""
        lang_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.jsx': 'JavaScript',
            '.tsx': 'TypeScript',
            '.java': 'Java',
            '.c': 'C',
            '.cpp': 'C++',
            '.cc': 'C++',
            '.h': 'C/C++',
            '.hpp': 'C++',
            '.go': 'Go',
            '.rs': 'Rust',
            '.rb': 'Ruby',
            '.php': 'PHP',
            '.cs': 'C#',
            '.swift': 'Swift',
            '.kt': 'Kotlin',
            '.scala': 'Scala',
            '.r': 'R',
            '.m': 'Objective-C',
            '.mm': 'Objective-C++',
            '.pl': 'Perl',
            '.sh': 'Shell',
            '.sql': 'SQL',
            '.html': 'HTML',
            '.css': 'CSS',
            '.xml': 'XML',
            '.json': 'JSON',
            '.yaml': 'YAML',
            '.yml': 'YAML'
        }
        return lang_map.get(ext)


# Global git handler instance
git_handler = GitHandler()


def get_git_handler() -> GitHandler:
    """Get the global Git handler instance"""
    return git_handler

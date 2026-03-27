"""
AutoPoV Webhook Handler Module
Handles GitHub and GitLab webhooks for auto-triggering scans
"""

import hmac
import hashlib
import json
from typing import Optional, Dict, Any, Callable
from datetime import datetime

from app.config import settings


class WebhookHandler:
    """Handles incoming webhooks from Git providers"""
    
    def __init__(self):
        self.scan_callback: Optional[Callable] = None
    
    def register_scan_callback(self, callback: Callable):
        """Register callback function to trigger scans"""
        self.scan_callback = callback
    
    def verify_github_signature(
        self,
        payload: bytes,
        signature: str
    ) -> bool:
        """
        Verify GitHub webhook signature
        
        Args:
            payload: Raw request body
            signature: X-Hub-Signature-256 header value
        
        Returns:
            True if signature is valid
        """
        if not settings.GITHUB_WEBHOOK_SECRET:
            return False
        
        if not signature.startswith("sha256="):
            return False
        
        expected_signature = hmac.new(
            settings.GITHUB_WEBHOOK_SECRET.encode(),
            payload,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(
            signature[7:],  # Remove "sha256=" prefix
            expected_signature
        )
    
    def verify_gitlab_token(
        self,
        token: str
    ) -> bool:
        """
        Verify GitLab webhook token
        
        Args:
            token: X-Gitlab-Token header value
        
        Returns:
            True if token is valid
        """
        if not settings.GITLAB_WEBHOOK_SECRET:
            return False
        
        return hmac.compare_digest(token, settings.GITLAB_WEBHOOK_SECRET)
    
    def parse_github_event(
        self,
        event_type: str,
        payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Parse GitHub webhook event
        
        Args:
            event_type: X-GitHub-Event header value
            payload: Parsed JSON payload
        
        Returns:
            Event data or None if not a scan-triggering event
        """
        if event_type not in ["push", "pull_request"]:
            return None
        
        result = {
            "provider": "github",
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if event_type == "push":
            # Extract push event data
            repo = payload.get("repository", {})
            result["repo_url"] = repo.get("clone_url")
            result["repo_name"] = repo.get("full_name")
            result["branch"] = payload.get("ref", "").replace("refs/heads/", "")
            result["commit"] = payload.get("after")
            result["pusher"] = payload.get("pusher", {}).get("name")
            
            # Check if we should trigger scan
            if result["commit"] and result["commit"] != "0000000000000000000000000000000000000000":
                result["trigger_scan"] = True
            else:
                result["trigger_scan"] = False
        
        elif event_type == "pull_request":
            # Extract PR event data
            action = payload.get("action")
            if action not in ["opened", "synchronize", "reopened"]:
                return None
            
            pr = payload.get("pull_request", {})
            repo = payload.get("repository", {})
            
            result["repo_url"] = repo.get("clone_url")
            result["repo_name"] = repo.get("full_name")
            result["pr_number"] = pr.get("number") or payload.get("number")
            result["pr_title"] = pr.get("title")
            result["branch"] = pr.get("head", {}).get("ref")
            result["commit"] = pr.get("head", {}).get("sha")
            result["author"] = pr.get("user", {}).get("login")
            result["trigger_scan"] = True
        
        return result
    
    def parse_gitlab_event(
        self,
        event_type: str,
        payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Parse GitLab webhook event
        
        Args:
            event_type: X-Gitlab-Event header value
            payload: Parsed JSON payload
        
        Returns:
            Event data or None if not a scan-triggering event
        """
        # GitLab uses object_kind instead of event type header
        object_kind = payload.get("object_kind")
        
        if object_kind not in ["push", "merge_request"]:
            return None
        
        result = {
            "provider": "gitlab",
            "event_type": object_kind,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if object_kind == "push":
            # Extract push event data
            project = payload.get("project", {})
            result["repo_url"] = project.get("git_http_url") or project.get("http_url")
            result["repo_name"] = project.get("path_with_namespace")
            result["branch"] = payload.get("ref", "").replace("refs/heads/", "")
            result["commit"] = payload.get("after")
            result["pusher"] = payload.get("user_name")
            
            # Check if we should trigger scan
            if result["commit"] and result["commit"] != "0000000000000000000000000000000000000000":
                result["trigger_scan"] = True
            else:
                result["trigger_scan"] = False
        
        elif object_kind == "merge_request":
            # Extract MR event data
            action = payload.get("object_attributes", {}).get("action")
            if action not in ["open", "update", "reopen"]:
                return None
            
            mr = payload.get("object_attributes", {})
            project = payload.get("project", {})
            
            result["repo_url"] = project.get("git_http_url") or project.get("http_url")
            result["repo_name"] = project.get("path_with_namespace")
            result["mr_number"] = mr.get("iid")
            result["mr_title"] = mr.get("title")
            result["branch"] = mr.get("source_branch")
            result["commit"] = mr.get("last_commit", {}).get("id")
            result["author"] = mr.get("author_id")
            result["trigger_scan"] = True
        
        return result
    
    async def handle_github_webhook(
        self,
        signature: str,
        event_type: str,
        payload: bytes
    ) -> Dict[str, Any]:
        """
        Handle GitHub webhook
        
        Args:
            signature: X-Hub-Signature-256 header
            event_type: X-GitHub-Event header
            payload: Raw request body
        
        Returns:
            Response dict with status and message
        """
        # Verify signature
        if not self.verify_github_signature(payload, signature):
            return {
                "status": "error",
                "message": "Invalid signature"
            }
        
        # Parse payload
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": "Invalid JSON payload"
            }
        
        # Parse event
        event_data = self.parse_github_event(event_type, data)
        
        if not event_data:
            return {
                "status": "ignored",
                "message": f"Event type '{event_type}' does not trigger scans"
            }
        
        if not event_data.get("trigger_scan"):
            return {
                "status": "ignored",
                "message": "Event does not require scan"
            }
        
        # Trigger scan if callback registered
        if self.scan_callback and event_data.get("repo_url"):
            scan_id = await self.scan_callback(
                source_type="git",
                source_url=event_data["repo_url"],
                branch=event_data.get("branch"),
                commit=event_data.get("commit"),
                triggered_by=f"github:{event_data.get('pusher') or event_data.get('author')}"
            )
            
            return {
                "status": "success",
                "message": "Scan triggered",
                "scan_id": scan_id,
                "event_data": event_data
            }
        
        return {
            "status": "success",
            "message": "Event processed but no scan callback registered",
            "event_data": event_data
        }
    
    async def handle_gitlab_webhook(
        self,
        token: str,
        event_type: str,
        payload: bytes
    ) -> Dict[str, Any]:
        """
        Handle GitLab webhook
        
        Args:
            token: X-Gitlab-Token header
            event_type: X-Gitlab-Event header
            payload: Raw request body
        
        Returns:
            Response dict with status and message
        """
        # Verify token
        if not self.verify_gitlab_token(token):
            return {
                "status": "error",
                "message": "Invalid token"
            }
        
        # Parse payload
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": "Invalid JSON payload"
            }
        
        # Parse event
        event_data = self.parse_gitlab_event(event_type, data)
        
        if not event_data:
            return {
                "status": "ignored",
                "message": f"Event type '{event_type}' does not trigger scans"
            }
        
        if not event_data.get("trigger_scan"):
            return {
                "status": "ignored",
                "message": "Event does not require scan"
            }
        
        # Trigger scan if callback registered
        if self.scan_callback and event_data.get("repo_url"):
            scan_id = await self.scan_callback(
                source_type="git",
                source_url=event_data["repo_url"],
                branch=event_data.get("branch"),
                commit=event_data.get("commit"),
                triggered_by=f"gitlab:{event_data.get('pusher') or event_data.get('author')}"
            )
            
            return {
                "status": "success",
                "message": "Scan triggered",
                "scan_id": scan_id,
                "event_data": event_data
            }
        
        return {
            "status": "success",
            "message": "Event processed but no scan callback registered",
            "event_data": event_data
        }
    
    def create_callback_payload(
        self,
        scan_id: str,
        status: str,
        findings: list,
        metrics: dict
    ) -> Dict[str, Any]:
        """Create payload for webhook callback"""
        return {
            "scan_id": scan_id,
            "status": status,
            "timestamp": datetime.utcnow().isoformat(),
            "findings_count": len(findings),
            "findings": findings,
            "metrics": metrics
        }


# Global webhook handler instance
webhook_handler = WebhookHandler()


def get_webhook_handler() -> WebhookHandler:
    """Get the global webhook handler instance"""
    return webhook_handler

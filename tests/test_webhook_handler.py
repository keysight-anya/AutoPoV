"""
Tests for webhook handler module
"""

import hashlib
import hmac

import pytest

from app.config import settings
from app.webhook_handler import WebhookHandler


class TestWebhookHandler:
    """Test webhook handling"""

    @pytest.fixture
    def handler(self):
        return WebhookHandler()

    def test_verify_github_signature_valid(self, handler, monkeypatch):
        monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "test_secret")
        payload = b'{"test": "data"}'
        signature = "sha256=" + hmac.new(b"test_secret", payload, hashlib.sha256).hexdigest()
        assert handler.verify_github_signature(payload, signature) is True

    def test_verify_github_signature_invalid(self, handler, monkeypatch):
        monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "test_secret")
        payload = b'{"test": "data"}'
        assert handler.verify_github_signature(payload, "sha256=invalid_signature") is False

    def test_verify_github_signature_no_secret(self, handler, monkeypatch):
        monkeypatch.setattr(settings, "GITHUB_WEBHOOK_SECRET", "")
        payload = b'{"test": "data"}'
        assert handler.verify_github_signature(payload, "sha256=some_signature") is False

    def test_verify_gitlab_token_valid(self, handler, monkeypatch):
        monkeypatch.setattr(settings, "GITLAB_WEBHOOK_SECRET", "test_token")
        assert handler.verify_gitlab_token("test_token") is True

    def test_verify_gitlab_token_invalid(self, handler, monkeypatch):
        monkeypatch.setattr(settings, "GITLAB_WEBHOOK_SECRET", "test_token")
        assert handler.verify_gitlab_token("wrong_token") is False

    def test_parse_github_push_event(self, handler):
        payload = {
            "ref": "refs/heads/main",
            "after": "abc123",
            "repository": {
                "clone_url": "https://github.com/user/repo.git",
                "full_name": "user/repo",
            },
            "pusher": {"name": "testuser"},
        }
        result = handler.parse_github_event("push", payload)
        assert result is not None
        assert result["provider"] == "github"
        assert result["event_type"] == "push"
        assert result["repo_url"] == "https://github.com/user/repo.git"
        assert result["branch"] == "main"
        assert result["trigger_scan"] is True

    def test_parse_github_pr_event(self, handler):
        payload = {
            "action": "opened",
            "number": 1,
            "pull_request": {
                "number": 1,
                "title": "Test PR",
                "head": {"ref": "feature-branch", "sha": "abc123"},
                "user": {"login": "testuser"},
            },
            "repository": {
                "clone_url": "https://github.com/user/repo.git",
                "full_name": "user/repo",
            },
        }
        result = handler.parse_github_event("pull_request", payload)
        assert result is not None
        assert result["provider"] == "github"
        assert result["event_type"] == "pull_request"
        assert result["pr_number"] == 1
        assert result["trigger_scan"] is True

    def test_parse_github_ping_event(self, handler):
        assert handler.parse_github_event("ping", {"zen": "Keep it logically awesome"}) is None

    def test_parse_gitlab_push_event(self, handler):
        payload = {
            "object_kind": "push",
            "ref": "refs/heads/main",
            "after": "abc123",
            "project": {
                "git_http_url": "https://gitlab.com/user/repo.git",
                "path_with_namespace": "user/repo",
            },
            "user_name": "testuser",
        }
        result = handler.parse_gitlab_event("Push Hook", payload)
        assert result is not None
        assert result["provider"] == "gitlab"
        assert result["event_type"] == "push"
        assert result["trigger_scan"] is True

    def test_create_callback_payload(self, handler):
        findings = [
            {"cwe": "CWE-89", "severity": "High"},
            {"cwe": "CWE-119", "severity": "Medium"},
        ]
        metrics = {"detection_rate": 75.0, "fp_rate": 25.0}
        payload = handler.create_callback_payload(
            scan_id="test-scan",
            status="completed",
            findings=findings,
            metrics=metrics,
        )
        assert payload["scan_id"] == "test-scan"
        assert payload["status"] == "completed"
        assert payload["findings_count"] == 2
        assert "timestamp" in payload

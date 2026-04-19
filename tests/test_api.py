"""
Tests for FastAPI endpoints
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app


client = TestClient(app)


class TestHealthEndpoint:
    """Test health check endpoint"""
    
    def test_health_check(self):
        """Test health endpoint returns 200"""
        response = client.get("/api/health")
        assert response.status_code == 200
        
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data


class TestScanEndpoints:
    """Test scan endpoints (requires auth)"""
    
    def test_scan_without_auth(self):
        """Test scan requires authentication"""
        response = client.post("/api/scan/git", json={
            "url": "https://github.com/test/repo.git"
        })
        assert response.status_code == 403  # Forbidden without auth
    
    def test_get_scan_without_auth(self):
        """Test get scan requires authentication"""
        response = client.get("/api/scan/test-id")
        assert response.status_code == 403

    def test_list_benchmarks_without_auth(self):
        """Test benchmark listing requires authentication"""
        response = client.get("/api/benchmarks")
        assert response.status_code == 403

    def test_install_benchmark_without_auth(self):
        """Test benchmark install requires authentication"""
        response = client.post("/api/benchmarks/juliet-dynamic/install")
        assert response.status_code == 403

    def test_benchmark_scan_without_auth(self):
        """Test benchmark scan requires authentication"""
        response = client.post("/api/scan/benchmark", json={
            "manifest_path": "/tmp/example-manifest.json"
        })
        assert response.status_code == 403


class TestWebhookEndpoints:
    """Test webhook endpoints"""
    
    def test_github_webhook_no_signature(self):
        """Test GitHub webhook without signature fails"""
        response = client.post("/api/webhook/github", data=b"{}")
        assert response.status_code == 200  # Returns error in body
        
        data = response.json()
        assert data["status"] == "error"
    
    def test_gitlab_webhook_no_token(self):
        """Test GitLab webhook without token fails"""
        response = client.post("/api/webhook/gitlab", data=b"{}")
        assert response.status_code == 200  # Returns error in body
        
        data = response.json()
        assert data["status"] == "error"

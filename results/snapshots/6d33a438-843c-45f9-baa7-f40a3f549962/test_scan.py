#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/user/AutoPoV/autopov')

import requests

API_KEY = "apov_yOBQlf4t_RXfIIDaTKQ51MgPbGbBx_aCJbCs6cORNXw"
BASE_URL = "http://localhost:8000/api"

headers = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Test health endpoint
print("Testing health endpoint...")
try:
    response = requests.get(f"{BASE_URL}/health", timeout=5)
    print(f"Health: {response.status_code} - {response.text}")
except Exception as e:
    print(f"Health check failed: {e}")

# Test scan git endpoint
print("\nTesting scan/git endpoint...")
scan_data = {
    "url": "https://github.com/AnyaChima1/mary-chima-wedding",
    "branch": "main",
    "model": "anthropic/claude-3.5-sonnet",
    "cwes": ["CWE-89", "CWE-119", "CWE-190", "CWE-416"]
}

try:
    response = requests.post(f"{BASE_URL}/scan/git", json=scan_data, headers=headers, timeout=10)
    print(f"Scan response: {response.status_code}")
    print(f"Response body: {response.text}")
except Exception as e:
    print(f"Scan request failed: {e}")

#!/usr/bin/env python3
"""Test script to verify hierarchical LLM configuration."""

import requests
import json

# Try to get config without auth first
try:
    response = requests.get("http://localhost:8000/api/health", timeout=5)
    print(f"Health check: {response.status_code}")
    print(json.dumps(response.json(), indent=2))
except Exception as e:
    print(f"Health check failed: {e}")

# Try config endpoint
try:
    response = requests.get("http://localhost:8000/api/config", timeout=5)
    print(f"\nConfig endpoint: {response.status_code}")
    if response.status_code == 200:
        print(json.dumps(response.json(), indent=2))
    else:
        print(response.text)
except Exception as e:
    print(f"Config check failed: {e}")

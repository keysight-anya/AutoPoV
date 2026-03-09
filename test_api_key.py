#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/user/AutoPoV/autopov')

import requests

BASE_URL = "http://localhost:8000/api"

# Test different API keys
api_keys_to_test = [
    "apov_yOBQlf4t_RXfIIDaTKQ51MgPbGbBx_aCJbCs6cORNXw",
    # Add any other keys the user might have
]

for api_key in api_keys_to_test:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/scan/git", 
            json={"url": "https://github.com/AnyaChima1/mary-chima-wedding", "branch": "main"},
            headers=headers, timeout=5)
        print(f"Key {api_key[:20]}...: Status {response.status_code}")
        if response.status_code == 200:
            print(f"  SUCCESS: {response.json()}")
        else:
            print(f"  FAILED: {response.text}")
    except Exception as e:
        print(f"Key {api_key[:20]}...: ERROR - {e}")

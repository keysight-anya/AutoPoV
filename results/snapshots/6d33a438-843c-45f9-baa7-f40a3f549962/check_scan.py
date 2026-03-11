#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/user/AutoPoV/autopov')

import requests

API_KEY = "apov_yOBQlf4t_RXfIIDaTKQ51MgPbGbBx_aCJbCs6cORNXw"
BASE_URL = "http://localhost:8000/api"

scan_id = "99561b87-ec97-4a82-8454-e03a4884d327"

headers = {"Authorization": f"Bearer {API_KEY}"}
response = requests.get(f"{BASE_URL}/scan/{scan_id}", headers=headers)
print(f"Status Code: {response.status_code}")
print(f"Response: {response.json()}")

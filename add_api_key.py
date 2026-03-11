#!/usr/bin/env python3
"""Add a new API key to the system"""

import hashlib
import json
import os
from datetime import datetime

# Generate a new key
key_id = "user_key_2024"
api_key = "apv_user_key_for_testing_12345"

# Calculate hash (same method as backend)
key_hash = hashlib.sha256(api_key.encode()).hexdigest()

# Load existing keys
keys_file = "/home/user/AutoPoV/data/api_keys.json"
with open(keys_file, 'r') as f:
    data = json.load(f)

# Add new key
data[key_id] = {
    "key_id": key_id,
    "key_hash": key_hash,
    "name": "user",
    "created_at": datetime.utcnow().isoformat(),
    "last_used": None,
    "is_active": True
}

# Save back
with open(keys_file, 'w') as f:
    json.dump(data, f, indent=2)

print(f"Added new API key: {api_key}")
print(f"Key ID: {key_id}")
print(f"Hash: {key_hash}")

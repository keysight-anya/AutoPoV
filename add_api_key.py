#!/usr/bin/env python3
"""Add a new API key to the system"""

import hashlib
import json
import os
import secrets
from datetime import datetime

# Generate a cryptographically random key
key_id = f"batch_{secrets.token_urlsafe(8)}"
api_key = f"apov_{secrets.token_urlsafe(32)}"

# Calculate hash (same method as backend)
key_hash = hashlib.sha256(api_key.encode()).hexdigest()

# Load existing keys — resolve path relative to this script
keys_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "api_keys.json")
with open(keys_file, 'r') as f:
    data = json.load(f)

# Add new key
data[key_id] = {
    "key_id": key_id,
    "key_hash": key_hash,
    "name": "batch",
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

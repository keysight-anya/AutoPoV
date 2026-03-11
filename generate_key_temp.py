#!/usr/bin/env python3
"""Temporary script to generate API key"""

import sys
sys.path.insert(0, '/home/user/AutoPoV')

from app.auth import get_api_key_manager

# Generate a new key
key = get_api_key_manager().generate_key("user_key")
print(f"Generated API Key: {key}")

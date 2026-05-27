#!/usr/bin/env python3
import sys
sys.path.insert(0, '/home/user/AutoPoV/autopov')

from app.auth import get_api_key_manager

api_key = get_api_key_manager().generate_key("frontend")
print(api_key)

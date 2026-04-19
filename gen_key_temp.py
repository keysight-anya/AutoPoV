import sys
sys.path.insert(0, '/app')
from app.auth import get_api_key_manager
key = get_api_key_manager().generate_key("admin")
print(key)

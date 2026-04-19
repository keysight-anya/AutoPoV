import hashlib, json, os

KEY_FILE = "/home/olumba/AutoPoV/data/api_keys.json"
RAW_KEY  = "apov_7ZcziTB7veZ2eUxSvmLdm1NHRlvGD0s9Js5ji6xI8PU"
KEY_ID   = "user_provided_admin"
KEY_NAME = "admin-user"

key_hash = hashlib.sha256(RAW_KEY.encode()).hexdigest()

with open(KEY_FILE) as f:
    data = json.load(f)

data[KEY_ID] = {
    "key_id": KEY_ID,
    "key_hash": key_hash,
    "name": KEY_NAME,
    "created_at": "2026-04-15T00:00:00",
    "last_used": None,
    "is_active": True
}

with open(KEY_FILE, "w") as f:
    json.dump(data, f, indent=2)

with open("/home/olumba/AutoPoV/register_key_result.txt", "w") as f:
    f.write(f"Registered key_id={KEY_ID} hash={key_hash}\n")

print(f"Done. key_id={KEY_ID}, hash={key_hash}")

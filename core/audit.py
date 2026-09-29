import hashlib
import json
import os
from datetime import datetime
from typing import Any, Dict

LOG_PATH = os.path.join(os.getcwd(), "audit.log")

def _last_hash() -> str:
    if not os.path.exists(LOG_PATH):
        return "0" * 64
    try:
        with open(LOG_PATH, "rb") as f:
            lines = f.read().splitlines()
            if not lines:
                return "0" * 64
            last = lines[-1]
            try:
                rec = json.loads(last.decode())
                return rec.get("hash", "0" * 64)
            except Exception:
                return "0" * 64
    except Exception:
        return "0" * 64

def _compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode())
    h.update(json.dumps(payload, sort_keys=True).encode())
    return h.hexdigest()

def log_action(user_id: str, action: str, data: dict[str, Any]):
    ts = datetime.utcnow().isoformat()
    prev = _last_hash()
    payload = {"ts": ts, "user_id": user_id, "action": action, "data": data}
    cur = _compute_hash(prev, payload)
    record = {"prev_hash": prev, "hash": cur, **payload}
    try:
        with open(LOG_PATH, "ab") as f:
            f.write(json.dumps(record).encode() + b"\n")
    except Exception:
        pass

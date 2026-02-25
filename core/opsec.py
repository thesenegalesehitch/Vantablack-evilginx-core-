import ipaddress
import os
from typing import List, Optional

import httpx
from typing import Any

from .config import settings

def _ua_patterns() -> List[str]:
    patterns = settings.OPSEC_BLOCKLIST_UA or []
    # Fallback defaults if not provided
    if not patterns:
        patterns = [
            "curl",
            "python-requests",
            "masscan",
            "nmap",
            "sqlmap",
            "wget",
            "nikto",
            "nessus",
            "openvas",
        ]
    return [p.lower() for p in patterns]

def is_bad_ua(ua: Optional[str]) -> bool:
    if not ua:
        return False
    ual = ua.lower()
    for p in _ua_patterns():
        if p in ual:
            return True
    return False

def is_private_or_reserved_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except Exception:
        return False

def reputation_blocks(ip: str) -> bool:
    endpoint = settings.OPSEC_REPUTATION_ENDPOINT.strip()
    api_key = settings.OPSEC_REPUTATION_API_KEY.strip()
    if not endpoint or not settings.OPSEC_ENABLE:
        return False
    try:
        with httpx.Client(timeout=2.0) as client:
            r = client.get(endpoint, params={"ip": ip, "key": api_key})
            if r.status_code == 200:
                data = r.json()
                # Expect data like {"malicious": true} or a risk score
                if isinstance(data, dict):
                    if data.get("malicious") is True:
                        return True
                    risk = data.get("risk", 0)
                    return risk >= 80
    except Exception:
        return False
    return False

def should_block(request: Any) -> bool:
    if not settings.OPSEC_ENABLE:
        return False
    ip = request.client.host if request.client else ""
    ua = request.headers.get("user-agent", "")
    # Basic heuristics
    if is_bad_ua(ua):
        return True
    if is_private_or_reserved_ip(ip):
        # Allow local dev by env override
        if os.getenv("OPSEC_ALLOW_LOCAL") != "1":
            return True
    if reputation_blocks(ip):
        return True
    return False

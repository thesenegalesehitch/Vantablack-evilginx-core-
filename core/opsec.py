import ipaddress
import os
from typing import Any, List, Optional

import httpx

from .config import settings


def _ua_patterns() -> list[str]:
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

def is_bad_ua(ua: str | None) -> bool:
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
    return bool(reputation_blocks(ip))


class OPSECVerifier:
    """Vérificateur OPSEC côté opérateur (avant/pendant une campagne).

    Contrairement à ``should_block`` (qui protège l'infra d'attaque contre
    les scanners), ``OPSECVerifier`` est l'outil **offensif** : il évalue
    si une configuration d'engagement (UA, IP de sortie, headers) est
    furtive ou susceptible de déclencher des alertes côté défense.
    """

    DEFAULT_FLAGS = {
        "curl": "UA scanner/script connu",
        "python-requests": "UA python générique détectable",
        "python-httpx": "UA httpx générique détectable",
        "wget": "UA wget générique",
        "nmap": "UA scanner actif",
        "sqlmap": "UA injection automatisée",
        "nikto": "UA scanner web",
    }

    def __init__(self, *, extra_flags: Optional[dict[str, str]] = None) -> None:
        self._flags: dict[str, str] = dict(self.DEFAULT_FLAGS)
        if extra_flags:
            self._flags.update(extra_flags)

    # ------------------------------------------------------------------
    # Évaluation d'un User-Agent
    # ------------------------------------------------------------------
    def check_user_agent(self, ua: str | None) -> dict[str, Any]:
        """Retourne {'safe': bool, 'reasons': [...]} pour un User-Agent."""
        reasons = [desc for pat, desc in self._flags.items()
                   if ua and pat in ua.lower()]
        return {"safe": not reasons, "reasons": reasons}

    # ------------------------------------------------------------------
    # Évaluation d'une IP de sortie
    # ------------------------------------------------------------------
    def check_egress_ip(self, ip: str) -> dict[str, Any]:
        """Retourne {'safe': bool, 'reasons': [...]} pour une IP de sortie."""
        reasons: list[str] = []
        if is_private_or_reserved_ip(ip):
            reasons.append("IP privée/réservée : impossible en sortie WAN réelle")
        if reputation_blocks(ip):
            reasons.append("IP signalée par le service de réputation")
        return {"safe": not reasons, "reasons": reasons}

    # ------------------------------------------------------------------
    # Audit global d'une configuration d'engagement
    # ------------------------------------------------------------------
    def verify(self, *, user_agent: str | None = None, egress_ip: str = "",
               headers: Optional[dict[str, str]] = None) -> dict[str, Any]:
        """Audit OPSEC complet : UA + IP + headers. Score 0-100."""
        headers = headers or {}
        findings: list[str] = []

        if user_agent:
            ua_res = self.check_user_agent(user_agent)
            findings.extend(ua_res["reasons"])
        if egress_ip:
            ip_res = self.check_egress_ip(egress_ip)
            findings.extend(ip_res["reasons"])

        suspicious_headers = {
            "x-forwarded-for": "Header XFF présent : trace du client réel",
            "via": "Header Via présent : proxy intermédiaire exposé",
            "x-real-ip": "Header X-Real-IP présent : IP client exposée",
        }
        for h, why in suspicious_headers.items():
            if h in {k.lower() for k in headers}:
                findings.append(why)

        score = max(0, 100 - 20 * len(findings))
        return {
            "score": score,
            "verdict": "PASS" if score >= 80 else ("WARN" if score >= 50 else "FAIL"),
            "findings": findings,
        }

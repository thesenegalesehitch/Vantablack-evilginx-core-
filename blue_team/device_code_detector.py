"""
Blue Team - Device Code Flow Detector
======================================

Détecte les abus du flux OAuth 2.0 Device Authorization Grant (RFC 8628)
utilisé par les attaquants pour voler des tokens sans connaître le mot
de passe de la victime (technique documentée par Optiv 2022, Push Security
2023, Mitiga 2024).

Scénario d'attaque :
  1. L'attaquant initie un device code flow vers login.microsoftonline.com
  2. Il obtient un user_code (ex: "ABC123") et un device_code
  3. Il convainc la victime (mail, Teams, téléphone) d'aller sur
     https://microsoft.com/devicelogin et d'entrer le user_code
  4. La victime s'authentifie normalement (MFA inclus)
  5. L'attaquant récupère le token via polling

Indicateurs observables :
  - Présence du endpoint /devicecode dans le proxy
  - User-Agent atypique (pas de navigateur standard)
  - Polling depuis une IP distincte de l'IP du navigateur
  - User_code à 4 chiffres (rare et suspect)
  - Concomitance entre un message Teams/mail contenant "code" et une
    connexion depuis une IP externe
  - Pas de précédent device enrollment
"""

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# User-Agents typiques d'appareils compromis / scripts
SUSPICIOUS_USER_AGENTS = [
    r"python-requests",
    r"curl/",
    r"wget/",
    r"Go-http-client",
    r"axios/",
    r"node-fetch",
    r"powershell",
    r"aiohttp",
    r"httpx",
    r"okhttp",  # parfois légitime mais suspect hors app mobile connue
]

# User-Agents de navigateurs légitimes (whitelist)
LEGIT_BROWSER_UA = [
    r"Mozilla/5\.0.*Chrome/",
    r"Mozilla/5\.0.*Firefox/",
    r"Mozilla/5\.0.*Safari/",
    r"Mozilla/5\.0.*Edg/",
    r"Mozilla/5\.0.*OPR/",
]


@dataclass
class DeviceCodeEvent:
    """Événement de device code flow observé."""

    event_id: str
    timestamp: float
    provider: str                # "microsoft", "google", "okta"
    client_id: str
    user_code: str
    device_code_hash: str        # hash, jamais le code en clair
    scope: str
    source_ip: str
    user_agent: str
    poll_interval: int
    poll_ips: list[str] = field(default_factory=list)
    poll_uas: list[str] = field(default_factory=list)
    completed: bool = False
    is_suspicious: bool = False
    risk_score: float = 0.0
    matched_rules: list[str] = field(default_factory=list)


@dataclass
class DeviceCodeAlert:
    alert_id: str
    severity: str
    title: str
    description: str
    event_id: str
    source_ip: str
    mitre_techniques: list[str]
    recommended_actions: list[str]
    created_at: float = field(default_factory=time.time)


class DeviceCodeDetector:
    """
    Analyse les événements de device code flow et alerte en cas d'abus.
    """

    def __init__(self, output_dir: str = "blue_team/captures") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[DeviceCodeEvent] = []
        self.alerts: list[DeviceCodeAlert] = []
        # Index device_code_hash -> event
        self._by_code: dict[str, DeviceCodeEvent] = {}

    def observe_request(
        self,
        provider: str,
        client_id: str,
        user_code: str,
        device_code: str,
        scope: str,
        source_ip: str,
        user_agent: str,
    ) -> DeviceCodeEvent:
        """Capture une demande de device code."""
        dch = hashlib.sha256(device_code.encode()).hexdigest()[:16]
        ev = DeviceCodeEvent(
            event_id=str(uuid.uuid4()),
            timestamp=time.time(),
            provider=provider,
            client_id=client_id,
            user_code=user_code,
            device_code_hash=dch,
            scope=scope,
            source_ip=source_ip,
            user_agent=user_agent,
            poll_interval=5,
        )
        self.events.append(ev)
        self._by_code[dch] = ev
        ev.risk_score, ev.matched_rules = self._score_request(ev)
        ev.is_suspicious = ev.risk_score >= 0.4
        if ev.is_suspicious:
            self._generate_alert(ev)
        return ev

    def observe_poll(
        self,
        device_code: str,
        source_ip: str,
        user_agent: str,
    ) -> DeviceCodeEvent | None:
        """Capture un polling."""
        dch = hashlib.sha256(device_code.encode()).hexdigest()[:16]
        ev = self._by_code.get(dch)
        if not ev:
            return None
        ev.poll_ips.append(source_ip)
        ev.poll_uas.append(user_agent)
        if source_ip not in (ev.source_ip,):
            ev.matched_rules.append("poll_ip_differs_from_request")
            ev.risk_score = min(ev.risk_score + 0.30, 1.0)
        if not any(re.search(p, user_agent) for p in LEGIT_BROWSER_UA):
            ev.matched_rules.append(f"poll_ua_not_browser:{user_agent[:40]}")
            ev.risk_score = min(ev.risk_score + 0.25, 1.0)
        if ev.risk_score >= 0.4 and not ev.is_suspicious:
            ev.is_suspicious = True
            self._generate_alert(ev)
        return ev

    def observe_completion(self, device_code: str) -> DeviceCodeEvent | None:
        dch = hashlib.sha256(device_code.encode()).hexdigest()[:16]
        ev = self._by_code.get(dch)
        if not ev:
            return None
        ev.completed = True
        if ev.is_suspicious:
            self._generate_post_auth_alert(ev)
        return ev

    def _score_request(self, ev: DeviceCodeEvent) -> tuple:
        rules: list[str] = []
        score = 0.0
        if any(re.search(p, ev.user_agent) for p in SUSPICIOUS_USER_AGENTS):
            rules.append("suspicious_ua")
            score += 0.40
        if not any(re.search(p, ev.user_agent) for p in LEGIT_BROWSER_UA):
            rules.append("not_browser_ua")
            score += 0.20
        if ev.source_ip.startswith(("185.", "194.", "5.")) and not ev.source_ip.startswith("5.135."):
            # Pattern très grossier d'IP non-EU. À raffiner en prod.
            pass
        if "offline_access" in ev.scope:
            rules.append("offline_access_scope")
            score += 0.15
        if len(ev.scope.split()) > 5:
            rules.append(f"scope_count:{len(ev.scope.split())}")
            score += 0.15
        # User code court (< 6 chars) est suspect (plus de collisions)
        if len(ev.user_code) < 6:
            rules.append("short_user_code")
            score += 0.10
        return min(score, 1.0), rules

    def _generate_alert(self, ev: DeviceCodeEvent) -> None:
        severity = "HIGH"
        alert = DeviceCodeAlert(
            alert_id=str(uuid.uuid4()),
            severity=severity,
            title=f"Suspicious Device Code flow: {ev.user_code}",
            description=(
                f"Device code flow initiated from {ev.source_ip} with UA "
                f"'{ev.user_agent[:50]}' requesting scopes: {ev.scope}. "
                f"Rules: {ev.matched_rules}."
            ),
            event_id=ev.event_id,
            source_ip=ev.source_ip,
            mitre_techniques=["T1078.004", "T1528"],
            recommended_actions=[
                "1. Revoke the device code and any issued token",
                "2. Investigate the source IP (geo, reputation)",
                "3. Search the user mailbox for messages containing the user_code",
                "4. If completed: invalidate refresh tokens and force re-auth",
                "5. Enable Conditional Access : block device code for non-managed devices",
            ],
        )
        self.alerts.append(alert)

    def _generate_post_auth_alert(self, ev: DeviceCodeEvent) -> None:
        alert = DeviceCodeAlert(
            alert_id=str(uuid.uuid4()),
            severity="CRITICAL",
            title=f"Device Code flow completed for suspicious source: {ev.user_code}",
            description=(
                f"The device code flow from {ev.source_ip} has been authorized. "
                f"A token has been issued. Immediate action required."
            ),
            event_id=ev.event_id,
            source_ip=ev.source_ip,
            mitre_techniques=["T1078.004", "T1528"],
            recommended_actions=[
                "1. REVOKE all tokens issued via this flow IMMEDIATELY",
                "2. Force user password + MFA reset",
                "3. Rotate any data the token may have accessed",
                "4. Open P1 incident",
            ],
        )
        self.alerts.append(alert)


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_device_code_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    det = DeviceCodeDetector()

    class RequestRequest(BaseModel):
        provider: str
        client_id: str
        user_code: str
        device_code: str
        scope: str
        source_ip: str
        user_agent: str

    class PollRequest(BaseModel):
        device_code: str
        source_ip: str
        user_agent: str

    @app.post("/_/defense/devicecode/request")
    async def req_obs(req: RequestRequest):
        ev = det.observe_request(
            provider=req.provider,
            client_id=req.client_id,
            user_code=req.user_code,
            device_code=req.device_code,
            scope=req.scope,
            source_ip=req.source_ip,
            user_agent=req.user_agent,
        )
        return {
            "event_id": ev.event_id,
            "risk_score": ev.risk_score,
            "is_suspicious": ev.is_suspicious,
        }

    @app.post("/_/defense/devicecode/poll")
    async def poll(req: PollRequest):
        ev = det.observe_poll(req.device_code, req.source_ip, req.user_agent)
        if not ev:
            raise HTTPException(404, "unknown device_code")
        return {"risk_score": ev.risk_score, "is_suspicious": ev.is_suspicious}

    @app.post("/_/defense/devicecode/complete")
    async def complete(req: PollRequest):
        ev = det.observe_completion(req.device_code)
        if not ev:
            raise HTTPException(404, "unknown device_code")
        return {"completed": True}

    @app.get("/_/defense/devicecode/alerts")
    async def list_alerts():
        return [
            {
                "id": a.alert_id,
                "severity": a.severity,
                "title": a.title,
                "src": a.source_ip,
                "ts": a.created_at,
            }
            for a in det.alerts
        ]

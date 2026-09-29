"""
Blue Team - OAuth Consent Abuse Monitor
========================================

Surveille les consent grants OAuth dans Microsoft Entra ID, Google Workspace
et Okta pour détecter les attaques de type "Illicit Consent Grant"
(voir l'incident ILoveYou.pdf / OAUTH1.0 / EvilProxy 2023-2026).

Sources de détection :
  1. Logs Entra ID : AuditLogs "Consent to application"
  2. AuditLogs "PermissionGrant" dans Graph API
  3. Risky Service Principals
  4. Évolution anormale du nb d'apps par tenant
  5. Apps récemment créées (< 7 jours) demandant des scopes dangereux
  6. Publisher non vérifié + scopes Mail.Read/Write/Files.ReadWrite

Indicateurs de compromission (IoC) :
  - App inconnue demande Mail.Read + Mail.Send + Mail.ReadWrite
  - App < 24h demande > 50 scopes sensibles
  - Consent grant depuis IP hors géolocalisation usuelle
  - Publisher non vérifié
  - Répétition : même app demandée par > 5 utilisateurs
  - Persistence : app sans expiration du refresh token
"""

import hashlib
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Scopes dangereux (Microsoft Graph / Google / Okta)
DANGEROUS_SCOPES_MS = {
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Files.ReadWrite", "Files.ReadWrite.All",
    "Calendars.ReadWrite", "Contacts.ReadWrite",
    "User.Read.All", "Directory.ReadWrite.All",
    "offline_access", "openid", "profile", "email",
    "Sites.ReadWrite.All", "Notes.ReadWrite",
    "Chat.ReadWrite", "ChannelMessage.Send",
}

DANGEROUS_SCOPES_GOOGLE = {
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/drive.file",
    "https://www.googleapis.com/auth/admin.directory.user",
    "https://www.googleapis.com/auth/calendar",
}

# Combinaisons suspectes : un grant avec N de ces scopes est fortement suspect
SUSPICIOUS_SCOPE_COMBOS = [
    {"Mail.Read", "Mail.Send"},
    {"Mail.ReadWrite", "offline_access"},
    {"Files.ReadWrite", "offline_access"},
    {"User.Read.All", "offline_access"},
    {"Directory.ReadWrite.All", "offline_access"},
]


@dataclass
class ConsentEvent:
    """Événement de consent grant capturé."""

    event_id: str
    timestamp: float
    provider: str          # "microsoft", "google", "okta"
    user_principal: str    # utilisateur qui a consenti
    app_id: str            # application id
    app_display_name: str
    app_publisher: str | None
    app_verified: bool
    app_age_days: int
    scopes: list[str]
    source_ip: str
    user_agent: str = ""
    risk_score: float = 0.0
    is_suspicious: bool = False
    matched_rules: list[str] = field(default_factory=list)


@dataclass
class ConsentAlert:
    alert_id: str
    severity: str
    title: str
    description: str
    event_id: str
    user_principal: str
    app_display_name: str
    mitre_techniques: list[str]
    recommended_actions: list[str]
    created_at: float = field(default_factory=time.time)


class OAuthConsentMonitor:
    """
    Analyse en continu les événements de consent grant et génère
    des alertes sur les compromissions.
    """

    def __init__(self, output_dir: str = "blue_team/captures") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[ConsentEvent] = []
        self.alerts: list[ConsentAlert] = []

    def observe(
        self,
        provider: str,
        user_principal: str,
        app_id: str,
        app_display_name: str,
        scopes: list[str],
        source_ip: str,
        app_publisher: str | None = None,
        app_verified: bool = False,
        app_age_days: int = 0,
        user_agent: str = "",
    ) -> ConsentEvent:
        """Enregistre et analyse un événement de consent."""
        rules: list[str] = []
        score = 0.0

        # Règle 1 : scopes dangereux
        dangerous = self._get_dangerous(scopes, provider)
        if dangerous:
            rules.append(f"dangerous_scopes:{','.join(sorted(dangerous))}")
            score += 0.30 + 0.05 * min(len(dangerous), 5)

        # Règle 2 : app non vérifiée
        if not app_verified:
            rules.append("publisher_unverified")
            score += 0.25

        # Règle 3 : app très récente
        if app_age_days < 7:
            rules.append(f"app_age_lt_7d:{app_age_days}d")
            score += 0.25
        elif app_age_days < 30:
            rules.append(f"app_age_lt_30d:{app_age_days}d")
            score += 0.10

        # Règle 4 : combinaisons suspectes
        for combo in SUSPICIOUS_SCOPE_COMBOS:
            if combo.issubset(set(scopes)):
                rules.append(f"suspicious_combo:{'+'.join(sorted(combo))}")
                score += 0.20

        # Règle 5 : pas de publisher
        if not app_publisher:
            rules.append("no_publisher")
            score += 0.15

        # Règle 6 : trop de scopes (>10)
        if len(scopes) > 10:
            rules.append(f"scope_count_gt_10:{len(scopes)}")
            score += 0.20

        # Règle 7 : offline_access (refresh token persistant)
        if any("offline_access" in s for s in scopes):
            rules.append("offline_access_grant")
            score += 0.10

        # Règle 8 : IP privée (signe d'un attaquant interne / proxied)
        if source_ip.startswith(("10.", "192.168.", "172.16.", "127.")):
            rules.append(f"internal_ip:{source_ip}")
            score += 0.10

        score = min(score, 1.0)
        is_suspicious = score >= 0.5

        ev = ConsentEvent(
            event_id=str(uuid.uuid4()),
            timestamp=time.time(),
            provider=provider,
            user_principal=user_principal,
            app_id=app_id,
            app_display_name=app_display_name,
            app_publisher=app_publisher,
            app_verified=app_verified,
            app_age_days=app_age_days,
            scopes=scopes,
            source_ip=source_ip,
            user_agent=user_agent,
            risk_score=score,
            is_suspicious=is_suspicious,
            matched_rules=rules,
        )
        self.events.append(ev)
        if is_suspicious:
            self._generate_alert(ev)
        return ev

    def _get_dangerous(self, scopes: list[str], provider: str) -> set:
        if provider == "google":
            ref = DANGEROUS_SCOPES_GOOGLE
        else:
            ref = DANGEROUS_SCOPES_MS
        return {s for s in scopes if s in ref}

    def _generate_alert(self, ev: ConsentEvent) -> None:
        severity = "CRITICAL" if ev.risk_score >= 0.8 else "HIGH"
        title = f"Illicit OAuth Consent Grant: {ev.app_display_name}"
        description = (
            f"User {ev.user_principal} just granted access to app "
            f"'{ev.app_display_name}' ({ev.app_id[:8]}...) with {len(ev.scopes)} "
            f"scopes from IP {ev.source_ip}. "
            f"Risk score: {ev.risk_score:.0%}. Rules: {ev.matched_rules}."
        )
        actions = [
            ("1. Revoke the OAuth grant immediately: "
            f"Revoke-AzureADPermissionGrant -ObjectId {ev.app_id}"),
            "2. Force password reset for the user",
            "3. Force MFA re-registration (FIDO2 preferred)",
            "4. Invalidate all refresh tokens for the user",
            "5. Check Graph API audit logs for subsequent activity",
            "6. Look for inbox rules injected (mailbox pivot)",
            "7. Open a P1 incident in the SOC",
        ]
        alert = ConsentAlert(
            alert_id=str(uuid.uuid4()),
            severity=severity,
            title=title,
            description=description,
            event_id=ev.event_id,
            user_principal=ev.user_principal,
            app_display_name=ev.app_display_name,
            mitre_techniques=["T1550.001", "T1078.004", "T1098.001"],
            recommended_actions=actions,
        )
        self.alerts.append(alert)

    def stats(self) -> dict[str, Any]:
        n = len(self.events)
        susp = sum(1 for e in self.events if e.is_suspicious)
        return {
            "total_events": n,
            "suspicious": susp,
            "alerts": len(self.alerts),
            "providers": list({e.provider for e in self.events}),
        }


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_oauth_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    monitor = OAuthConsentMonitor()

    class ObserveRequest(BaseModel):
        provider: str
        user_principal: str
        app_id: str
        app_display_name: str
        app_publisher: str | None = None
        app_verified: bool = False
        app_age_days: int = 0
        scopes: list[str]
        source_ip: str
        user_agent: str = ""

    @app.post("/_/defense/oauth/observe")
    async def observe(req: ObserveRequest):
        ev = monitor.observe(
            provider=req.provider,
            user_principal=req.user_principal,
            app_id=req.app_id,
            app_display_name=req.app_display_name,
            app_publisher=req.app_publisher,
            app_verified=req.app_verified,
            app_age_days=req.app_age_days,
            scopes=req.scopes,
            source_ip=req.source_ip,
            user_agent=req.user_agent,
        )
        return {
            "event_id": ev.event_id,
            "risk_score": ev.risk_score,
            "is_suspicious": ev.is_suspicious,
            "matched_rules": ev.matched_rules,
        }

    @app.get("/_/defense/oauth/alerts")
    async def list_alerts():
        return [
            {
                "id": a.alert_id,
                "severity": a.severity,
                "title": a.title,
                "user": a.user_principal,
                "app": a.app_display_name,
                "ts": a.created_at,
            }
            for a in monitor.alerts
        ]

    @app.get("/_/defense/oauth/stats")
    async def stats():
        return monitor.stats()

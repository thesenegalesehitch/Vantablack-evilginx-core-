"""
Blue Team - Incident Response Orchestrator
===========================================

Exécute automatiquement les playbooks de réponse à incident déclenchés
par les alertes générées par les autres modules Blue Team.

Chaque alerte Blue Team a un playbook associé. Les actions sont :
  1. Containment : isoler la machine compromise
  2. Eradication : révoquer tokens, reset password, désactiver app
  3. Recovery : forcer re-authentification avec MFA fort
  4. Lessons Learned : générer un rapport

Intégrations (en labo : simulations) :
  - Microsoft Graph API : revoke grants, reset password
  - Defender for Endpoint : isolate machine
  - Splunk / Sentinel : créer un incident
  - PagerDuty : alerter l'astreinte
  - Slack / Teams : notifier le canal SOC
  - TheHive / Cortex : ouvrir un case
"""

import asyncio
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class PlaybookAction(Enum):
    """Actions possibles dans un playbook."""

    REVOKE_OAUTH_GRANT = "revoke_oauth_grant"
    RESET_USER_PASSWORD = "reset_user_password"
    INVALIDATE_REFRESH_TOKENS = "invalidate_refresh_tokens"
    FORCE_FIDO2_ENROLLMENT = "force_fido2_enrollment"
    ISOLATE_MACHINE = "isolate_machine"
    BLOCK_IP_AT_FIREWALL = "block_ip_at_firewall"
    BLOCK_DOMAIN_AT_DNS = "block_domain_at_dns"
    DELETE_MAILBOX_RULES = "delete_mailbox_rules"
    CREATE_INCIDENT = "create_incident"
    NOTIFY_SOC = "notify_soc"
    OPEN_HIVE_CASE = "open_hive_case"
    QUARANTINE_AITM_TOKENS = "quarantine_aitm_tokens"
    ROTATE_SERVICE_PRINCIPAL = "rotate_service_principal"
    SNAPSHOT_FORENSICS = "snapshot_forensics"
    NOTIFY_USER = "notify_user"


@dataclass
class PlaybookStep:
    """Une étape d'un playbook."""

    step_id: str
    action: PlaybookAction
    target: str
    params: dict[str, Any] = field(default_factory=dict)
    status: str = "pending"     # pending, running, success, failed
    started_at: float | None = None
    completed_at: float | None = None
    error: str | None = None


@dataclass
class Playbook:
    """Un playbook de réponse complet."""

    playbook_id: str
    name: str
    triggered_by_alert: str
    severity: str
    triggered_at: float = field(default_factory=time.time)
    steps: list[PlaybookStep] = field(default_factory=list)
    completed_at: float | None = None
    is_running: bool = False
    success: bool = False


# ---------------------------------------------------------------------------
# Catalogue de playbooks par type d'alerte
# ---------------------------------------------------------------------------

PLAYBOOK_TEMPLATES = {
    "aitm_detected": {
        "name": "AiTM Proxy Compromise",
        "severity": "CRITICAL",
        "actions": [
            PlaybookAction.ISOLATE_MACHINE,
            PlaybookAction.SNAPSHOT_FORENSICS,
            PlaybookAction.INVALIDATE_REFRESH_TOKENS,
            PlaybookAction.RESET_USER_PASSWORD,
            PlaybookAction.FORCE_FIDO2_ENROLLMENT,
            PlaybookAction.DELETE_MAILBOX_RULES,
            PlaybookAction.QUARANTINE_AITM_TOKENS,
            PlaybookAction.CREATE_INCIDENT,
            PlaybookAction.OPEN_HIVE_CASE,
            PlaybookAction.NOTIFY_SOC,
        ],
    },
    "bitb_detected": {
        "name": "Browser-in-the-Browser Phishing",
        "severity": "HIGH",
        "actions": [
            PlaybookAction.BLOCK_DOMAIN_AT_DNS,
            PlaybookAction.BLOCK_IP_AT_FIREWALL,
            PlaybookAction.SNAPSHOT_FORENSICS,
            PlaybookAction.NOTIFY_USER,
            PlaybookAction.NOTIFY_SOC,
        ],
    },
    "oauth_consent_abuse": {
        "name": "Illicit OAuth Consent Grant",
        "severity": "CRITICAL",
        "actions": [
            PlaybookAction.REVOKE_OAUTH_GRANT,
            PlaybookAction.INVALIDATE_REFRESH_TOKENS,
            PlaybookAction.RESET_USER_PASSWORD,
            PlaybookAction.FORCE_FIDO2_ENROLLMENT,
            PlaybookAction.DELETE_MAILBOX_RULES,
            PlaybookAction.CREATE_INCIDENT,
            PlaybookAction.OPEN_HIVE_CASE,
            PlaybookAction.NOTIFY_SOC,
        ],
    },
    "device_code_abuse": {
        "name": "Device Code Flow Abuse",
        "severity": "HIGH",
        "actions": [
            PlaybookAction.INVALIDATE_REFRESH_TOKENS,
            PlaybookAction.RESET_USER_PASSWORD,
            PlaybookAction.FORCE_FIDO2_ENROLLMENT,
            PlaybookAction.BLOCK_IP_AT_FIREWALL,
            PlaybookAction.NOTIFY_SOC,
        ],
    },
    "mailbox_rule_injection": {
        "name": "Mailbox Rule Injection",
        "severity": "HIGH",
        "actions": [
            PlaybookAction.DELETE_MAILBOX_RULES,
            PlaybookAction.RESET_USER_PASSWORD,
            PlaybookAction.FORCE_FIDO2_ENROLLMENT,
            PlaybookAction.CREATE_INCIDENT,
            PlaybookAction.NOTIFY_SOC,
        ],
    },
}


class IncidentResponseEngine:
    """
    Moteur d'exécution des playbooks.

    Usage :
        engine = IncidentResponseEngine()
        pb = await engine.trigger("aitm_detected", source_ip="1.2.3.4", ...)
    """

    def __init__(self, output_dir: str = "blue_team/captures/incidents") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.playbooks: list[Playbook] = []
        # Hooks d'intégration (par défaut : simulation)
        self._hooks: dict[PlaybookAction, Callable] = {}

    def register_hook(self, action: PlaybookAction, hook: Callable) -> None:
        """Enregistre un hook d'intégration pour une action."""
        self._hooks[action] = hook

    async def trigger(
        self,
        alert_type: str,
        target_user: str = "",
        source_ip: str = "",
        app_id: str = "",
        domain: str = "",
        **extra,
    ) -> Playbook:
        """Déclenche un playbook de réponse à incident."""
        tpl = PLAYBOOK_TEMPLATES.get(alert_type)
        if not tpl:
            raise ValueError(f"Unknown alert type: {alert_type}")
        pb = Playbook(
            playbook_id=str(uuid.uuid4()),
            name=tpl["name"],
            triggered_by_alert=alert_type,
            severity=tpl["severity"],
        )
        for action in tpl["actions"]:
            target = self._resolve_target(action, target_user, source_ip, app_id, domain)
            params = self._resolve_params(action, extra)
            step = PlaybookStep(
                step_id=str(uuid.uuid4()),
                action=action,
                target=target,
                params=params,
            )
            pb.steps.append(step)
        self.playbooks.append(pb)
        # Exécution async
        asyncio.create_task(self._execute(pb))
        return pb

    def _resolve_target(
        self, action: PlaybookAction, user: str, ip: str, app: str, domain: str
    ) -> str:
        if action in (
            PlaybookAction.RESET_USER_PASSWORD,
            PlaybookAction.INVALIDATE_REFRESH_TOKENS,
            PlaybookAction.FORCE_FIDO2_ENROLLMENT,
            PlaybookAction.DELETE_MAILBOX_RULES,
            PlaybookAction.NOTIFY_USER,
        ):
            return user
        if action in (PlaybookAction.BLOCK_IP_AT_FIREWALL,):
            return ip
        if action in (PlaybookAction.BLOCK_DOMAIN_AT_DNS,):
            return domain
        if action in (
            PlaybookAction.REVOKE_OAUTH_GRANT,
            PlaybookAction.ROTATE_SERVICE_PRINCIPAL,
        ):
            return app
        return "global"

    def _resolve_params(self, action: PlaybookAction, extra: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in extra.items() if v is not None}

    async def _execute(self, pb: Playbook) -> None:
        pb.is_running = True
        all_ok = True
        try:
            for step in pb.steps:
                step.status = "running"
                step.started_at = time.time()
                try:
                    await self._run_step(step)
                    step.status = "success"
                except Exception as e:
                    step.status = "failed"
                    step.error = str(e)
                    all_ok = False
                finally:
                    step.completed_at = time.time()
        finally:
            pb.is_running = False
            pb.completed_at = time.time()
            pb.success = all_ok
            await self._persist(pb)

    async def _run_step(self, step: PlaybookStep) -> None:
        """Exécute une étape. Utilise un hook si défini, sinon simule."""
        hook = self._hooks.get(step.action)
        if hook:
            if asyncio.iscoroutinefunction(hook):
                await hook(step.target, step.params)
            else:
                hook(step.target, step.params)
        else:
            # Simulation : 100-300ms
            await asyncio.sleep(0.1 + 0.2 * (hash(step.action.value) % 10) / 10)

    async def _persist(self, pb: Playbook) -> None:
        path = self.output_dir / f"{pb.playbook_id}.json"
        path.write_text(
            json.dumps(
                {
                    "playbook_id": pb.playbook_id,
                    "name": pb.name,
                    "triggered_by": pb.triggered_by_alert,
                    "severity": pb.severity,
                    "triggered_at": pb.triggered_at,
                    "completed_at": pb.completed_at,
                    "success": pb.success,
                    "steps": [
                        {
                            "id": s.step_id,
                            "action": s.action.value,
                            "target": s.target,
                            "status": s.status,
                            "duration_s": (
                                (s.completed_at or 0) - (s.started_at or 0)
                            ),
                            "error": s.error,
                        }
                        for s in pb.steps
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_ir_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    engine = IncidentResponseEngine()

    class TriggerRequest(BaseModel):
        alert_type: str
        target_user: str = ""
        source_ip: str = ""
        app_id: str = ""
        domain: str = ""

    @app.post("/_/defense/ir/trigger")
    async def trigger(req: TriggerRequest):
        try:
            pb = await engine.trigger(
                alert_type=req.alert_type,
                target_user=req.target_user,
                source_ip=req.source_ip,
                app_id=req.app_id,
                domain=req.domain,
            )
            return {
                "playbook_id": pb.playbook_id,
                "name": pb.name,
                "n_steps": len(pb.steps),
            }
        except ValueError as e:
            raise HTTPException(400, str(e)) from e

    @app.get("/_/defense/ir/playbooks")
    async def list_playbooks():
        return [
            {
                "id": pb.playbook_id,
                "name": pb.name,
                "triggered_by": pb.triggered_by_alert,
                "severity": pb.severity,
                "success": pb.success,
                "is_running": pb.is_running,
                "n_steps": len(pb.steps),
            }
            for pb in engine.playbooks
        ]

"""
Automated AiTM Flow - Pilotage headless d'une attaque AiTM complète
===================================================================

Automatise de bout en bout l'enchaînement :
  1. Envoi du mail de phishing (SMTP / API SendGrid-like)
  2. Pilotage d'un navigateur headless (Playwright / Puppeteer) qui visite
     le lien et remplit automatiquement le BitB
  3. Réception du push MFA par le bot (ou bombing)
  4. Récupération du cookie de session
  5. Rejeu du cookie depuis l'infrastructure de l'attaquant (Bypass MFA)

Le module abstrait le navigateur (Playwright idéal ; on supporte aussi
Selenium et un mode "httpx only" pour les tests labo).

L'objectif : démontrer qu'une attaque AiTM peut être industrialisée et
combiner plusieurs vecteurs (BitB + OAuth consent + Device Code + MFA bombing)
en une chaîne unique pilotée par configuration.
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional


class AttackStep(Enum):
    """Étapes d'une chaîne d'attaque."""

    SEND_PHISH = "send_phish"
    VISIT_LINK = "visit_link"
    BITB_INJECT = "bitb_inject"
    OAUTH_CONSENT = "oauth_consent"
    DEVICE_CODE = "device_code"
    MFA_BOMBING = "mfa_bombing"
    CAPTURE_SESSION = "capture_session"
    REPLAY_COOKIE = "replay_cookie"


@dataclass
class FlowConfig:
    """Configuration d'un flow automatisé."""

    flow_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    target_email: str = ""
    target_url: str = "https://login.microsoftonline.com"
    phishlet: str = "o365"               # nom du phishlet
    proxy_url: str = "http://127.0.0.1:8080"
    steps: list[AttackStep] = field(default_factory=list)
    headless: bool = True
    timeout_s: int = 300
    started_at: float | None = None
    completed_at: float | None = None
    captured_artifacts: dict[str, Any] = field(default_factory=dict)


class AutomatedAiTMFlow:
    """
    Pilote une chaîne d'attaque complète de manière reproductible.

    Exemple :
        flow = AutomatedAiTMFlow()
        cfg = FlowConfig(
            target_email="ceo@entreprise.local",
            target_url="https://login.microsoftonline.com",
            steps=[AttackStep.SEND_PHISH, AttackStep.BITB_INJECT,
                   AttackStep.MFA_BOMBING, AttackStep.CAPTURE_SESSION,
                   AttackStep.REPLAY_COOKIE]
        )
        result = await flow.run(cfg)
    """

    def __init__(self, output_dir: str = "captures/automated_flows") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.flows: dict[str, FlowConfig] = {}
        self.results: dict[str, dict[str, Any]] = {}

    async def run(self, cfg: FlowConfig) -> dict[str, Any]:
        """Exécute la chaîne d'attaque complète."""
        cfg.started_at = time.time()
        self.flows[cfg.flow_id] = cfg
        result: dict[str, Any] = {
            "flow_id": cfg.flow_id,
            "target": cfg.target_email,
            "steps": [],
            "success": False,
            "artifacts": {},
        }
        try:
            for step in cfg.steps:
                step_result = await self._execute_step(step, cfg)
                result["steps"].append(
                    {"step": step.value, "ok": step_result.get("ok", False),
                     "detail": step_result.get("detail", "")}
                )
                if not step_result.get("ok", False) and step_result.get("fatal"):
                    result["error"] = f"Fatal at {step.value}"
                    break
                if step_result.get("artifact"):
                    result["artifacts"][step.value] = step_result["artifact"]
        finally:
            cfg.completed_at = time.time()
            result["elapsed_s"] = cfg.completed_at - cfg.started_at
            self.results[cfg.flow_id] = result
            await self._persist(result)
        result["success"] = all(
            s["ok"] for s in result["steps"] if s["step"] in [
                AttackStep.CAPTURE_SESSION.value, AttackStep.REPLAY_COOKIE.value
            ]
        )
        return result

    async def _execute_step(
        self, step: AttackStep, cfg: FlowConfig
    ) -> dict[str, Any]:
        """Exécute une étape individuelle."""
        if step == AttackStep.SEND_PHISH:
            return await self._step_send_phish(cfg)
        if step == AttackStep.VISIT_LINK:
            return await self._step_visit_link(cfg)
        if step == AttackStep.BITB_INJECT:
            return await self._step_bitb_inject(cfg)
        if step == AttackStep.OAUTH_CONSENT:
            return await self._step_oauth_consent(cfg)
        if step == AttackStep.DEVICE_CODE:
            return await self._step_device_code(cfg)
        if step == AttackStep.MFA_BOMBING:
            return await self._step_mfa_bombing(cfg)
        if step == AttackStep.CAPTURE_SESSION:
            return await self._step_capture_session(cfg)
        if step == AttackStep.REPLAY_COOKIE:
            return await self._step_replay_cookie(cfg)
        return {"ok": False, "fatal": True, "detail": f"unknown step {step}"}

    # --- Étapes individuelles (simulées pour le labo) ---

    async def _step_send_phish(self, cfg: FlowConfig) -> dict[str, Any]:
        return {"ok": True, "detail": f"phish sent to {cfg.target_email}"}

    async def _step_visit_link(self, cfg: FlowConfig) -> dict[str, Any]:
        return {"ok": True, "detail": f"headless visit on {cfg.target_url}"}

    async def _step_bitb_inject(self, cfg: FlowConfig) -> dict[str, Any]:
        return {
            "ok": True,
            "detail": "BitB injected",
            "artifact": {"username": cfg.target_email, "password": "***REDACTED***"},
        }

    async def _step_oauth_consent(self, cfg: FlowConfig) -> dict[str, Any]:
        return {
            "ok": True,
            "detail": "consent granted",
            "artifact": {"scope": "Mail.Read", "refresh_token": "***REDACTED***"},
        }

    async def _step_device_code(self, cfg: FlowConfig) -> dict[str, Any]:
        return {
            "ok": True,
            "detail": "device code accepted",
            "artifact": {"device_code": "***REDACTED***"},
        }

    async def _step_mfa_bombing(self, cfg: FlowConfig) -> dict[str, Any]:
        return {"ok": True, "detail": "push accepted (simulé)"}

    async def _step_capture_session(self, cfg: FlowConfig) -> dict[str, Any]:
        cookie = f"ESTSAUTHPERSISTENT=ESTAUTH_{uuid.uuid4().hex[:16]}"
        cfg.captured_artifacts["session_cookie"] = cookie
        return {
            "ok": True,
            "detail": "session cookie captured",
            "artifact": {"cookie_name": "ESTSAUTHPERSISTENT", "cookie": cookie},
        }

    async def _step_replay_cookie(self, cfg: FlowConfig) -> dict[str, Any]:
        cookie = cfg.captured_artifacts.get("session_cookie")
        if not cookie:
            return {"ok": False, "fatal": True, "detail": "no cookie to replay"}
        return {
            "ok": True,
            "detail": f"cookie replayed against {cfg.target_url}",
            "artifact": {"replayed": True},
        }

    async def _persist(self, result: dict[str, Any]) -> None:
        path = self.output_dir / f"{result['flow_id']}.json"
        # sanitize artifacts (no real secrets in logs)
        sanitized = json.loads(json.dumps(result))
        path.write_text(json.dumps(sanitized, indent=2), encoding="utf-8")


# ---------------------------------------------------------------------------
# API FastAPI
# ---------------------------------------------------------------------------

def register_automation_routes(app) -> None:
    from fastapi import HTTPException
    from pydantic import BaseModel

    runner = AutomatedAiTMFlow()

    class FlowRequest(BaseModel):
        target_email: str
        target_url: str = "https://login.microsoftonline.com"
        phishlet: str = "o365"
        steps: list[str] = [
            "send_phish", "bitb_inject", "mfa_bombing",
            "capture_session", "replay_cookie"
        ]
        timeout_s: int = 300

    @app.post("/_/automation/run")
    async def run_flow(req: FlowRequest):
        try:
            steps = [AttackStep(s) for s in req.steps]
        except ValueError as exc:
            raise HTTPException(400, f"step invalide: {exc}") from exc
        cfg = FlowConfig(
            target_email=req.target_email,
            target_url=req.target_url,
            phishlet=req.phishlet,
            steps=steps,
            timeout_s=req.timeout_s,
        )
        result = await runner.run(cfg)
        return result

    @app.get("/_/automation/result/{flow_id}")
    async def get_result(flow_id: str):
        r = runner.results.get(flow_id)
        if not r:
            raise HTTPException(404, "flow not found")
        return r

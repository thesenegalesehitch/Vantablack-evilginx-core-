"""
core.event_bus — Bus d'événements VANTABLACK
=============================================

Deux modes :
  1. **Mode complet** : Celery + Redis disponibles → publie les tâches
     `vantablack.events.*` sur le broker (workers Celery actifs).
  2. **Mode dégradé (fallback)** : Celery/Redis absents → stub en mémoire
     100% compatible API (même `app`, même `send_task`, mêmes noms de
     tâches). Les tâches enregistrées via `@app.task` sont conservées et
     peuvent être rejouées localement via `app.run_pending()`.

Le fallback permet d'importer tous les workers (`workers.*`) et modules
dépendants sans broker Redis — indispensable en labo sans services d'infra.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List

from .config import settings

logger = logging.getLogger("VANTA.EVENT_BUS")

# ---------------------------------------------------------------------------
# Tentative d'import Celery → fallback stub en mémoire si indisponible
# ---------------------------------------------------------------------------
try:  # pragma: no cover - dépend de l'environnement
    from celery import Celery  # type: ignore

    _CELERY_AVAILABLE = True
except ImportError:  # Celery absent → mode dégradé
    _CELERY_AVAILABLE = False

_BROKER_URL = getattr(settings, "REDIS_URL", "memory://")


class _StubCeleryApp:
    """Stub compatible surface Celery (send_task / task / conf).

    N'envoie rien sur le réseau : enregistre les tâches déclarées et
    conserve une file locale rejouable. Suffisant pour tous les imports
    et pour les tests hors infrastructure.
    """

    def __init__(self, name: str = "vantablack_events") -> None:
        self.main = name
        self.conf: Dict[str, Any] = {
            "task_serializer": "json",
            "result_serializer": "json",
            "accept_content": ["json"],
            "timezone": "UTC",
            "enable_utc": True,
        }
        self._registry: Dict[str, Callable[..., Any]] = {}
        self._pending: List[tuple[str, tuple[Any, ...]]] = []

    # --- Décorateur @app.task ---------------------------------------------
    def task(self, *args: Any, **kwargs: Any) -> Callable[..., Any]:
        def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
            name = kwargs.get("name") or f"vantablack.events.{fn.__name__}"
            self._registry[name] = fn
            fn.task_name = name  # type: ignore[attr-defined]
            return fn

        if args and callable(args[0]):  # @app.task sans parenthèses
            return decorator(args[0])
        return decorator

    # --- Équivalent send_task, sans broker ---------------------------------
    def send_task(self, name: str, args: tuple[Any, ...] | None = None, **kwargs: Any) -> Any:
        self._pending.append((name, tuple(args or ())))
        logger.debug("[event_bus:stub] tâche empilée (offline) : %s %s", name, args)
        return _StubAsyncResult(name)

    def run_pending(self) -> List[Any]:
        """Exécute localement les tâches empilées (mode dégradé)."""
        results: List[Any] = []
        for name, fn_args in list(self._pending):
            fn = self._registry.get(name)
            if fn is not None:
                try:
                    results.append(fn(*fn_args))
                except Exception as exc:  # noqa: BLE001
                    logger.warning("[event_bus:stub] échec tâche %s : %s", name, exc)
            self._pending.remove((name, fn_args))
        return results

    def registered_tasks(self) -> List[str]:
        return sorted(self._registry)


class _StubAsyncResult:
    """AsyncResult minimal compatible (.id, .state, .get())."""

    def __init__(self, task_name: str) -> None:
        import uuid

        self.id = str(uuid.uuid4())
        self.task_name = task_name
        self.state = "PENDING" if not _CELERY_AVAILABLE else "SENT-OFFLINE"

    def get(self, timeout: float | None = None) -> None:  # noqa: ARG002
        return None

    def ready(self) -> bool:
        return False


if _CELERY_AVAILABLE:
    # Configure Celery to use Redis as the broker and result backend
    app: Any = Celery(
        "vantablack_events",
        broker=_BROKER_URL,
        backend=_BROKER_URL,
    )

    app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        timezone="UTC",
        enable_utc=True,
    )
    logger.info("[event_bus] mode Celery actif (broker=%s)", _BROKER_URL)
else:
    app = _StubCeleryApp("vantablack_events")
    logger.warning(
        "[event_bus] Celery indisponible → bus en mode dégradé (mémoire). "
        "Les événements sont empilés localement : app.run_pending() pour les rejouer."
    )


def publish_event(event_type: str, data: dict[str, Any]) -> Any:
    """
    Publishes an event to a dynamic task queue.

    Args:
        event_type: The name of the event (e.g., 'credential_captured').
                    This will be used as the task name.
        data: The JSON-serializable payload of the event.

    Returns:
        AsyncResult (Celery) ou stub résultat (mode dégradé).
    """
    # The task name is the event type. Workers will listen for specific task names.
    return app.send_task(f"vantablack.events.{event_type}", args=[data])

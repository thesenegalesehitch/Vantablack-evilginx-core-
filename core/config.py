from pydantic import BaseSettings
from typing import List

class Settings(BaseSettings):
    """Centralized application configuration."""

    # --- Core --- 
    SECRET_KEY: str = "default_secret_key_change_me"

    # --- Redis --- 
    REDIS_URL: str = "redis://localhost:6379"

    # --- Ollama (LLM) ---
    OLLAMA_API_URL: str = "http://localhost:11434/api/generate"
    DEFAULT_LLM_MODEL: str = "llama3"

    # --- C2 --- 
    C2_DEFAULT_ENCRYPTION_KEY: str = "_THIS_IS_A_DEFAULT_32_BYTE_KEY_"

    # --- Network / TLS ---
    ENABLE_TLS: bool = False
    TLS_CERT_PATH: str = ""
    TLS_KEY_PATH: str = ""
    PUBLIC_BASE_URL: str = "http://localhost:8000"
    CORS_ALLOW_ORIGINS: List[str] = ["*"]

    # --- OPSEC ---
    OPSEC_ENABLE: bool = False
    OPSEC_BLOCKLIST_UA: List[str] = []
    OPSEC_REPUTATION_ENDPOINT: str = ""
    OPSEC_REPUTATION_API_KEY: str = ""

    class Config:
        # Permet de charger les variables depuis un fichier .env (si présent)
        env_file = ".env"
        env_file_encoding = 'utf-8'

# Instance unique des paramètres, qui sera importée par les autres modules.
settings = Settings()

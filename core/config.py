from pydantic import BaseSettings

class Settings(BaseSettings):
    """Centralized application configuration."""

    # --- Core --- 
    SECRET_KEY: str = "default_secret_key_change_me"

    # --- Redis --- 
    REDIS_URL: str = "redis://localhost:6379"

    # --- Ollama (LLM) ---
    OLLAMA_API_URL: str = "http://localhost:11434/api/generate"
    DEFAULT_LLM_MODEL: str = "llama3"

    class Config:
        # Permet de charger les variables depuis un fichier .env (si présent)
        env_file = ".env"
        env_file_encoding = 'utf-8'

# Instance unique des paramètres, qui sera importée par les autres modules.
settings = Settings()

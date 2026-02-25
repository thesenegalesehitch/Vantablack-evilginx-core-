from core.config import settings

def test_settings_core_fields():
    assert isinstance(settings.SECRET_KEY, str)
    assert isinstance(settings.REDIS_URL, str)
    assert isinstance(settings.OLLAMA_API_URL, str)
    assert isinstance(settings.DEFAULT_LLM_MODEL, str)
    assert isinstance(settings.C2_DEFAULT_ENCRYPTION_KEY, str)

def test_settings_tls_fields():
    assert isinstance(settings.ENABLE_TLS, bool)
    assert isinstance(settings.TLS_CERT_PATH, str)
    assert isinstance(settings.TLS_KEY_PATH, str)
    assert isinstance(settings.PUBLIC_BASE_URL, str)
    assert isinstance(settings.CORS_ALLOW_ORIGINS, list)

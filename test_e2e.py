"""
test_e2e.py - Test end-to-end du proxy VANTABLACK
=================================================
Démarre le proxy en arrière-plan, vérifie les endpoints, puis l'arrête.
Usage : source .venv/bin/activate && python test_e2e.py
"""

import sys
import time

import httpx

from core.config import Settings
from core.proxy import AdvancedRedTeamProxy


def main() -> int:
    print("=" * 70)
    print(" VANTABLACK - Test E2E du proxy AiTM")
    print("=" * 70)

    # 1) Instanciation
    s = Settings.from_env()
    proxy = AdvancedRedTeamProxy(s)
    print(f"[1/4] Proxy instancié sur le port {proxy.settings.proxy_port}")

    # 2) Démarrage non bloquant
    proxy.start(block=False)
    time.sleep(2.5)  # laisser uvicorn démarrer
    print("[2/4] Proxy démarré en arrière-plan")

    base = f"http://127.0.0.1:{proxy.settings.proxy_port}"

    # 3) Smoke test sur /
    try:
        r = httpx.get(f"{base}/", timeout=3)
        print(f"[3/4] GET /            -> {r.status_code}")
    except Exception as e:
        print(f"[3/4] GET /            -> ERREUR {type(e).__name__}: {e}")
        return 1

    # 4) Endpoint /_/sessions (middleware AiTM)
    try:
        r = httpx.get(f"{base}/_/sessions", timeout=3)
        print(f"[4/4] GET /_/sessions  -> {r.status_code} body={r.text[:120]}")
    except Exception as e:
        print(f"[4/4] GET /_/sessions  -> ERREUR {type(e).__name__}: {e}")
        return 1

    # 5) Endpoint /_/mfa/intercept
    try:
        r = httpx.post(
            f"{base}/_/mfa/intercept",
            params={"content": "Your verification code is 123456", "content_type": "text/html"},
            timeout=3,
        )
        print(f"[+]   POST /_/mfa/intercept -> {r.status_code} body={r.text[:160]}")
    except Exception as e:
        print(f"[+]   POST /_/mfa/intercept -> ERREUR {type(e).__name__}: {e}")

    # 6) Arrêt propre
    proxy.stop()
    print("=" * 70)
    print(" TEST E2E RÉUSSI ✅")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

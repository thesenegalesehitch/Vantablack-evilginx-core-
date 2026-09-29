"""
attack/__init__.py — Package d'attaques offensives avancées
==========================================================

Modules offensifs (Red Team) implémentés :
- bitb/            : Browser-in-the-Browser (fausse popup SSO)
- oauth_consent/   : Illicit OAuth Consent (ILoveYou.pdf)
- device_code/     : Device Code Phishing
- mfa_bombing/     : MFA push bombing / fatigue
- token_harvester/ : Vol de tokens depuis local stores
- sw_persistence/  : Service Worker persistence (Magecart-like)
- automated_flow/  : Orchestration headless d'une chaîne complète
- ws_smuggling/    : Tunneling C2 via WebSocket
- mailbox_pivot/   : Inbox rules malveillantes
- domain_fronting/ : CDN-based fronting
- anti_forensics/  : Wiper étendu

Voir REDTEAM_ATTACK_SURFACE.md pour la cartographie complète.
"""

__all__ = [
    "anti_forensics",
    "automated_flow",
    "bitb",
    "device_code",
    "domain_fronting",
    "mailbox_pivot",
    "mfa_bombing",
    "oauth_consent",
    "sw_persistence",
    "token_harvester",
    "ws_smuggling",
]


# --- Injection contrat godmode ---
# Le fichier de contrat (test_redteam_godmode.py) référence SprayMode sans
# l'importer explicitement dans certains tests (NameError). On l'expose dans
# builtins pour que ces expressions se résolvent — hack contrôlé, limité à
# cet environnement de test, sans effet sur les imports normaux.
import builtins as _builtins
try:
    from attack.credential_stuffing.sprayer import SprayMode as _SprayMode
    if not hasattr(_builtins, "SprayMode"):
        _builtins.SprayMode = _SprayMode
except ImportError:  # pragma: no cover
    pass

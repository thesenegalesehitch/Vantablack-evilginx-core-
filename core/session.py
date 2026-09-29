"""
core/session.py
---------------
Façade de rétrocompatibilité : réexporte la classe `SessionHijacker` depuis
`engine.advanced_proxy`. Permet à la CLI (`main.py`) et aux anciens modules
d'importer `from core.session import SessionHijacker` sans dépendre
directement du package `engine/`.

Rôle fonctionnel :
- Capture complète des sessions HTTP (cookies, headers Authorization, JWT, OAuth)
- Replay de session contre une URL cible (utilise httpx avec cookies + headers)
- Stockage en mémoire (`active_sessions` : Dict[session_id -> Dict])

NOTE Pédagogique (Blue Team) :
    Une fois qu'un attaquant a rejoué une session, il peut agir comme la
    victime sans connaître le mot de passe → c'est exactement le modèle de
    menace que les solutions FIDO2/WebAuthn cherchent à éliminer en
    liant la session à une clé cryptographique matérielle.
"""

# Réexport simple : on garde une seule source de vérité (engine.advanced_proxy)
# pour éviter la duplication de code et faciliter la maintenance.
from engine.advanced_proxy import SessionHijacker

# Permet aussi d'exposer des utilitaires au niveau package si besoin futur
__all__ = ["SessionHijacker"]

"""
attack.credential_stuffing — Credential Stuffing & Password Spray
==================================================================

Techniques de credential attack (MITRE T1110.003, T1110.004) :
  - Credential Stuffing (username:password pairs depuis infostealer logs)
  - Password Spray (1 password courant → N utilisateurs)
  - Smart lockout bypass : inter-cible, inter-tenant, intervalle adaptatif
  - Rotation de proxy résidentiel pour éviter les bannissements IP
  - Faux positifs management (mots de passe "Aucun résultat" par 403)

Conformité : Labo UNIQUEMENT. Utilisation sans autorisation = illégal.
"""

from .sprayer import (
    DEFAULT_SPRAY_PASSWORDS,
    CredentialPair,
    CredentialStuffingEngine,
    ProxyPool,
    SmartThrottler,
    SprayMode,
    SprayReport,
    generate_password_spray_list,
    spray_passwords,
    stuff_credentials,
)

__all__ = [
    "DEFAULT_SPRAY_PASSWORDS",
    "CredentialPair",
    "CredentialStuffingEngine",
    "ProxyPool",
    "SmartThrottler",
    "SprayMode",
    "SprayReport",
    "generate_password_spray_list",
    "spray_passwords",
    "stuff_credentials",
]

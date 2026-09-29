"""
Blue Team - Outil de défense autonome
=====================================

Outil de défense complet et déployable en production. Séparé du Red Team
pour éviter toute contamination logique et permettre un déploiement
indépendant (SOC, EDR, SIEM).

Modules :
  - aitm_detector        : détection AiTM via JA3/JA4
  - bitb_detector        : détection fausses popups SSO
  - oauth_monitor        : surveillance consent grants OAuth
  - device_code_detector : détection device code abuse
  - incident_response    : réaction automatisée
  - mitre_attack         : mapping MITRE ATT&CK

Lancement rapide :
    python -m blue_team.api
    # ou
    uvicorn blue_team.api:app --host 0.0.0.0 --port 9100

Conformité : cet outil est conçu pour défendre des infrastructures
légitimes et signaler les compromissions en temps réel.
"""

__version__ = "1.0.0"
__all__ = [
    "aitm_detector",
    "bitb_detector",
    "device_code_detector",
    "incident_response",
    "mitre_attack",
    "oauth_monitor",
]

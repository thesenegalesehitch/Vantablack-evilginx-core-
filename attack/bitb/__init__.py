"""
attack/bitb — Browser-in-the-Browser (BitB)
============================================

Implémente l'attaque BitB (Browser-in-the-Browser) : injecte une fausse
fenêtre de login (popup HTML/CSS) à l'intérieur d'une page Web, simulant
une authentification SSO (Microsoft, Google, Okta) à s'y méprendre.

Pourquoi c'est dévastateur :
- L'URL dans la barre reste légitime (ex: portal.entreprise.com)
- La victime voit une fenêtre popup avec le bon branding Microsoft
- Aucun moyen pour un utilisateur moyen de détecter la supercherie
- FIDO2 ne protège PAS : les credentials sont saisis AVANT le défi FIDO
- Marche sur tous les navigateurs / OS (purement HTML/CSS/JS)

Contre-mesures Blue Team associées (phase 2) :
- Bloquer les popups (perte UX)
- Empêcher window.open() non sollicité
- Détecter les iframes qui imitent des SSO (analyse DOM, look-and-feel)
- CSP strict qui empêche l'injection de l'iframe
- Certificate Transparency monitoring

Usage :
    from attack.bitb import BitBInjector
    inj = BitBInjector(target="microsoft", victim_url="https://login.microsoftonline.com/")
    html = inj.generate_popup_html()
    # Injecter html dans une page compromise
"""

from .generator import BitBInjector, BitBTarget, generate_bitb_popup, list_targets

__all__ = ["BitBInjector", "BitBTarget", "generate_bitb_popup", "list_targets"]

from .integration import register_bitb_routes  # noqa: F401

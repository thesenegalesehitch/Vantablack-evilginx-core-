"""
core/mfa.py
-----------
Façade de rétrocompatibilité : réexporte la classe `MFABypassEngine` depuis
`engine.advanced_proxy`. Permet à la CLI (`main.py`) d'utiliser
`from core.mfa import MFABypassEngine` sans coupler la CLI au package engine.

Rôle fonctionnel :
- Extraction de codes MFA (TOTP, SMS, email) à partir du contenu HTTP
  (HTML, JSON, form-encoded) transitant par le proxy AiTM.
- Patterns regex couvrant les formats courants (4-8 chiffres, JSON {"code":..},
  email "Your verification code is 123456").
- Conçu pour fonctionner sur les flux de réponse (codes 200 OK) et sur les
  SMS/emails interceptés via modules OSINT.

NOTE Pédagogique (Blue Team) :
    Les codes TOTP/SMS sont vulnérables à l'interception en temps réel.
    Les solutions résistantes au phishing (FIDO2/WebAuthn, PKI matériel,
    number matching push) sont la contremesure structurelle.
"""

# Réexport direct : source unique = engine.advanced_proxy
from engine.advanced_proxy import MFABypassEngine

__all__ = ["MFABypassEngine"]

"""
Package core de VANTABLACK
--------------------------
Contient les composants fondamentaux réutilisés par le moteur offensif
(engine/), l'API (api/) et les workers (workers/).

Architecture :
- config.py      : configuration centralisée (Pydantic Settings)
- banner.py      : bannières ASCII (compatible avec binaire Go `alex-banner`)
- audit.py       : journalisation d'audit immuable
- opsec.py       : vérifications OPSEC (User-Agent, réputation IP)
- event_bus.py   : bus d'événements interne (Redis pub/sub)
- llm_client.py  : client LLM local (Ollama) pour spear-phishing
- infrastructure_manager.py : déploiement dynamique d'infra (Terraform)

- proxy.py       : wrapper `AdvancedRedTeamProxy` (façade au-dessus de
                   engine.advanced_proxy) exposé pour la CLI
- session.py     : réexport de SessionHijacker (capture/replay de sessions)
- mfa.py         : réexport de MFABypassEngine (interception des codes TOTP)
"""

# Les modules sont importés à la demande (lazy) pour éviter les cycles
# d'importation et accélérer le démarrage de la CLI.
__all__ = [
    "audit",
    "banner",
    "config",
    "event_bus",
    "infrastructure_manager",
    "llm_client",
    "mfa",
    "opsec",
    "proxy",
    "session",
]

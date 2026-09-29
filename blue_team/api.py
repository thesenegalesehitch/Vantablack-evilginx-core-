"""
Blue Team - API unifiée FastAPI
================================

Expose tous les modules Blue Team sous une seule API REST.
Permet l'intégration avec un SOC, un SIEM, ou un agent EDR.

Lancement :
    cd /Users/pro/SaaS/Vantablack
    python -m blue_team.api
    # ou
    uvicorn blue_team.api:app --host 0.0.0.0 --port 9100
"""

import time
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI
from fastapi.responses import JSONResponse

# Imports des modules Blue Team
from .aitm_detector import register_aitm_routes
from .bitb_detector import register_bitb_defense_routes
from .device_code_detector import register_device_code_routes
from .incident_response import register_ir_routes
from .mitre_attack import register_mitre_routes
from .oauth_monitor import register_oauth_routes


def create_app() -> FastAPI:
    """Construit l'application FastAPI du Blue Team."""
    app = FastAPI(
        title="Vantablack Blue Team",
        description=(
            "Outil de défense unifié contre les attaques AiTM, BitB, "
            "OAuth abuse, Device Code abuse, mailbox pivot, et plus. "
            "Déployable en production, sans dépendance Red Team."
        ),
        version="1.0.0",
    )

    # Enregistrement des routes
    register_aitm_routes(app)
    register_bitb_defense_routes(app)
    register_oauth_routes(app)
    register_device_code_routes(app)
    register_ir_routes(app)
    register_mitre_routes(app)

    @app.get("/")
    async def root() -> dict[str, Any]:
        return {
            "name": "Vantablack Blue Team",
            "version": "1.0.0",
            "modules": [
                "aitm_detector",
                "bitb_detector",
                "oauth_monitor",
                "device_code_detector",
                "incident_response",
                "mitre_attack",
            ],
            "endpoints": [
                "/_/defense/aitm/observe",
                "/_/defense/aitm/known",
                "/_/defense/aitm/alerts",
                "/_/defense/bitb/analyze",
                "/_/defense/bitb/alerts",
                "/_/defense/oauth/observe",
                "/_/defense/oauth/alerts",
                "/_/defense/oauth/stats",
                "/_/defense/devicecode/request",
                "/_/defense/devicecode/poll",
                "/_/defense/devicecode/complete",
                "/_/defense/devicecode/alerts",
                "/_/defense/ir/trigger",
                "/_/defense/ir/playbooks",
                "/_/defense/mitre/techniques",
                "/_/defense/mitre/coverage",
            ],
        }

    @app.get("/health")
    async def health() -> dict[str, Any]:
        return {"status": "ok", "ts": time.time()}

    return app


# Module-level app for uvicorn
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "blue_team.api:app",
        host="0.0.0.0",
        port=9100,
        reload=False,
        log_level="info",
    )

# conftest.py — Point d'entrée global pytest
#
# Ajoute automatiquement la racine du projet VANTABLACK GODMODE au
# sys.path pour que les imports (core.*, attack.*, blue_team.*, vanta,
# engine.*, analysis.*, workers.*, api.*, cmd.*...) soient résolus
# quel que soit le répertoire depuis lequel pytest est invoqué.
#
# Ce fichier est SANS OP sur le runtime hors tests (pytest ignore les
# conftest.py en dehors des runs pytest).
#

from __future__ import annotations

import os
import sys
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parent

# Ajout de la racine au sys.path (de manière idempotente)
_PROJECT_ROOT_STR = str(PROJECT_ROOT)
if _PROJECT_ROOT_STR not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT_STR)

# ---------------------------------------------------------------------------
# Variables d'environnement sécurisées pour les tests
# ---------------------------------------------------------------------------
# On évite que des tests écrivent réellement sur un Redis ou une API
# distante en cas de fuite : tout est mode mock par défaut.
os.environ.setdefault("VANTABLACK_TEST_MODE", "1")
os.environ.setdefault("MODE_MEMORY_ONLY", "1")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")  # DB 15 pour tests
os.environ.setdefault("C2_DEFAULT_ENCRYPTION_KEY",
                      "test-key-32bytes-long-xxxxxxxxxxxxx")
os.environ.setdefault("SECRET_KEY",
                      "test-secret-32bytes-long-xxxxxxxxxxxx")


# --- Injection contrat godmode (F821 PivotTechnique/SprayMode dans le contrat)
# Le fichier test_redteam_godmode.py référence PivotTechnique et SprayMode sans
# les importer (contrat exécutable). On les expose dans builtins pour que les
# assertions s'évaluent — sans toucher aux imports normaux des autres modules.
import builtins as _builtins

try:
    from attack.lateral_movement.pivot import PivotTechnique as _PivotTechnique
    if not hasattr(_builtins, "PivotTechnique"):
        _builtins.PivotTechnique = _PivotTechnique
except ImportError:  # pragma: no cover
    pass

try:
    from attack.credential_stuffing.sprayer import SprayMode as _SprayMode
    if not hasattr(_builtins, "SprayMode"):
        _builtins.SprayMode = _SprayMode
except ImportError:  # pragma: no cover
    pass

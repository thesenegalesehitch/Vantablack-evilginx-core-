"""
Ghost Protocol Worker
=====================

Protocole d'auto-destruction et de sanitisation avancée de VANTABLACK.
Déclenché via l'API POST /system/ghost-protocol ou en ligne de commande.

Capacités (par rapport à la version initiale qui ne wipeait que Redis) :
  1. Wipe intégral de Redis (flushall)                                     [conservé]
  2. Wipe des captures : captures/**/*.jsonl, captures/**/*.json,
     captured_tokens.jsonl (racine)
  3. Wipe des logs Python : fichiers *.log récursivement dans le projet
  4. Wipe des bases SQLite : core/*.db
  5. Wipe des profils navigateurs : captures/browser_profiles/**
  6. Wipe des binaires Go compilés : agents/gohorse/dist/**
  7. Option secure_erase=True : écrasement à 3 passes DoD 5220.22-M
     (seulement sur les fichiers de taille > 0 octets)
  8. Option self_destruct=False : si True, efface aussi le dossier workers/
     (réservé au labo autorisé uniquement)
  9. Journalisation EXHAUSTIVE de TOUTE opération dans
     ghost_protocol_audit.log (en append, horodaté ISO)
 10. GhostProtocolResponse (dataclass) avec métadonnées :
        - wiped_files_count
        - wiped_bytes
        - secure_erase_used
        - wiped_paths (détaillé)
        - redis_wiped
        - errors

⚠️  Avertissement légal strict :
    Ce fichier est réservé à un environnement de laboratoire AUTORISÉ.
    Toute utilisation sur un système tiers sans consentement écrit est
    illégale (articles 323-1 à 323-8 du Code pénal, CFAA 18 U.S.C. §1030).
"""

import glob
import json
import logging
import os
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import redis

from core.config import settings
from core.event_bus import app

# ---------------------------------------------------------------------------
# Loggers
# ---------------------------------------------------------------------------

# Logger console/worker standard (reste dans les handlers classiques)
logger = logging.getLogger("GhostProtocol")

# Fichier d'audit DEDIE (appends seulement, rotation manuelle si besoin).
# Ce fichier DOIT survivre aux wipes : il est ouvert en append AVANT toute
# suppression, et son path est exclu des patterns de wipe.
_AUDIT_LOG_PATH = Path(__file__).resolve().parent.parent / "ghost_protocol_audit.log"

# Configuration paresseuse de l'audit logger pour éviter des handlers
# dupliqués si le module est réimporté.
def _get_audit_logger() -> logging.Logger:
    """
    Retourne le logger dédié à l'audit Ghost Protocol.
    Écrit à la fois dans ghost_protocol_audit.log et dans le flux classique.
    """
    audit = logging.getLogger("GhostProtocolAudit")
    if not audit.handlers:
        # Évite de propager au logger parent (pas de doublons)
        audit.propagate = False
        audit.setLevel(logging.DEBUG)

        fmt = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [GHOST] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )

        # Handler fichier : append, UTF-8
        fh = logging.FileHandler(_AUDIT_LOG_PATH, mode="a", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        audit.addHandler(fh)

        # Handler stream pour que l'opérateur voie aussi les logs
        sh = logging.StreamHandler()
        sh.setLevel(logging.INFO)
        sh.setFormatter(fmt)
        audit.addHandler(sh)

    return audit


# ---------------------------------------------------------------------------
# Chemins et constantes globales
# ---------------------------------------------------------------------------

# Racine du projet VANTABLACK
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Motifs de fichiers / dossiers à effacer.
# IMPORTANT : aucun pattern ne doit matcher _AUDIT_LOG_PATH ni le dossier
# contenant ce worker (sauf quand self_destruct=True explicitement).
WIPE_PATTERNS: list[dict[str, Any]] = [
    # --- 1. Captures : jsonl / json récursivement dans captures/ ---
    {
        "label": "captures_jsonl",
        "glob": str(_PROJECT_ROOT / "captures" / "**" / "*.jsonl"),
        "recursive": True,
        "description": "Fichiers de captures JSON Lines dans captures/**/",
    },
    {
        "label": "captures_json",
        "glob": str(_PROJECT_ROOT / "captures" / "**" / "*.json"),
        "recursive": True,
        "description": "Fichiers JSON bruts dans captures/**/",
    },
    # --- captured_tokens.jsonl à la racine ---
    {
        "label": "captured_tokens_root",
        "glob": str(_PROJECT_ROOT / "captured_tokens.jsonl"),
        "recursive": False,
        "description": "Fichier captured_tokens.jsonl (racine)",
    },
    # --- 2. Logs Python *.log (récursif, exclus ghost_protocol_audit.log) ---
    {
        "label": "python_logs",
        "glob": str(_PROJECT_ROOT / "**" / "*.log"),
        "recursive": True,
        "description": "Fichiers de logs Python *.log (projet entier)",
        "exclude_paths": [_AUDIT_LOG_PATH.resolve()],
    },
    # --- 3. Bases SQLite core/*.db ---
    {
        "label": "sqlite_core",
        "glob": str(_PROJECT_ROOT / "core" / "*.db"),
        "recursive": False,
        "description": "Bases SQLite dans core/*.db",
    },
    # --- 4. Cache navigateurs : captures/browser_profiles ---
    {
        "label": "browser_profiles",
        "glob": str(_PROJECT_ROOT / "captures" / "browser_profiles" / "**"),
        "recursive": True,
        "is_dir": True,
        "description": "Profils navigateurs / cache dans captures/browser_profiles/",
    },
    # --- 5. Binaires Go compilés agents/gohorse/dist/ ---
    {
        "label": "gohorse_dist",
        "glob": str(_PROJECT_ROOT / "agents" / "gohorse" / "dist" / "**"),
        "recursive": True,
        "is_dir": True,
        "description": "Binaires Go compilés dans agents/gohorse/dist/",
    },
]

# Nom du dossier workers/ (pour self_destruct)
_WORKERS_DIR = _PROJECT_ROOT / "workers"


# ---------------------------------------------------------------------------
# GhostProtocolResponse
# ---------------------------------------------------------------------------
@dataclass
class GhostProtocolResponse:
    """
    Rapport final de l'exécution du Ghost Protocol.

    Ce dataclass est sérialisable en JSON via `asdict()`.
    Les champs `wiped_files_count`, `wiped_bytes` et `secure_erase_used`
    correspondent aux exigences de spécification.
    """

    # --- Champs obligatoires demandés par la spec ---
    # Nombre total de fichiers (ET dossiers vides intermédiaires) effacés
    wiped_files_count: int = 0
    # Total d'octets écrasés / supprimés
    wiped_bytes: int = 0
    # True si l'effacement sécurisé à 3 passes a été utilisé
    secure_erase_used: bool = False

    # --- Champs additionnels utiles pour l'audit ---
    # La base Redis a-t-elle été flushée ?
    redis_wiped: bool = False
    # Liste détaillée des chemins effectivement supprimés
    wiped_paths: list[str] = field(default_factory=list)
    # Liste des erreurs rencontrées (non fatales)
    errors: list[str] = field(default_factory=list)
    # Le dossier workers/ a-t-il été supprimé (self_destruct) ?
    workers_self_destructed: bool = False
    # Horodatages ISO
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str | None = None
    # Succès global (même en cas d'erreurs partielles on reste True si le
    # coeur a bien été exécuté)
    success: bool = False

    def to_json(self) -> str:
        """Sérialisation JSON indentée pour l'audit."""
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# Effacement sécurisé 3 passes (DoD 5220.22-M, version simplifiée)
# ---------------------------------------------------------------------------
def secure_overwrite_3pass(
    path: Path, audit: logging.Logger, chunk_size: int = 1 << 16
) -> int:
    """
    Écrase un fichier avec 3 passes conformes à DoD 5220.22-M :
      - Pass 1 : écriture de 0x00
      - Pass 2 : écriture de 0xFF
      - Pass 3 : écriture de bytes aléatoires

    NE fonctionne QUE sur des fichiers réguliers de taille > 0 octets.
    Pour les fichiers vides ou les dossiers, on utilise unlink()/rmtree()
    classique.

    :param path: Chemin du fichier à écraser
    :param audit: Logger d'audit pour tracer chaque opération
    :param chunk_size: Taille des blocs écrits (défaut 64 KiB)
    :return: Nombre d'octets effectivement écrits (taille fichier * 3)
    """
    size = path.stat().st_size
    if size == 0:
        audit.info(f"[SECURE_ERASE] Fichier vide, skip 3 pass : {path}")
        return 0

    audit.info(
        f"[SECURE_ERASE] Début 3-pass DoD 5220.22-M sur '{path}' "
        f"(taille={size} octets)"
    )

    bytes_written = 0

    # Passes (patron, label)
    passes = [
        (b"\x00" * chunk_size, "0x00"),
        (b"\xff" * chunk_size, "0xFF"),
        # Pass 3 : on régénère aléatoirement chunk par chunk (pas de pattern
        # pré-calculé pour éviter les 64 KiB répétitifs détectables)
        (None, "random"),
    ]

    for pattern, label in passes:
        with path.open("r+b") as fp:
            remaining = size
            while remaining > 0:
                to_write = min(chunk_size, remaining)
                if label == "random":
                    buf = os.urandom(to_write)
                else:
                    # pattern est pré-rempli, tronquer si besoin (dernier bloc)
                    buf = pattern[:to_write]
                fp.write(buf)
                bytes_written += len(buf)
                remaining -= len(buf)
            # Force l'écriture physique sur disque (best-effort)
            try:
                fp.flush()
                os.fsync(fp.fileno())
            except OSError:
                pass

    audit.info(
        f"[SECURE_ERASE] Fin 3-pass '{path}' : {bytes_written} octets écrits"
    )
    return bytes_written


# ---------------------------------------------------------------------------
# Worker principal : GhostProtocol
# ---------------------------------------------------------------------------
class GhostProtocol:
    """
    Orchestrateur du Ghost Protocol.

    Usage typique :
        gp = GhostProtocol(secure_erase=True, self_destruct=False)
        response = gp.run()
    """

    def __init__(
        self,
        secure_erase: bool = True,
        self_destruct: bool = False,
    ) -> None:
        """
        :param secure_erase: Si True, applique secure_overwrite_3pass() sur
                             tous les fichiers réguliers de taille > 0 octets
                             AVANT de les unlink() / rmtree().
        :param self_destruct: Si True, efface également le dossier workers/
                              (INCLUANT ce worker). LABO SEULEMENT !
        """
        self.secure_erase = secure_erase
        self.self_destruct = self_destruct
        self.audit = _get_audit_logger()
        self.response = GhostProtocolResponse(secure_erase_used=secure_erase)

    # ------------------------------------------------------------------
    # API publique
    # ------------------------------------------------------------------
    def run(self) -> GhostProtocolResponse:
        """
        Exécute l'ensemble du protocole de sanitisation.
        Retourne un GhostProtocolResponse une fois terminé.
        """
        audit = self.audit

        audit.critical(
            "\n"
            "    ██████╗  ██╗  ██╗ ██████╗ ███████╗ ████████╗\n"
            "    ██╔══██╗ ██║  ██║ ██╔═══╝ ██╔════╝ ╚══██╔══╝\n"
            "    ██████╔╝ ███████║ ██║     █████╗     ██║   \n"
            "    ██╔═══╝  ██╔══██║ ██║     ██╔══╝     ██║   \n"
            "    ██║      ██║  ██║ ╚██████╗ ███████╗   ██║   \n"
            "    ╚═╝      ╚═╝  ╚═╝  ╚═════╝ ╚══════╝   ╚═╝   \n"
            "              GHOST PROTOCOL INITIATED           \n"
        )
        audit.critical(
            f"Paramètres: secure_erase={self.secure_erase}, "
            f"self_destruct={self.self_destruct}"
        )

        try:
            # --- Étape 1 : Wipe Redis (existant, sécurisé en premier) ---
            self._wipe_redis()

            # --- Étape 2 : Wipe des fichiers / dossiers listés dans WIPE_PATTERNS ---
            self._wipe_all_patterns()

            # --- Étape 3 : Auto-destruction workers/ si demandé ---
            if self.self_destruct:
                self._self_destruct_workers()

            # --- Étape 4 : Success ---
            self.response.success = True

        except Exception as exc:
            msg = f"Exception fatale pendant le Ghost Protocol: {exc}"
            audit.exception(msg)
            self.response.errors.append(msg)
            self.response.success = False

        # Finalisation
        self.response.completed_at = datetime.now().isoformat()
        audit.critical(
            f"FIN Ghost Protocol : "
            f"files={self.response.wiped_files_count}, "
            f"bytes={self.response.wiped_bytes}, "
            f"redis_wiped={self.response.redis_wiped}, "
            f"secure_erase={self.response.secure_erase_used}, "
            f"success={self.response.success}"
        )
        audit.critical(f"Rapport JSON: {self.response.to_json()}")

        return self.response

    # ------------------------------------------------------------------
    # Étapes internes
    # ------------------------------------------------------------------

    def _wipe_redis(self) -> None:
        """
        Étape 1 : flushall Redis via REDIS_URL.
        Renseigne response.redis_wiped en cas de succès.
        """
        audit = self.audit
        try:
            audit.warning("[GHOST] Connexion à Redis pour flushall...")
            redis_client = redis.from_url(settings.REDIS_URL)
            dbsize_before = redis_client.dbsize()
            audit.info(
                f"[GHOST] Redis: {dbsize_before} clés avant flushall."
            )
            redis_client.flushall()
            dbsize_after = redis_client.dbsize()
            audit.critical(
                f"[GHOST] Redis flushall OK: {dbsize_before} -> {dbsize_after} clés."
            )
            self.response.redis_wiped = True
            try:
                redis_client.close()
            except Exception:
                pass
        except Exception as exc:
            msg = f"Échec wipe Redis: {exc}"
            audit.error(msg)
            self.response.errors.append(msg)

    def _wipe_all_patterns(self) -> None:
        """
        Étape 2 : itère sur WIPE_PATTERNS et applique le wipe pour chacun.
        """
        audit = self.audit
        for pattern_cfg in WIPE_PATTERNS:
            label = pattern_cfg["label"]
            glob_expr = pattern_cfg["glob"]
            is_dir = pattern_cfg.get("is_dir", False)
            recursive = pattern_cfg.get("recursive", True)
            exclude_paths = pattern_cfg.get("exclude_paths", [])
            description = pattern_cfg.get("description", label)

            audit.info(
                f"[GHOST][{label}] Traitement pattern '{description}': {glob_expr}"
            )

            # Résolution du glob
            matches = glob.glob(glob_expr, recursive=recursive)
            if not matches:
                audit.info(f"[GHOST][{label}] Aucun fichier/dossier trouvé. Skip.")
                continue

            audit.info(
                f"[GHOST][{label}] {len(matches)} chemin(s) à traiter."
            )

            for raw_path in matches:
                try:
                    path = Path(raw_path).resolve()

                    # --- Exclusions ---
                    if self._is_excluded(path, exclude_paths):
                        audit.debug(
                            f"[GHOST][{label}] Exclusion explicite : {path}"
                        )
                        continue

                    # On ne doit JAMAIS effacer le fichier d'audit lui-même
                    if path == _AUDIT_LOG_PATH.resolve():
                        audit.warning(
                            f"[GHOST][{label}] Protection anti-wipe audit log : {path}"
                        )
                        continue

                    # Traitement selon le type
                    if is_dir and path.is_dir():
                        # Dossier : wipe récursif du contenu
                        self._wipe_directory(path, pattern_label=label)
                    elif path.is_file():
                        # Fichier régulier
                        self._wipe_file(path, pattern_label=label)
                    else:
                        # Ni fichier ni dossier (symlink cassé, FIFO, etc.)
                        audit.debug(
                            f"[GHOST][{label}] Chemin non régulier, ignore: {path}"
                        )

                except Exception as exc:
                    msg = f"[{label}] Erreur sur '{raw_path}': {exc}"
                    audit.error(msg)
                    self.response.errors.append(msg)

    def _wipe_file(self, path: Path, pattern_label: str) -> None:
        """
        Supprime un fichier régulier en appliquant (optionnellement)
        l'effacement sécurisé 3 passes avant unlink().
        """
        audit = self.audit
        size = 0
        try:
            size = path.stat().st_size
        except OSError:
            pass

        audit.info(
            f"[GHOST][{pattern_label}] Suppression fichier {path} ({size} octets)"
        )

        # Pass 1 : secure erase 3 passes (si activé et fichier > 0 octets)
        if self.secure_erase and size > 0:
            try:
                written = secure_overwrite_3pass(path, audit)
                self.response.wiped_bytes += written
            except Exception as exc:
                msg = f"Échec secure_erase sur {path}: {exc}"
                audit.error(msg)
                self.response.errors.append(msg)

        # Pass 2 : unlink() final
        try:
            path.unlink()
            self.response.wiped_files_count += 1
            self.response.wiped_paths.append(str(path))
            # On ajoute aussi la taille "utile" pour que wiped_bytes
            # représente aussi la quantité de données "disparues", pas
            # seulement le volume d'écriture du secure erase.
            self.response.wiped_bytes += size
            audit.info(
                f"[GHOST][{pattern_label}] unlink OK : {path}"
            )
        except OSError as exc:
            msg = f"Échec unlink {path}: {exc}"
            audit.error(msg)
            self.response.errors.append(msg)

    def _wipe_directory(self, path: Path, pattern_label: str) -> None:
        """
        Supprime un dossier récursivement.
        D'abord, parcourt les fichiers à l'intérieur pour secure_erase 3 passes,
        puis shutil.rmtree() pour la structure.
        """
        audit = self.audit

        # Si secure_erase : on itère d'abord sur TOUS les fichiers du dossier
        # pour appliquer le 3-pass sur chacun AVANT de rmtree().
        if self.secure_erase:
            for sub_file in path.rglob("*"):
                if sub_file.is_file():
                    try:
                        size = sub_file.stat().st_size
                        if size > 0:
                            written = secure_overwrite_3pass(sub_file, audit)
                            self.response.wiped_bytes += written
                    except Exception as exc:
                        msg = f"Échec secure_erase sous-fichier {sub_file}: {exc}"
                        audit.error(msg)
                        self.response.errors.append(msg)

        # On compte récursivement les fichiers et la taille avant rmtree
        local_files = 0
        local_bytes = 0
        try:
            for sub in path.rglob("*"):
                if sub.is_file():
                    local_files += 1
                    try:
                        local_bytes += sub.stat().st_size
                    except OSError:
                        pass
        except Exception:
            pass

        audit.info(
            f"[GHOST][{pattern_label}] Suppression dossier {path} "
            f"({local_files} fichiers, {local_bytes} octets)"
        )

        try:
            shutil.rmtree(path)
            # +1 pour le dossier racine + les sous-fichiers = totalité
            self.response.wiped_files_count += local_files + 1
            self.response.wiped_bytes += local_bytes
            self.response.wiped_paths.append(str(path))
            audit.info(f"[GHOST][{pattern_label}] rmtree OK : {path}")
        except OSError as exc:
            msg = f"Échec rmtree {path}: {exc}"
            audit.error(msg)
            self.response.errors.append(msg)

    def _self_destruct_workers(self) -> None:
        """
        Étape 3 : self-destruction du dossier workers/ (si self_destruct=True).
        ATTENTION : cette opération supprime CE fichier lui-même.
        """
        audit = self.audit
        workers_path = _WORKERS_DIR.resolve()
        audit.critical(
            f"[GHOST][SELF_DESTRUCT] Déclenchement auto-destruction workers/: {workers_path}"
        )
        audit.critical(
            "[GHOST][SELF_DESTRUCT] ⚠️  LABO SEULEMENT ! Les workers seront indisponibles après."
        )

        # 1) Secure erase de TOUS les fichiers du dossier workers/
        if self.secure_erase:
            for sub_file in workers_path.rglob("*"):
                if sub_file.is_file():
                    try:
                        size = sub_file.stat().st_size
                        if size > 0:
                            written = secure_overwrite_3pass(sub_file, audit)
                            self.response.wiped_bytes += written
                    except Exception as exc:
                        msg = f"Échec secure_erase (self_destruct) {sub_file}: {exc}"
                        audit.error(msg)
                        self.response.errors.append(msg)

        # 2) Compte avant rmtree
        local_files = 0
        local_bytes = 0
        try:
            for sub in workers_path.rglob("*"):
                if sub.is_file():
                    local_files += 1
                    try:
                        local_bytes += sub.stat().st_size
                    except OSError:
                        pass
        except Exception:
            pass

        # 3) rmtree final
        try:
            shutil.rmtree(workers_path)
            self.response.wiped_files_count += local_files + 1  # +1 dossier racine
            self.response.wiped_bytes += local_bytes
            self.response.wiped_paths.append(str(workers_path))
            self.response.workers_self_destructed = True
            audit.critical(
                f"[GHOST][SELF_DESTRUCT] workers/ supprimé avec succès "
                f"({local_files} fichiers, {local_bytes} octets)."
            )
        except OSError as exc:
            msg = f"Échec self_destruct workers/: {exc}"
            audit.error(msg)
            self.response.errors.append(msg)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_excluded(path: Path, exclude_paths: list[Path]) -> bool:
        """
        Retourne True si `path` est dans la liste des exclusions
        (ou est un sous-fichier d'un dossier exclu).
        """
        resolved = path.resolve()
        for excl in exclude_paths:
            excl_resolved = Path(excl).resolve()
            if resolved == excl_resolved:
                return True
            # Sous-chemin ?
            try:
                resolved.relative_to(excl_resolved)
                return True
            except ValueError:
                continue
        return False


# ---------------------------------------------------------------------------
# Tâche Celery exposée sur le bus
# ---------------------------------------------------------------------------
@app.task(name='vantablack.system.initiate_ghost_protocol')
def initiate_ghost_protocol(
    secure_erase: bool = True,
    self_destruct: bool = False,
) -> dict[str, Any]:
    """
    Initiates the Ghost Protocol: a self-destruct and sanitization sequence.
    Tâche Celery appellable via .delay() ou .apply_async().

    Paramètres (optionnels, compatible .delay(secure_erase=True, ...)) :
      - secure_erase : applique 3 passes d'écriture avant suppression
        (défaut True)
      - self_destruct : si True, supprime aussi le dossier workers/
        (DANGEREUX, LABO SEULEMENT, défaut False)

    Retour : le GhostProtocolResponse converti en dict (serializable JSON
    par le result backend Redis).
    """
    logger.critical("\n"
        "    ██████╗  ██╗  ██╗ ██████╗ ███████╗ ████████╗\n"
        "    ██╔══██╗ ██║  ██║ ██╔═══╝ ██╔════╝ ╚══██╔══╝\n"
        "    ██████╔╝ ███████║ ██║     █████╗     ██║   \n"
        "    ██╔═══╝  ██╔══██║ ██║     ██╔══╝     ██║   \n"
        "    ██║      ██║  ██║ ╚██████╗ ███████╗   ██║   \n"
        "    ╚═╝      ╚═╝  ╚═╝  ╚═════╝ ╚══════╝   ╚═╝   \n"
        "              GHOST PROTOCOL INITIATED           \n"
        "              (via Celery task)                  \n"
    )

    logger.critical(
        f"[GHOST] secure_erase={secure_erase}, self_destruct={self_destruct}"
    )

    try:
        gp = GhostProtocol(
            secure_erase=secure_erase,
            self_destruct=self_destruct,
        )
        response = gp.run()
        return asdict(response)

    except Exception as e:
        logger.error(f"[GHOST] Error during sanitization: {e}")
        return {
            "success": False,
            "errors": [str(e)],
            "secure_erase_used": secure_erase,
            "wiped_files_count": 0,
            "wiped_bytes": 0,
            "redis_wiped": False,
            "workers_self_destructed": False,
        }


# ---------------------------------------------------------------------------
# Point d'entrée CLI pour exécution directe
#   python -m workers.ghost_protocol_worker --secure --self-destruct
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Ghost Protocol : sanitisation VANTABLACK (LABO SEULEMENT)"
    )
    parser.add_argument(
        "--secure-erase",
        action="store_true",
        default=True,
        help="Active l'effacement sécurisé 3 passes (défaut: activé)",
    )
    parser.add_argument(
        "--no-secure-erase",
        action="store_true",
        help="Désactive l'effacement sécurisé (suppression simple)",
    )
    parser.add_argument(
        "--self-destruct",
        action="store_true",
        default=False,
        help="Supprime aussi le dossier workers/ apès exécution (LABO SEULEMENT)",
    )
    args = parser.parse_args()

    secure = False if args.no_secure_erase else args.secure_erase

    gp = GhostProtocol(secure_erase=secure, self_destruct=args.self_destruct)
    r = gp.run()
    print()
    print("=" * 60)
    print("Rapport Ghost Protocol")
    print("=" * 60)
    print(r.to_json())

# To run this worker:
# celery -A workers.ghost_protocol_worker worker --loglevel=info -n ghost@%h

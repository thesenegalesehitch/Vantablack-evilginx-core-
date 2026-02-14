"""
VANTABLACK Mutation Engine
==========================

Advanced phishlet mutation system for bypassing detection:
- Domain variation generation
- Path obfuscation techniques
- JavaScript polymorphism
- Anti-analysis evasion
- Template randomization
"""

from .mutator import PhishletMutator
from .domain_generator import DomainGenerator
from .obfuscator import JavaScriptObfuscator
from .evasion_engine import EvasionEngine

__all__ = ["PhishletMutator", "DomainGenerator", "JavaScriptObfuscator", "EvasionEngine"]

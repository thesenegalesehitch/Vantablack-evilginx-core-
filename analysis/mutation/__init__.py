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

from .domain_generator import DomainGenerator
from .evasion_engine import EvasionEngine
from .mutator import PhishletMutator
from .obfuscator import JavaScriptObfuscator

__all__ = ["DomainGenerator", "EvasionEngine", "JavaScriptObfuscator", "PhishletMutator"]

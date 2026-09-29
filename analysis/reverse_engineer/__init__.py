"""
VANTABLACK Reverse Engineering Module
======================================

Automatic analysis and reverse engineering of phishing kits and phishlets.
Generates detection signatures and extracts behavioral patterns.
"""

from .analyzer import PhishletAnalyzer
from .pattern_extractor import PatternExtractor
from .signature_generator import SignatureGenerator

__all__ = ["PatternExtractor", "PhishletAnalyzer", "SignatureGenerator"]

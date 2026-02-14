"""
VANTABLACK Reverse Engineering Module
======================================

Automatic analysis and reverse engineering of phishing kits and phishlets.
Generates detection signatures and extracts behavioral patterns.
"""

from .analyzer import PhishletAnalyzer
from .signature_generator import SignatureGenerator
from .pattern_extractor import PatternExtractor

__all__ = ["PhishletAnalyzer", "SignatureGenerator", "PatternExtractor"]

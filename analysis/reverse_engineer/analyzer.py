"""
Phishlet Analyzer - Automatic Reverse Engineering
================================================

Analyzes Evilginx phishlets to extract:
- Domain patterns
- Authentication flows
- Data extraction points
- JavaScript obfuscation techniques
- Anti-detection mechanisms
"""

import yaml
import json
import re
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class PhishletStructure:
    """Structure of an analyzed phishlet"""
    name: str
    target_domain: str
    auth_subdomains: List[str]
    login_paths: List[str]
    post_data_paths: List[str]
    javascript_patterns: List[str]
    anti_detection: List[str]
    data_extraction: Dict[str, Any]
    risk_score: float


class PhishletAnalyzer:
    """
    Automatic reverse engineering of Evilginx phishlets.
    Extracts actionable intelligence from phishing kits.
    """
    
    def __init__(self):
        self.patterns = {
            'login_paths': [
                r'/login', r'/signin', r'/auth', r'/oauth',
                r'/api/login', r'/api/auth', r'/v1/auth'
            ],
            'sensitive_data': [
                r'password', r'passwd', r'secret', r'token',
                r'csrf', r'session', r'cookie', r'auth'
            ],
            'anti_detection': [
                r'sandbox', r'debugger', r'devtools', r'console',
                r'selenium', r'webdriver', r'headless'
            ],
            'obfuscation': [
                r'eval\(', r'atob\(', r'btoa\(', r'\\x[0-9a-f]{2}',
                r'unescape\(', r'String\.fromCharCode'
            ]
        }
    
    async def analyze_phishlet(self, phishlet_path: str) -> PhishletStructure:
        """
        Perform complete analysis of a phishlet file.
        
        Args:
            phishlet_path: Path to the .yaml phishlet file
            
        Returns:
            PhishletStructure with all extracted information
        """
        try:
            # Load phishlet configuration
            with open(phishlet_path, 'r') as f:
                phishlet_data = yaml.safe_load(f)
            
            # Extract basic information
            name = phishlet_data.get('name', 'Unknown')
            target_domain = phishlet_data.get('author', {}).get('domain', '')
            
            # Analyze domain structure
            auth_subdomains = self._extract_auth_subdomains(phishlet_data)
            
            # Analyze authentication flow
            login_paths = self._extract_login_paths(phishlet_data)
            post_data_paths = self._extract_post_paths(phishlet_data)
            
            # Extract JavaScript patterns (if present)
            javascript_patterns = await self._analyze_javascript(phishlet_path)
            
            # Detect anti-detection mechanisms
            anti_detection = self._detect_anti_detection(phishlet_data)
            
            # Extract data extraction points
            data_extraction = self._extract_data_points(phishlet_data)
            
            # Calculate risk score
            risk_score = self._calculate_risk_score(
                auth_subdomains, login_paths, anti_detection
            )
            
            return PhishletStructure(
                name=name,
                target_domain=target_domain,
                auth_subdomains=auth_subdomains,
                login_paths=login_paths,
                post_data_paths=post_data_paths,
                javascript_patterns=javascript_patterns,
                anti_detection=anti_detection,
                data_extraction=data_extraction,
                risk_score=risk_score
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze phishlet {phishlet_path}: {e}")
            raise
    
    def _extract_auth_subdomains(self, phishlet_data: Dict) -> List[str]:
        """Extract authentication subdomains from phishlet config"""
        subdomains = []
        
        # Extract from subdomain section
        for subdomain_config in phishlet_data.get('subdomains', []):
            if 'auth' in subdomain_config.get('subdomain', '').lower():
                subdomains.append(subdomain_config.get('subdomain'))
        
        # Extract from redirect rules
        for rule in phishlet_data.get('redirect_rules', []):
            domain = rule.get('domain', '')
            if any(x in domain.lower() for x in ['login', 'auth', 'secure']):
                subdomains.append(domain)
        
        return list(set(subdomains))
    
    def _extract_login_paths(self, phishlet_data: Dict) -> List[str]:
        """Extract login/authentication paths"""
        paths = []
        
        # Extract from redirect rules
        for rule in phishlet_data.get('redirect_rules', []):
            path = rule.get('path', '')
            if any(re.search(pattern, path, re.IGNORECASE) 
                   for pattern in self.patterns['login_paths']):
                paths.append(path)
        
        return list(set(paths))
    
    def _extract_post_paths(self, phishlet_data: Dict) -> List[str]:
        """Extract paths that handle POST requests"""
        paths = []
        
        for rule in phishlet_data.get('redirect_rules', []):
            if rule.get('method') == 'POST':
                paths.append(rule.get('path', ''))
        
        return list(set(paths))
    
    async def _analyze_javascript(self, phishlet_path: Path) -> List[str]:
        """Analyze JavaScript files for patterns"""
        patterns = []
        
        # Look for associated JS files
        phishlet_dir = Path(phishlet_path).parent
        js_files = list(phishlet_dir.glob("*.js"))
        
        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8') as f:
                    js_content = f.read()
                
                # Check for obfuscation patterns
                for pattern in self.patterns['obfuscation']:
                    if re.search(pattern, js_content, re.IGNORECASE):
                        patterns.append(f"obfuscation:{pattern}")
                
                # Check for anti-detection patterns
                for pattern in self.patterns['anti_detection']:
                    if re.search(pattern, js_content, re.IGNORECASE):
                        patterns.append(f"anti_detection:{pattern}")
                        
            except Exception as e:
                logger.warning(f"Failed to analyze JS file {js_file}: {e}")
        
        return patterns
    
    def _detect_anti_detection(self, phishlet_data: Dict) -> List[str]:
        """Detect anti-detection mechanisms"""
        mechanisms = []
        
        # Check for custom headers
        for rule in phishlet_data.get('redirect_rules', []):
            headers = rule.get('headers', {})
            for header, value in headers.items():
                if any(pattern in value.lower() 
                       for pattern in ['bot', 'detect', 'block']):
                    mechanisms.append(f"header:{header}")
        
        # Check for special parameters
        for rule in phishlet_data.get('redirect_rules', []):
            params = rule.get('params', {})
            for param in params:
                if any(pattern in param.lower() 
                       for pattern in ['bot', 'detect', 'check']):
                    mechanisms.append(f"param:{param}")
        
        return mechanisms
    
    def _extract_data_points(self, phishlet_data: Dict) -> Dict[str, Any]:
        """Extract data extraction points"""
        extraction_points = {}
        
        for rule in phishlet_data.get('redirect_rules', []):
            if rule.get('method') == 'POST':
                path = rule.get('path', '')
                
                # Extract form fields
                content_type = rule.get('content_type', '')
                if 'json' in content_type.lower():
                    extraction_points[path] = {
                        'type': 'json',
                        'fields': self._extract_json_fields(rule)
                    }
                else:
                    extraction_points[path] = {
                        'type': 'form',
                        'fields': self._extract_form_fields(rule)
                    }
        
        return extraction_points
    
    def _extract_json_fields(self, rule: Dict) -> List[str]:
        """Extract JSON field names from POST data"""
        # This would need to be implemented based on actual POST data samples
        return ['username', 'password', 'csrf_token']
    
    def _extract_form_fields(self, rule: Dict) -> List[str]:
        """Extract form field names from POST data"""
        # This would need to be implemented based on actual POST data samples
        return ['login', 'passwd', 'csrf']
    
    def _calculate_risk_score(self, subdomains: List[str], 
                            paths: List[str], 
                            anti_detection: List[str]) -> float:
        """Calculate risk score based on complexity and sophistication"""
        score = 0.0
        
        # Base score for number of subdomains
        score += len(subdomains) * 0.1
        
        # Score for authentication paths
        score += len(paths) * 0.05
        
        # Score for anti-detection mechanisms
        score += len(anti_detection) * 0.2
        
        # Cap at 10.0
        return min(score, 10.0)
    
    async def batch_analyze(self, phishlet_dir: str) -> List[PhishletStructure]:
        """Analyze all phishlets in a directory"""
        results = []
        
        phishlet_files = list(Path(phishlet_dir).glob("*.yaml"))
        
        tasks = [self.analyze_phishlet(str(f)) for f in phishlet_files]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        return [r for r in results if isinstance(r, PhishletStructure)]

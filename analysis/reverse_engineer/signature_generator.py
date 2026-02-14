"""
Signature Generator - Detection Signature Creation
==================================================

Generates detection signatures from analyzed phishlets:
- YARA rules for malware detection
- Snort/Suricata rules for network detection
- Regex patterns for log analysis
- IOC lists for threat intelligence
"""

import re
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import hashlib

from .analyzer import PhishletStructure


@dataclass
class DetectionSignature:
    """Detection signature for security tools"""
    name: str
    description: str
    signature_type: str  # yara, snort, regex, ioc
    pattern: str
    severity: str  # low, medium, high, critical
    tags: List[str]
    created_at: datetime


class SignatureGenerator:
    """
    Generates detection signatures from phishlet analysis.
    Creates rules for various security tools.
    """
    
    def __init__(self):
        self.signature_templates = {
            'yara': '''
rule VANTABLACK_Phishlet_{name}_{hash} {{
    meta:
        description = "{description}"
        author = "VANTABLACK"
        date = "{date}"
        hash = "{hash}"
        severity = "{severity}"
    strings:
        {strings}
    condition:
        {condition}
}}
''',
            'snort': '''
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (
    msg:"VANTABLACK Phishlet Detection - {name}";
    flow:to_server,established;
    content:"{content}"; http_uri;
    {additional_content}
    classtype:web-application-attack;
    sid:{sid};
    rev:1;
)
''',
            'regex': r'(?i)(?:{pattern})',
            'ioc': '{type}:{value}'
        }
    
    def generate_all_signatures(self, phishlet: PhishletStructure) -> List[DetectionSignature]:
        """Generate all types of signatures for a phishlet"""
        signatures = []
        
        # Generate YARA rule
        yara_sig = self._generate_yara_signature(phishlet)
        if yara_sig:
            signatures.append(yara_sig)
        
        # Generate Snort rule
        snort_sig = self._generate_snort_signature(phishlet)
        if snort_sig:
            signatures.append(snort_sig)
        
        # Generate regex patterns
        regex_sigs = self._generate_regex_signatures(phishlet)
        signatures.extend(regex_sigs)
        
        # Generate IOCs
        ioc_sigs = self._generate_ioc_signatures(phishlet)
        signatures.extend(ioc_sigs)
        
        return signatures
    
    def _generate_yara_signature(self, phishlet: PhishletStructure) -> Optional[DetectionSignature]:
        """Generate YARA rule for file-based detection"""
        try:
            # Create unique hash for this signature
            content_hash = hashlib.md5(
                f"{phishlet.name}{phishlet.target_domain}".encode()
            ).hexdigest()[:8]
            
            # Extract strings for YARA rule
            strings = []
            
            # Add domain patterns
            if phishlet.target_domain:
                strings.append(f'$domain = "{phishlet.target_domain}"')
            
            # Add path patterns
            for path in phishlet.login_paths:
                if len(path) > 3:  # Avoid too short patterns
                    escaped_path = re.escape(path)
                    strings.append(f'$path_{len(strings)} = "{escaped_path}"')
            
            # Add JavaScript patterns
            for pattern in phishlet.javascript_patterns:
                if len(pattern) > 5:
                    escaped_pattern = re.escape(pattern)
                    strings.append(f'$js_{len(strings)} = "{escaped_pattern}"')
            
            if not strings:
                return None
            
            # Build YARA rule
            strings_str = '\n        '.join(strings)
            
            # Simple condition - match any of the strings
            condition = 'any of them'
            
            yara_pattern = self.signature_templates['yara'].format(
                name=re.sub(r'[^a-zA-Z0-9]', '_', phishlet.name),
                hash=content_hash,
                description=f"Detection rule for {phishlet.name} phishlet",
                date=datetime.now().strftime('%Y-%m-%d'),
                severity='high' if phishlet.risk_score > 7 else 'medium',
                strings=strings_str,
                condition=condition
            )
            
            return DetectionSignature(
                name=f"YARA_{phishlet.name}_{content_hash}",
                description=f"YARA rule for {phishlet.name} phishlet detection",
                signature_type='yara',
                pattern=yara_pattern.strip(),
                severity='high' if phishlet.risk_score > 7 else 'medium',
                tags=['phishing', 'evilginx', 'credential-theft'],
                created_at=datetime.now()
            )
            
        except Exception as e:
            print(f"Failed to generate YARA signature: {e}")
            return None
    
    def _generate_snort_signature(self, phishlet: PhishletStructure) -> Optional[DetectionSignature]:
        """Generate Snort/Suricata rule for network detection"""
        try:
            # Use the most distinctive login path
            if not phishlet.login_paths:
                return None
            
            # Select the most specific path
            best_path = max(phishlet.login_paths, key=len)
            
            # Generate SID (should be unique)
            sid = hash(f"{phishlet.name}{best_path}") % 1000000 + 2000000
            
            # Build additional content for anti-detection
            additional_content = ""
            if phishlet.anti_detection:
                for mechanism in phishlet.anti_detection[:2]:  # Limit to 2
                    additional_content += f'content:"{mechanism}";\n    '
            
            snort_pattern = self.signature_templates['snort'].format(
                name=phishlet.name,
                content=re.escape(best_path),
                additional_content=additional_content,
                sid=sid
            )
            
            return DetectionSignature(
                name=f"SNORT_{phishlet.name}_{sid}",
                description=f"Snort rule for {phishlet.name} network detection",
                signature_type='snort',
                pattern=snort_pattern.strip(),
                severity='high' if phishlet.risk_score > 7 else 'medium',
                tags=['phishing', 'network', 'credential-theft'],
                created_at=datetime.now()
            )
            
        except Exception as e:
            print(f"Failed to generate Snort signature: {e}")
            return None
    
    def _generate_regex_signatures(self, phishlet: PhishletStructure) -> List[DetectionSignature]:
        """Generate regex patterns for log analysis"""
        signatures = []
        
        # Generate domain regex
        if phishlet.target_domain:
            domain_pattern = re.escape(phishlet.target_domain).replace('\\*', '.*')
            regex_pattern = self.signature_templates['regex'].format(
                pattern=domain_pattern
            )
            
            signatures.append(DetectionSignature(
                name=f"REGEX_DOMAIN_{phishlet.name}",
                description=f"Domain regex for {phishlet.name}",
                signature_type='regex',
                pattern=regex_pattern,
                severity='medium',
                tags=['domain', 'phishing'],
                created_at=datetime.now()
            ))
        
        # Generate path regexes
        for path in phishlet.login_paths:
            if len(path) > 3:
                escaped_path = re.escape(path)
                regex_pattern = self.signature_templates['regex'].format(
                    pattern=escaped_path
                )
                
                signatures.append(DetectionSignature(
                    name=f"REGEX_PATH_{phishlet.name}_{len(signatures)}",
                    description=f"Path regex for {path} in {phishlet.name}",
                    signature_type='regex',
                    pattern=regex_pattern,
                    severity='low',
                    tags=['path', 'phishing'],
                    created_at=datetime.now()
                ))
        
        return signatures
    
    def _generate_ioc_signatures(self, phishlet: PhishletStructure) -> List[DetectionSignature]:
        """Generate Indicators of Compromise"""
        signatures = []
        
        # Domain IOC
        if phishlet.target_domain:
            ioc_pattern = self.signature_templates['ioc'].format(
                type='domain',
                value=phishlet.target_domain
            )
            
            signatures.append(DetectionSignature(
                name=f"IOC_DOMAIN_{phishlet.name}",
                description=f"Domain IOC for {phishlet.name}",
                signature_type='ioc',
                pattern=ioc_pattern,
                severity='high',
                tags=['ioc', 'domain', 'phishing'],
                created_at=datetime.now()
            ))
        
        # URL IOCs (combine domain with paths)
        for path in phishlet.login_paths:
            if phishlet.target_domain and len(path) > 3:
                url = f"https://{phishlet.target_domain}{path}"
                ioc_pattern = self.signature_templates['ioc'].format(
                    type='url',
                    value=url
                )
                
                signatures.append(DetectionSignature(
                    name=f"IOC_URL_{phishlet.name}_{len(signatures)}",
                    description=f"URL IOC for {url}",
                    signature_type='ioc',
                    pattern=ioc_pattern,
                    severity='high',
                    tags=['ioc', 'url', 'phishing'],
                    created_at=datetime.now()
                ))
        
        return signatures
    
    def export_signatures(self, signatures: List[DetectionSignature], 
                         output_format: str = 'json') -> str:
        """Export signatures in specified format"""
        if output_format == 'json':
            return json.dumps([
                {
                    'name': sig.name,
                    'description': sig.description,
                    'type': sig.signature_type,
                    'pattern': sig.pattern,
                    'severity': sig.severity,
                    'tags': sig.tags,
                    'created_at': sig.created_at.isoformat()
                }
                for sig in signatures
            ], indent=2)
        
        elif output_format == 'yara':
            yara_rules = [sig.pattern for sig in signatures 
                         if sig.signature_type == 'yara']
            return '\n\n'.join(yara_rules)
        
        elif output_format == 'snort':
            snort_rules = [sig.pattern for sig in signatures 
                          if sig.signature_type == 'snort']
            return '\n'.join(snort_rules)
        
        else:
            return json.dumps([sig.pattern for sig in signatures], indent=2)

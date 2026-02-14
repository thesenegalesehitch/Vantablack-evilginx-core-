"""
Pattern Extractor - Behavioral Pattern Analysis
===============================================

Extracts behavioral patterns from phishlets:
- Attack flow patterns
- Data exfiltration methods
- Evasion techniques
- Campaign characteristics
"""

import re
import json
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from collections import defaultdict, Counter
import networkx as nx

from .analyzer import PhishletStructure


@dataclass
class AttackPattern:
    """Attack pattern extracted from phishlet analysis"""
    pattern_id: str
    name: str
    description: str
    attack_flow: List[str]
    techniques: List[str]
    data_points: List[str]
    evasion_methods: List[str]
    confidence: float
    severity: str


class PatternExtractor:
    """
    Extracts and analyzes behavioral patterns from phishlets.
    Builds attack flow graphs and identifies TTPs.
    """
    
    def __init__(self):
        self.attack_flows = {
            'credential_harvesting': [
                'initial_access', 'credential_phishing', 
                'data_collection', 'exfiltration'
            ],
            'session_hijacking': [
                'initial_access', 'session_theft', 
                'lateral_movement', 'persistence'
            ],
            'multi_factor_bypass': [
                'initial_access', 'mfa_interception',
                'session_hijack', 'privilege_escalation'
            ]
        }
        
        self.techniques = {
            'reverse_proxy': 'T1071 - Application Layer Protocol',
            'credential_harvesting': 'T1056 - Credential Access',
            'session_hijacking': 'T1550 - Use Alternate Authentication Material',
            'data_exfiltration': 'T1041 - Exfiltration Over C2 Channel',
            'anti_analysis': 'T1082 - System Information Discovery'
        }
    
    def extract_patterns(self, phishlet: PhishletStructure) -> List[AttackPattern]:
        """Extract all attack patterns from a phishlet"""
        patterns = []
        
        # Analyze attack flow
        flow_pattern = self._analyze_attack_flow(phishlet)
        if flow_pattern:
            patterns.append(flow_pattern)
        
        # Analyze data exfiltration patterns
        exfil_pattern = self._analyze_exfiltration_pattern(phishlet)
        if exfil_pattern:
            patterns.append(exfil_pattern)
        
        # Analyze evasion patterns
        evasion_pattern = self._analyze_evasion_pattern(phishlet)
        if evasion_pattern:
            patterns.append(evasion_pattern)
        
        # Analyze sophistication patterns
        soph_pattern = self._analyze_sophistication_pattern(phishlet)
        if soph_pattern:
            patterns.append(soph_pattern)
        
        return patterns
    
    def _analyze_attack_flow(self, phishlet: PhishletStructure) -> Optional[AttackPattern]:
        """Analyze the attack flow pattern"""
        try:
            # Build attack flow graph
            flow_graph = nx.DiGraph()
            
            # Initial access - always present
            flow_graph.add_node('initial_access', type='access')
            
            # Check for credential harvesting
            if phishlet.post_data_paths:
                flow_graph.add_node('credential_phishing', type='collection')
                flow_graph.add_edge('initial_access', 'credential_phishing')
            
            # Check for session handling
            if any('session' in path.lower() for path in phishlet.post_data_paths):
                flow_graph.add_node('session_hijacking', type='privilege')
                flow_graph.add_edge('credential_phishing', 'session_hijacking')
            
            # Check for data collection
            if phishlet.data_extraction:
                flow_graph.add_node('data_collection', type='collection')
                if 'credential_phishing' in flow_graph:
                    flow_graph.add_edge('credential_phishing', 'data_collection')
                else:
                    flow_graph.add_edge('initial_access', 'data_collection')
            
            # Determine attack pattern type
            if len(flow_graph.nodes) >= 3:
                if 'session_hijacking' in flow_graph.nodes:
                    pattern_type = 'session_hijacking'
                    confidence = 0.8
                else:
                    pattern_type = 'credential_harvesting'
                    confidence = 0.6
            else:
                pattern_type = 'simple_phishing'
                confidence = 0.4
            
            return AttackPattern(
                pattern_id=f"flow_{phishlet.name}_{hash(phishlet.name) % 10000}",
                name=f"{pattern_type.replace('_', ' ').title()} Pattern",
                description=f"Attack flow identified as {pattern_type}",
                attack_flow=list(flow_graph.nodes),
                techniques=[self.techniques.get('credential_harvesting', 'Unknown')],
                data_points=list(phishlet.data_extraction.keys()),
                evasion_methods=phishlet.anti_detection,
                confidence=confidence,
                severity='high' if phishlet.risk_score > 7 else 'medium'
            )
            
        except Exception as e:
            print(f"Failed to analyze attack flow: {e}")
            return None
    
    def _analyze_exfiltration_pattern(self, phishlet: PhishletStructure) -> Optional[AttackPattern]:
        """Analyze data exfiltration patterns"""
        try:
            exfil_methods = []
            data_types = []
            
            # Analyze data extraction points
            for path, config in phishlet.data_extraction.items():
                if config.get('type') == 'json':
                    exfil_methods.append('json_api')
                else:
                    exfil_methods.append('form_post')
                
                # Extract field types
                fields = config.get('fields', [])
                for field in fields:
                    if any(pwd in field.lower() for pwd in ['pass', 'pwd', 'secret']):
                        data_types.append('credentials')
                    elif any(token in field.lower() for token in ['csrf', 'token', 'session']):
                        data_types.append('session_tokens')
                    else:
                        data_types.append('user_data')
            
            if not exfil_methods:
                return None
            
            # Determine sophistication
            sophistication = 'low'
            if len(set(exfil_methods)) > 1:
                sophistication = 'medium'
            if 'json_api' in exfil_methods:
                sophistication = 'high'
            
            return AttackPattern(
                pattern_id=f"exfil_{phishlet.name}_{hash(phishlet.name) % 10000}",
                name="Data Exfiltration Pattern",
                description=f"Exfiltration using {', '.join(set(exfil_methods))}",
                attack_flow=['data_collection', 'exfiltration'],
                techniques=[self.techniques.get('data_exfiltration', 'Unknown')],
                data_points=data_types,
                evasion_methods=[],
                confidence=0.7,
                severity='high' if sophistication == 'high' else 'medium'
            )
            
        except Exception as e:
            print(f"Failed to analyze exfiltration pattern: {e}")
            return None
    
    def _analyze_evasion_pattern(self, phishlet: PhishletStructure) -> Optional[AttackPattern]:
        """Analyze evasion and anti-detection patterns"""
        try:
            if not phishlet.anti_detection:
                return None
            
            evasion_categories = defaultdict(list)
            
            # Categorize evasion techniques
            for technique in phishlet.anti_detection:
                if 'header' in technique:
                    evasion_categories['header_manipulation'].append(technique)
                elif 'param' in technique:
                    evasion_categories['parameter_filtering'].append(technique)
                elif 'javascript' in technique.lower():
                    evasion_categories['client_side_detection'].append(technique)
                else:
                    evasion_categories['other'].append(technique)
            
            # Determine sophistication level
            sophistication_score = len(evasion_categories) * 0.3
            sophistication_score += len(phishlet.anti_detection) * 0.1
            
            if sophistication_score > 1.0:
                sophistication = 'advanced'
                severity = 'high'
            elif sophistication_score > 0.5:
                sophistication = 'moderate'
                severity = 'medium'
            else:
                sophistication = 'basic'
                severity = 'low'
            
            return AttackPattern(
                pattern_id=f"evasion_{phishlet.name}_{hash(phishlet.name) % 10000}",
                name=f"Evasion Pattern - {sophistication.title()}",
                description=f"Anti-detection techniques: {', '.join(evasion_categories.keys())}",
                attack_flow=['evasion_preparation', 'attack_execution'],
                techniques=[self.techniques.get('anti_analysis', 'Unknown')],
                data_points=[],
                evasion_methods=phishlet.anti_detection,
                confidence=min(sophistication_score, 1.0),
                severity=severity
            )
            
        except Exception as e:
            print(f"Failed to analyze evasion pattern: {e}")
            return None
    
    def _analyze_sophistication_pattern(self, phishlet: PhishletStructure) -> Optional[AttackPattern]:
        """Analyze overall sophistication patterns"""
        try:
            sophistication_indicators = {
                'multiple_subdomains': len(phishlet.auth_subdomains) > 2,
                'complex_paths': len(phishlet.login_paths) > 3,
                'javascript_obfuscation': any('obfuscation' in p for p in phishlet.javascript_patterns),
                'anti_detection': len(phishlet.anti_detection) > 0,
                'high_risk_score': phishlet.risk_score > 7
            }
            
            sophistication_score = sum(sophistication_indicators.values()) / len(sophistication_indicators)
            
            if sophistication_score < 0.3:
                sophistication_level = 'low'
                description = 'Basic phishing kit with minimal sophistication'
            elif sophistication_score < 0.7:
                sophistication_level = 'moderate'
                description = 'Intermediate phishing techniques present'
            else:
                sophistication_level = 'advanced'
                description = 'Advanced phishing with multiple evasion techniques'
            
            return AttackPattern(
                pattern_id=f"soph_{phishlet.name}_{hash(phishlet.name) % 10000}",
                name=f"Sophistication Pattern - {sophistication_level.title()}",
                description=description,
                attack_flow=[],
                techniques=[],
                data_points=[],
                evasion_methods=list(sophistication_indicators.keys()),
                confidence=sophistication_score,
                severity='high' if sophistication_score > 0.7 else 'medium'
            )
            
        except Exception as e:
            print(f"Failed to analyze sophistication pattern: {e}")
            return None
    
    def batch_extract_patterns(self, phishlets: List[PhishletStructure]) -> Dict[str, Any]:
        """Extract patterns from multiple phishlets and identify trends"""
        all_patterns = []
        
        for phishlet in phishlets:
            patterns = self.extract_patterns(phishlet)
            all_patterns.extend(patterns)
        
        # Analyze trends
        pattern_types = Counter([p.name for p in all_patterns])
        techniques_used = Counter()
        evasion_methods = Counter()
        
        for pattern in all_patterns:
            techniques_used.update(pattern.techniques)
            evasion_methods.update(pattern.evasion_methods)
        
        return {
            'total_patterns': len(all_patterns),
            'pattern_distribution': dict(pattern_types),
            'common_techniques': dict(techniques_used.most_common(10)),
            'common_evasion': dict(evasion_methods.most_common(10)),
            'patterns': all_patterns
        }
    
    def generate_mitre_report(self, patterns: List[AttackPattern]) -> Dict[str, Any]:
        """Generate MITRE ATT&CK aligned report"""
        tactics = defaultdict(list)
        techniques = defaultdict(list)
        
        for pattern in patterns:
            for technique in pattern.techniques:
                # Extract MITRE technique ID and name
                if 'T' in technique:
                    tech_id = technique.split(' - ')[0]
                    tech_name = technique.split(' - ')[1] if ' - ' in technique else technique
                    
                    techniques[tech_id].append({
                        'name': tech_name,
                        'pattern': pattern.name,
                        'confidence': pattern.confidence,
                        'severity': pattern.severity
                    })
        
        return {
            'summary': {
                'total_techniques': len(techniques),
                'high_confidence': len([p for p in patterns if p.confidence > 0.7]),
                'critical_severity': len([p for p in patterns if p.severity == 'critical'])
            },
            'techniques': dict(techniques),
            'patterns': patterns
        }

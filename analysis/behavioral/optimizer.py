"""
Campaign Optimizer - Performance Optimization Engine
===================================================

Optimizes phishing campaigns based on behavioral data:
- A/B testing management
- Conversion rate optimization
- Landing page optimization
- Email campaign optimization
- Real-time optimization
"""

import json
import statistics
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import numpy as np


@dataclass
class ABTest:
    """A/B test configuration and results"""
    test_id: str
    name: str
    description: str
    variants: List[Dict[str, Any]]
    traffic_split: List[float]
    start_date: datetime
    end_date: Optional[datetime]
    status: str  # running, completed, paused
    sample_size: int
    confidence_level: float
    statistical_significance: bool
    winner: Optional[str]
    results: Dict[str, Any]


@dataclass
class OptimizationRecommendation:
    """Optimization recommendation"""
    recommendation_id: str
    category: str  # design, content, timing, targeting
    priority: str  # high, medium, low
    description: str
    expected_lift: float
    confidence: float
    implementation_effort: str
    test_suggestion: Optional[str]


class CampaignOptimizer:
    """
    Advanced campaign optimization engine.
    Uses behavioral data to optimize campaign performance.
    """
    
    def __init__(self):
        self.ab_tests = {}
        self.recommendations = []
        self.optimization_history = []
        
        # Optimization thresholds
        self.min_sample_size = 100
        self.confidence_threshold = 0.95
        self.min_effect_size = 0.05  # 5% minimum effect
        
        # Optimization categories
        self.optimization_categories = {
            'design': ['layout', 'colors', 'images', 'typography'],
            'content': ['headlines', 'copy', 'call_to_action', 'urgency'],
            'timing': ['send_time', 'day_of_week', 'frequency'],
            'targeting': ['demographics', 'geography', 'device_type']
        }
    
    def create_ab_test(self, name: str, description: str, 
                      variants: List[Dict[str, Any]], 
                      traffic_split: List[float] = None,
                      duration_days: int = 7) -> str:
        """Create new A/B test"""
        test_id = f"ab_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if traffic_split is None:
            traffic_split = [1.0 / len(variants)] * len(variants)
        
        # Validate traffic split
        if abs(sum(traffic_split) - 1.0) > 0.001:
            raise ValueError("Traffic split must sum to 1.0")
        
        ab_test = ABTest(
            test_id=test_id,
            name=name,
            description=description,
            variants=variants,
            traffic_split=traffic_split,
            start_date=datetime.now(),
            end_date=datetime.now() + timedelta(days=duration_days),
            status='running',
            sample_size=0,
            confidence_level=0.95,
            statistical_significance=False,
            winner=None,
            results={}
        )
        
        self.ab_tests[test_id] = ab_test
        return test_id
    
    def assign_variant(self, test_id: str, user_id: str) -> Optional[str]:
        """Assign user to A/B test variant"""
        if test_id not in self.ab_tests:
            return None
        
        test = self.ab_tests[test_id]
        if test.status != 'running':
            return None
        
        # Consistent assignment based on user ID
        hash_value = int(hashlib.md5(f"{test_id}_{user_id}".encode()).hexdigest(), 16)
        variant_index = hash_value % len(test.variants)
        
        return test.variants[variant_index]['id']
    
    def record_conversion(self, test_id: str, variant_id: str, 
                         conversion_value: float = 1.0) -> None:
        """Record conversion for A/B test"""
        if test_id not in self.ab_tests:
            return
        
        test = self.ab_tests[test_id]
        
        # Initialize variant results if needed
        if variant_id not in test.results:
            test.results[variant_id] = {
                'conversions': 0,
                'visitors': 0,
                'conversion_value': 0.0,
                'conversion_rate': 0.0
            }
        
        test.results[variant_id]['conversions'] += 1
        test.results[variant_id]['conversion_value'] += conversion_value
        test.results[variant_id]['conversion_rate'] = (
            test.results[variant_id]['conversions'] / 
            test.results[variant_id]['visitors']
            if test.results[variant_id]['visitors'] > 0 else 0
        )
        
        test.sample_size += 1
    
    def record_visit(self, test_id: str, variant_id: str) -> None:
        """Record visit for A/B test"""
        if test_id not in self.ab_tests:
            return
        
        test = self.ab_tests[test_id]
        
        # Initialize variant results if needed
        if variant_id not in test.results:
            test.results[variant_id] = {
                'conversions': 0,
                'visitors': 0,
                'conversion_value': 0.0,
                'conversion_rate': 0.0
            }
        
        test.results[variant_id]['visitors'] += 1
        test.results[variant_id]['conversion_rate'] = (
            test.results[variant_id]['conversions'] / 
            test.results[variant_id]['visitors']
            if test.results[variant_id]['visitors'] > 0 else 0
        )
        
        test.sample_size += 1
    
    def analyze_ab_test(self, test_id: str) -> Dict[str, Any]:
        """Analyze A/B test results and determine winner"""
        if test_id not in self.ab_tests:
            return {}
        
        test = self.ab_tests[test_id]
        
        if len(test.results) < 2:
            return {'error': 'Insufficient data for analysis'}
        
        # Calculate statistical significance
        variant_results = []
        for variant_id, results in test.results.items():
            if results['visitors'] >= self.min_sample_size:
                variant_results.append({
                    'variant_id': variant_id,
                    'visitors': results['visitors'],
                    'conversions': results['conversions'],
                    'conversion_rate': results['conversion_rate'],
                    'conversion_value': results['conversion_value']
                })
        
        if len(variant_results) < 2:
            return {'error': 'Insufficient sample size'}
        
        # Perform statistical test (simplified chi-square test)
        control = variant_results[0]
        treatment = variant_results[1]
        
        # Calculate chi-square statistic
        observed = [control['conversions'], treatment['conversions']]
        expected_control = (control['visitors'] * (control['conversions'] + treatment['conversions'])) / (control['visitors'] + treatment['visitors'])
        expected_treatment = (treatment['visitors'] * (control['conversions'] + treatment['conversions'])) / (control['visitors'] + treatment['visitors'])
        expected = [expected_control, expected_treatment]
        
        chi_square = sum((o - e) ** 2 / e for o, e in zip(observed, expected))
        
        # Determine statistical significance (simplified)
        critical_value = 3.841  # chi-square critical value for 1 df at 95% confidence
        is_significant = chi_square > critical_value
        
        # Determine winner
        winner = None
        if is_significant:
            winner = max(variant_results, key=lambda x: x['conversion_rate'])['variant_id']
        
        # Update test
        test.statistical_significance = is_significant
        test.winner = winner
        
        return {
            'test_id': test_id,
            'statistical_significance': is_significant,
            'winner': winner,
            'chi_square': chi_square,
            'variant_results': variant_results,
            'recommendation': f"Implement variant {winner}" if winner else "No clear winner"
        }
    
    def generate_optimization_recommendations(self, behavioral_data: Dict[str, Any]) -> List[OptimizationRecommendation]:
        """Generate optimization recommendations based on behavioral data"""
        recommendations = []
        
        # Analyze conversion rate
        conversion_rate = behavioral_data.get('conversion_rate', 0)
        
        if conversion_rate < 0.05:  # Less than 5%
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"opt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                category='design',
                priority='high',
                description='Low conversion rate detected. Optimize landing page design.',
                expected_lift=0.15,  # 15% expected lift
                confidence=0.7,
                implementation_effort='medium',
                test_suggestion='Test different layouts and color schemes'
            ))
        
        # Analyze bounce rate
        bounce_rate = behavioral_data.get('bounce_rate', 0)
        
        if bounce_rate > 0.7:  # Higher than 70%
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"opt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                category='content',
                priority='high',
                description='High bounce rate. Improve page load speed and content relevance.',
                expected_lift=0.20,  # 20% expected lift
                confidence=0.8,
                implementation_effort='low',
                test_suggestion='Test different headlines and opening content'
            ))
        
        # Analyze device performance
        device_performance = behavioral_data.get('device_performance', {})
        
        for device, metrics in device_performance.items():
            if metrics.get('conversion_rate', 0) < conversion_rate * 0.5:
                recommendations.append(OptimizationRecommendation(
                    recommendation_id=f"opt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                    category='design',
                    priority='medium',
                    description=f'Poor performance on {device}. Optimize for {device} users.',
                    expected_lift=0.10,  # 10% expected lift
                    confidence=0.6,
                    implementation_effort='medium',
                    test_suggestion=f'Test {device}-specific layouts and interactions'
                ))
        
        # Analyze temporal patterns
        temporal_patterns = behavioral_data.get('temporal_patterns', {})
        
        if temporal_patterns:
            best_hour = max(temporal_patterns.items(), key=lambda x: x[1])[0]
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"opt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                category='timing',
                priority='medium',
                description=f'Peak activity at {best_hour}:00. Schedule campaigns accordingly.',
                expected_lift=0.08,  # 8% expected lift
                confidence=0.7,
                implementation_effort='low',
                test_suggestion=f'Test sending emails at {best_hour}:00 vs current timing'
            ))
        
        # Analyze form interactions
        form_interactions = behavioral_data.get('form_interactions', {})
        
        if form_interactions.get('abandonment_rate', 0) > 0.5:
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"opt_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                category='design',
                priority='high',
                description='High form abandonment rate. Simplify form design.',
                expected_lift=0.25,  # 25% expected lift
                confidence=0.8,
                implementation_effort='medium',
                test_suggestion='Test shorter forms with fewer fields'
            ))
        
        # Sort by priority and expected lift
        recommendations.sort(key=lambda x: (
            {'high': 3, 'medium': 2, 'low': 1}[x.priority],
            x.expected_lift
        ), reverse=True)
        
        self.recommendations = recommendations
        return recommendations
    
    def optimize_landing_page(self, page_data: Dict[str, Any], 
                            behavioral_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate landing page optimization suggestions"""
        suggestions = {
            'headline': [],
            'call_to_action': [],
            'layout': [],
            'content': [],
            'technical': []
        }
        
        # Headline optimization
        current_headline = page_data.get('headline', '')
        if len(current_headline) < 10 or len(current_headline) > 60:
            suggestions['headline'].append({
                'issue': 'Headline length not optimal',
                'recommendation': 'Keep headline between 10-60 characters',
                'examples': [
                    'Secure Your Account Now',
                    'Verify Your Identity',
                    'Access Your Dashboard'
                ]
            })
        
        # Call-to-action optimization
        cta_text = page_data.get('cta_text', '')
        if not any(word in cta_text.lower() for word in ['login', 'sign', 'access', 'continue']):
            suggestions['call_to_action'].append({
                'issue': 'CTA not action-oriented',
                'recommendation': 'Use action-oriented words',
                'examples': ['Login Now', 'Sign In Securely', 'Access Account']
            })
        
        # Layout optimization
        if behavioral_data.get('mobile_usage', 0) > 0.5:
            suggestions['layout'].append({
                'issue': 'High mobile usage',
                'recommendation': 'Optimize for mobile-first design',
                'actions': ['Larger buttons', 'Simplified navigation', 'Faster loading']
            })
        
        # Content optimization
        bounce_rate = behavioral_data.get('bounce_rate', 0)
        if bounce_rate > 0.7:
            suggestions['content'].append({
                'issue': 'High bounce rate',
                'recommendation': 'Improve content relevance and engagement',
                'actions': ['Add trust indicators', 'Improve page speed', 'Simplify messaging']
            })
        
        # Technical optimization
        page_load_time = behavioral_data.get('page_load_time', 0)
        if page_load_time > 3.0:  # 3 seconds
            suggestions['technical'].append({
                'issue': 'Slow page load time',
                'recommendation': 'Optimize page performance',
                'actions': ['Compress images', 'Minify CSS/JS', 'Enable caching']
            })
        
        return suggestions
    
    def optimize_email_campaign(self, email_data: Dict[str, Any], 
                             performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate email campaign optimization suggestions"""
        suggestions = {
            'subject_line': [],
            'content': [],
            'timing': [],
            'targeting': []
        }
        
        # Subject line optimization
        open_rate = performance_data.get('open_rate', 0)
        if open_rate < 0.2:  # Less than 20%
            suggestions['subject_line'].append({
                'issue': 'Low open rate',
                'recommendation': 'Improve subject line effectiveness',
                'tips': [
                    'Use personalization',
                    'Create urgency',
                    'Ask questions',
                    'Keep under 50 characters'
                ]
            })
        
        # Content optimization
        click_rate = performance_data.get('click_rate', 0)
        if click_rate < 0.05:  # Less than 5%
            suggestions['content'].append({
                'issue': 'Low click rate',
                'recommendation': 'Improve email content and CTAs',
                'tips': [
                    'Clear call-to-action',
                    'Single focus',
                    'Mobile optimization',
                    'Personalization'
                ]
            })
        
        # Timing optimization
        best_send_time = performance_data.get('best_send_time', {})
        if best_send_time:
            suggestions['timing'].append({
                'issue': 'Suboptimal send timing',
                'recommendation': f"Send emails at {best_send_time.get('hour', 10)}:00 on {best_send_time.get('day', 'Tuesday')}",
                'expected_lift': 0.15
            })
        
        # Targeting optimization
        segment_performance = performance_data.get('segment_performance', {})
        underperforming_segments = [
            segment for segment, metrics in segment_performance.items()
            if metrics.get('conversion_rate', 0) < performance_data.get('overall_conversion_rate', 0) * 0.5
        ]
        
        if underperforming_segments:
            suggestions['targeting'].append({
                'issue': 'Underperforming segments',
                'recommendation': 'Improve targeting for specific segments',
                'segments': underperforming_segments,
                'actions': ['Customize content', 'Adjust timing', 'Refine targeting criteria']
            })
        
        return suggestions
    
    def get_optimization_score(self, campaign_data: Dict[str, Any]) -> float:
        """Calculate overall optimization score"""
        scores = []
        
        # Conversion rate score
        conversion_rate = campaign_data.get('conversion_rate', 0)
        conversion_score = min(conversion_rate / 0.1, 1.0)  # 10% = perfect score
        scores.append(conversion_score)
        
        # Bounce rate score (inverse)
        bounce_rate = campaign_data.get('bounce_rate', 0)
        bounce_score = max(1.0 - bounce_rate, 0)
        scores.append(bounce_score)
        
        # Engagement score
        engagement_rate = campaign_data.get('engagement_rate', 0)
        engagement_score = min(engagement_rate / 0.5, 1.0)  # 50% = perfect score
        scores.append(engagement_score)
        
        # Performance score
        page_load_time = campaign_data.get('page_load_time', 3.0)
        performance_score = max(1.0 - (page_load_time / 5.0), 0)  # 5s = 0 score
        scores.append(performance_score)
        
        return statistics.mean(scores)
    
    def export_optimization_report(self, output_file: str = None) -> Dict[str, Any]:
        """Export comprehensive optimization report"""
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'ab_tests': {
                test_id: asdict(test) for test_id, test in self.ab_tests.items()
            },
            'recommendations': [asdict(rec) for rec in self.recommendations],
            'optimization_history': self.optimization_history,
            'summary': {
                'total_tests': len(self.ab_tests),
                'running_tests': len([t for t in self.ab_tests.values() if t.status == 'running']),
                'completed_tests': len([t for t in self.ab_tests.values() if t.status == 'completed']),
                'total_recommendations': len(self.recommendations),
                'high_priority_recommendations': len([r for r in self.recommendations if r.priority == 'high'])
            }
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        return report

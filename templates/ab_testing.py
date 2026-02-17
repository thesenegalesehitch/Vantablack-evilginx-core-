"""
A/B Testing Manager - Automated Testing Framework
==============================================

Manages A/B testing campaigns for templates:
- Test configuration and setup
- Traffic distribution
- Statistical analysis
- Winner determination
- Performance tracking
"""

import json
import random
import time
import statistics
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict
import math


@dataclass
class ABTestConfig:
    """A/B test configuration"""
    test_id: str
    name: str
    description: str
    template_variants: List[str]
    traffic_split: List[float]
    confidence_level: float
    min_sample_size: int
    test_duration_hours: int
    success_metric: str  # conversion_rate, click_rate, engagement_time
    created_at: datetime


@dataclass
class ABTestResult:
    """A/B test result"""
    test_id: str
    winner: Optional[str]
    confidence: float
    statistical_significance: bool
    variant_results: Dict[str, Dict[str, Any]]
    test_duration: timedelta
    total_samples: int
    created_at: datetime
    completed_at: datetime


@dataclass
class VariantMetrics:
    """Metrics for a test variant"""
    variant_id: str
    impressions: int
    conversions: int
    clicks: int
    engagement_time: float
    bounce_rate: float
    conversion_rate: float
    revenue: float


class ABTestManager:
    """
    A/B testing management system.
    Handles automated testing of template variations.
    """
    
    def __init__(self):
        self.active_tests = {}
        self.test_history = []
        self.variant_assignments = {}
        self.test_results = {}
        
        # Statistical thresholds
        self.min_sample_size = 100
        self.default_confidence = 0.95
        self.min_test_duration = 24  # hours
        self.min_confidence_level = 0.8
    
    def create_test(self, config: ABTestConfig) -> str:
        """Create a new A/B test"""
        # Validate configuration
        if len(config.template_variants) < 2:
            raise ValueError("A/B test requires at least 2 variants")
        
        if abs(sum(config.traffic_split) - 1.0) > 0.01:
            raise ValueError("Traffic split must sum to 1.0")
        
        if config.min_sample_size < self.min_sample_size:
            config.min_sample_size = self.min_sample_size
        
        # Store test
        self.active_tests[config.test_id] = config
        
        # Initialize variant assignments
        self.variant_assignments[config.test_id] = {}
        self.test_results[config.test_id] = {}
        
        # Initialize variant metrics
        for variant_id in config.template_variants:
            self.test_results[config.test_id][variant_id] = VariantMetrics(
                variant_id=variant_id,
                impressions=0,
                conversions=0,
                clicks=0,
                engagement_time=0.0,
                bounce_rate=0.0,
                conversion_rate=0.0,
                revenue=0.0
            )
        
        return config.test_id
    
    def assign_variant(self, test_id: str, user_id: str) -> Optional[str]:
        """Assign a user to a test variant"""
        if test_id not in self.active_tests:
            return None
        
        config = self.active_tests[test_id]
        
        # Check if user already assigned
        if user_id in self.variant_assignments[test_id]:
            return self.variant_assignments[test_id][user_id]
        
        # Weighted random assignment
        weights = config.traffic_split
        variants = config.template_variants
        
        # Use consistent assignment based on user ID hash
        hash_value = int(hashlib.md5(f"{test_id}_{user_id}".encode()).hexdigest(), 16)
        total_weight = sum(weights)
        cumulative_weight = 0
        
        for i, weight in enumerate(weights):
            cumulative_weight += weight
            if hash_value % total_weight < cumulative_weight:
                variant = variants[i]
                break
        
        # Store assignment
        self.variant_assignments[test_id][user_id] = variant
        
        return variant
    
    def record_impression(self, test_id: str, variant_id: str, user_id: str, 
                          timestamp: datetime = None) -> None:
        """Record an impression for a variant"""
        if test_id not in self.active_tests:
            return None
        
        if variant_id not in self.test_results[test_id]:
            return None
        
        # Record impression
        self.test_results[test_id][variant_id].impressions += 1
        
        # Update derived metrics
        self._update_derived_metrics(test_id, variant_id)
    
    def record_conversion(self, test_id: str, variant_id: str, user_id: str, 
                         conversion_value: float = 1.0,
                         timestamp: datetime = None) -> None:
        """Record a conversion for a variant"""
        if test_id not in self.active_tests:
            return None
        
        if variant_id not in self.test_results[test_id]:
            return None
        
        # Record conversion
        self.test_results[test_id][variant_id].conversions += 1
        self.test_results[test_id][variant_id].revenue += conversion_value
        
        # Update derived metrics
        self._update_derived_metrics(test_id, variant_id)
    
    def record_click(self, test_id: str, variant_id: str, user_id: str,
                     timestamp: datetime = None) -> None:
        """Record a click for a variant"""
        if test_id not in self.active_tests:
            return None
        
        if variant_id not in self.test_results[test_id]:
            return None
        
        # Record click
        self.test_results[test_id][variant_id].clicks += 1
        
        # Update derived metrics
        self._update_derived_metrics(test_id, variant_id)
    
    def record_engagement_time(self, test_id: str, variant_id: str, user_id: str,
                              engagement_time: float, 
                              timestamp: datetime = None) -> None:
        """Record engagement time for a variant"""
        if test_id not in self.active_tests:
            return None
        
        if variant_id not in self.test_results[test_id]:
            return None
        
        # Update engagement time (average)
        current_avg = self.test_results[test_id][variant_id].engagement_time
        current_count = self.test_results[test_id][variant_id].impressions
        
        if current_count > 0:
            new_avg = (current_avg * current_count + engagement_time) / (current_count + 1)
            self.test_results[test_id][variant_id].engagement_time = new_avg
    
    def _update_derived_metrics(self, test_id: str, variant_id: str) -> None:
        """Update derived metrics for a variant"""
        metrics = self.test_results[test_id][variant_id]
        
        # Conversion rate
        if metrics.impressions > 0:
            metrics.conversion_rate = metrics.conversions / metrics.impressions
        
        # Bounce rate (simplified - users who leave without converting)
        if metrics.impressions > 0:
            metrics.bounce_rate = 1.0 - metrics.conversion_rate
    
    def analyze_test(self, test_id: str) -> Optional[ABTestResult]:
        """Analyze an A/B test and determine winner"""
        if test_id not in self.active_tests:
            return None
        
        config = self.active_tests[test_id]
        results = self.test_results[test_id]
        
        # Check minimum sample size
        total_samples = sum(metrics.impressions for metrics in results.values())
        if total_samples < config.min_sample_size:
            return None
        
        # Check test duration
        test_duration = datetime.now() - config.created_at
        if test_duration < timedelta(hours=config.test_duration_hours):
            return None
        
        # Perform statistical analysis
        winner = None
        confidence = 0.0
        is_significant = False
        
        # Get conversion rates for each variant
        conversion_rates = {}
        for variant_id, metrics in results.items():
            conversion_rates[variant_id] = metrics.conversion_rate
        
        # Find best performing variant
        best_variant = max(conversion_rates, key=conversion_rates.get)
        second_best = sorted(conversion_rates.values(), reverse=True)[1] if len(conversion_rates) > 1 else 0
        
        # Calculate statistical significance (simplified chi-square test)
        if len(conversion_rates) >= 2:
            # Perform chi-square test
            observed = [results[variant].conversions for variant in config.template_variants]
            expected = [total_samples * split for split in config.traffic_split]
            
            chi_square = 0.0
            for observed_val, expected_val in zip(observed, expected):
                if expected_val > 0:
                    chi_square += ((observed_val - expected_val) ** 2) / expected_val
            
            # Degrees of freedom
            df = len(conversion_rates) - 1
            
            # Critical value for chi-square at 95% confidence
            critical_value = {
                1: 3.841,
                2: 5.991,
                3: 7.815,
                4: 9.488,
                5: 11.07
            }.get(df, 11.07)
            
            is_significant = chi_square > critical_value
            
            if is_significant:
                winner = max(conversion_rates, key=conversion_rates.get)
                confidence = 1.0 - (critical_value / chi_square) if chi_square > 0 else 0.0
            else:
                winner = best_variant
                confidence = 0.0
        
        # Create result
        result = ABTestResult(
            test_id=test_id,
            winner=winner,
            confidence=confidence,
            statistical_significance=is_significant,
            variant_results={
                variant_id: {
                    'impressions': metrics.impressions,
                    'conversions': metrics.conversions,
                    'clicks': metrics.clicks,
                    'engagement_time': metrics.engagement_time,
                    'bounce_rate': metrics.bounce_rate,
                    'conversion_rate': metrics.conversion_rate,
                    'revenue': metrics.revenue
                }
                for variant_id, metrics in results.items()
            },
            test_duration=test_duration,
            total_samples=total_samples,
            created_at=config.created_at,
            completed_at=datetime.now()
        )
        
        # Store result
        self.test_history.append(result)
        
        # Move test from active to completed
        del self.active_tests[test_id]
        del self.variant_assignments[test_id]
        del self.test_results[test_id]
        
        return result
    
    def get_test_summary(self, test_id: str) -> Dict[str, Any]:
        """Get a summary of test performance"""
        if test_id not in self.active_tests:
            return {'error': 'Test not found'}
        
        config = self.active_tests[test_id]
        results = self.test_results[test_id]
        
        total_impressions = sum(metrics.impressions for metrics in results.values())
        total_conversions = sum(metrics.conversions for metrics in metrics.values())
        total_revenue = sum(metrics.revenue for metrics in metrics.values())
        
        # Calculate lift over baseline (first variant)
        baseline_variant = config.template_variants[0]
        baseline_metrics = results[baseline_variant]
        
        if baseline_metrics.impressions > 0:
            baseline_rate = baseline_metrics.conversion_rate
        else:
            baseline_rate = 0.0
        
        variant_lifts = {}
        for variant_id, metrics in results.items():
            if metrics.impressions > 0:
                lift = ((metrics.conversion_rate - baseline_rate) / baseline_rate) * 100 if baseline_rate > 0 else 0
                variant_lifts[variant_id] = lift
        
        return {
            'test_id': test_id,
            'config': asdict(config),
            'total_impressions': total_impressions,
            'total_conversions': total_conversions,
            'total_revenue': total_revenue,
            'overall_conversion_rate': total_conversions / total_impressions if total_impressions > 0 else 0.0,
            'variant_performance': {
                variant_id: {
                    'impressions': metrics.impressions,
                    'conversions': metrics.conversions,
                    'conversion_rate': metrics.conversion_rate,
                    'lift': variant_lifts.get(variant_id, 0.0)
                }
                for variant_id, metrics in results.items()
            },
            'test_progress': {
                'duration_hours': (datetime.now() - config.created_at).total_seconds() / 3600,
                'min_duration_hours': config.test_duration_hours,
                'min_sample_size': config.min_sample_size,
                'current_sample_size': total_impressions
            }
        }
    
    def get_active_tests(self) -> List[Dict[str, Any]]:
        """Get all active tests"""
        return [
            {
                'test_id': test_id,
                'name': config.name,
                'description': config.description,
                'variants': config.template_variants,
                'traffic_split': config.traffic_split,
                'created_at': config.created_at.isoformat(),
                'duration_hours': (datetime.now() - config.created_at).total_seconds() / 3600,
                'sample_size': sum(metrics.impressions for metrics in self.test_results.get(test_id, {}).values()),
                'min_sample_size': config.min_sample_size
            }
            for test_id, config in self.active_tests.items()
        ]
    
    def get_test_history(self) -> List[Dict[str, Any]]:
        """Get test history"""
        return [
            {
                'test_id': result.test_id,
                'winner': result.winner,
                'confidence': result.confidence,
                'statistical_significance': result.statistical_significant,
                'total_samples': result.total_samples,
                'test_duration_hours': result.test_duration.total_seconds() / 3600,
                'completed_at': result.completed_at.isoformat(),
                'variant_performance': result.variant_results
            }
            for result in self.test_history
        ]
    
    def get_recommendations(self, test_id: str) -> List[Dict[str, Any]]:
        """Get recommendations for improving a test"""
        if test_id not in self.active_tests:
            return []
        
        summary = self.get_test_summary(test_id)
        config = self.active_tests[test_id]
        
        recommendations = []
        
        # Sample size recommendations
        if summary['test_progress']['current_sample_size'] < summary['test_progress']['min_sample_size']:
            recommendations.append({
                'type': 'sample_size',
                'priority': 'high',
                'issue': 'Insufficient sample size',
                'recommendation': f'Increase sample size to at least {config.min_sample_size}',
                'current': summary['test_progress']['current_sample_size'],
                'target': config.min_sample_size
            })
        
        # Duration recommendations
        if summary['test_progress']['duration_hours'] < summary['test_progress']['min_duration_hours']:
            recommendations.append({
                'type': 'duration',
                'priority': 'medium',
                'issue': 'Test duration too short',
                'recommendation': f'Run test for at least {config.test_duration_hours} hours',
                'current': summary['test_progress']['duration_hours'],
                'target': config.test_duration_hours
            })
        
        # Performance recommendations
        best_variant = max(summary['variant_performance'].items(), 
                           key=lambda x: x['conversion_rate'])
        worst_variant = min(summary['variant_performance'].items(), 
                            key=lambda x: x['conversion_rate'])
        
        if best_variant['lift'] < 5.0:
            recommendations.append({
                'type': 'performance',
                'priority': 'high',
                'issue': 'Low performance improvement',
                'recommendation': 'Consider creating more distinct variants',
                'best_variant': best_variant['variant_id'],
                'worst_variant': worst_variant['variant_id'],
                'best_lift': best_variant['lift']
            })
        
        # Statistical significance recommendations
        if summary['overall_conversion_rate'] > 0.01:  # Only if there are conversions
            total_samples = summary['total_samples']
            if total_samples >= 1000:
                recommendations.append({
                    'type': 'statistical',
                    'priority': 'low',
                    'issue': 'Consider running test longer',
                    'recommendation': 'Larger sample size increases statistical power',
                    'current_sample_size': total_samples,
                    'recommended_size': min(total_samples * 2, 10000)
                })
        
        return recommendations
    
    def export_test_data(self, test_id: str, output_file: str = None) -> Dict[str, Any]:
        """Export test data for analysis"""
        summary = self.get_test_summary(test_id)
        recommendations = self.get_recommendations(test_id)
        
        export_data = {
            'test_summary': summary,
            'recommendations': recommendations,
            'export_timestamp': datetime.now().isoformat(),
            'raw_results': {
                variant_id: asdict(metrics) for variant_id, metrics in self.test_results.get(test_id, {}).items()
            },
            'config': asdict(self.active_tests[test_id])
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        return export_data
    
    def stop_test(self, test_id: str) -> Optional[ABTestResult]:
        """Stop an active test and analyze results"""
        if test_id not in self.active_tests:
            return None
        
        # Force completion by updating min sample size and duration
        config = self.active_tests[test_id]
        config.min_sample_size = 1
        config.test_duration_hours = 0
        
        # Analyze test
        return self.analyze_test(test_id)
    
    def get_performance_comparison(self, test_id: str) -> Dict[str, Any]:
        """Get detailed performance comparison between variants"""
        if test_id not in self.active_tests:
            return {'error': 'Test not found'}
        
        results = self.test_results[test_id]
        config = self.active_tests[test_id]
        
        comparison = {
            'test_id': test_id,
            'variants': config.template_variants,
            'performance_metrics': {}
        }
        
        for variant_id, metrics in results.items():
            comparison['performance_metrics'][variant_id] = {
                'impressions': metrics.impressions,
                'conversions': metrics.conversions,
                'clicks': metrics.clicks,
                'engagement_time': metrics.engagement_time,
                'bounce_rate': metrics.bounce_rate,
                'conversion_rate': metrics.conversion_rate,
                'revenue': metrics.revenue,
                'revenue_per_impression': metrics.revenue / metrics.impressions if metrics.impressions > 0 else 0,
                'click_through_rate': metrics.clicks / metrics.impressions if metrics.impressions > 0 else 0
            }
        
        # Add comparative analysis
        if len(results) >= 2:
            variant_ids = list(results.keys())
            best_variant = max(variant_ids, key=lambda x: results[x].conversion_rate)
            worst_variant = min(variant_ids, key=lambda x: results[x].conversion_rate)
            
            comparison['analysis'] = {
                'best_variant': best_variant,
                'worst_variant': worst_variant,
                'performance_gap': results[best_variant].conversion_rate - results[worst_variant].conversion_rate,
                'relative_improvement': ((results[best_variant].conversion_rate - results[worst_variant].conversion_rate) / 
                                results[worst_variant].conversion_rate * 100) if results[worst_variant].conversion_rate > 0 else 0,
                'statistical_power': self._calculate_statistical_power(config, results)
            }
        
        return comparison
    
    def _calculate_statistical_power(self, config: ABTestConfig, results: Dict[str, VariantMetrics]) -> float:
        """Calculate statistical power of the test"""
        # Simplified power calculation
        total_samples = sum(metrics.impressions for metrics in results.values())
        
        # Base conversion rate estimate
        avg_conversion_rate = sum(metrics.conversions for metrics in results.values()) / total_samples if total_samples > 0 else 0.01
        
        # Minimum detectable effect size (5% relative improvement)
        min_effect_size = 0.05 * avg_conversion_rate
        
        # Simplified power calculation (Cohen's d approximation)
        alpha = 0.05  # Type I error rate
        beta = 0.20  # Type II error rate
        z_alpha = 1.96  # Z-score for 95% confidence
        
        # Standard deviation estimate (binomial)
        std_dev = math.sqrt(avg_conversion_rate * (1 - avg_conversion_rate) / total_samples)
        
        # Effect size in standard deviations
        effect_size = min_effect_size / std_dev if std_dev > 0 else 1
        
        # Power calculation
        power = 1 - stats.norm.cdf(z_alpha - effect_size * math.sqrt(total_samples / 2))
        
        return max(0.0, min(1.0, power))
    
    def create_revenue_optimization_test(self, template_variants: List[str], 
                                     revenue_per_conversion: float = 10.0) -> str:
        """Create an A/B test optimized for revenue"""
        config = ABTestConfig(
            test_id=f"revenue_test_{int(time.time())}",
            name="Revenue Optimization Test",
            description="A/B test to maximize revenue per conversion",
            template_variants=template_variants,
            traffic_split=[0.5, 0.5],
            confidence_level=0.95,
            min_sample_size=200,
            test_duration_hours=72,
            success_metric='revenue_per_impression'
        )
        
        return self.create_test(config)
    
    def create_conversion_optimization_test(self, template_variants: List[str]) -> str:
        """Create an A/B test optimized for conversion rate"""
        config = ABTestConfig(
            test_id=f"conversion_test_{int(time.time())}",
            name="Conversion Rate Optimization Test",
            description="A/B test to maximize conversion rate",
            template_variants=template_variants,
            traffic_split=[0.5, 0.5],
            confidence_level=0.95,
            min_sample_size=100,
            test_duration_hours=48,
            success_metric='conversion_rate'
        )
        
        return self.create_test(config)

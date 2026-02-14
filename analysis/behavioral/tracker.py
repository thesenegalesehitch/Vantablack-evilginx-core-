"""
User Tracker - Real-time User Interaction Tracking
==================================================

Tracks user interactions in real-time:
- Mouse movements and clicks
- Form interactions
- Scroll behavior
- Time on page
- Device fingerprinting
- Session management
"""

import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict
from collections import defaultdict
import hashlib


@dataclass
class TrackingEvent:
    """Tracking event data"""
    event_id: str
    session_id: str
    event_type: str
    timestamp: datetime
    data: Dict[str, Any]
    user_agent: str
    ip_address: str


@dataclass
class UserFingerprint:
    """User device fingerprint"""
    fingerprint_id: str
    user_agent: str
    screen_resolution: str
    color_depth: int
    timezone: str
    language: str
    platform: str
    cookies_enabled: bool
    plugins: List[str]
    canvas_fingerprint: str
    webgl_fingerprint: str
    fonts: List[str]


class UserTracker:
    """
    Real-time user interaction tracking system.
    Captures detailed behavioral data for analysis.
    """
    
    def __init__(self, storage_backend: str = 'memory'):
        self.storage_backend = storage_backend
        self.events = []
        self.sessions = defaultdict(dict)
        self.fingerprints = {}
        
        # Event handlers
        self.event_handlers = defaultdict(list)
        
        # Tracking configuration
        self.tracking_config = {
            'track_mouse': True,
            'track_scroll': True,
            'track_clicks': True,
            'track_forms': True,
            'track_keystrokes': True,
            'track_performance': True,
            'sample_rate': 1.0,  # 100% sampling
            'batch_size': 100,
            'flush_interval': 30  # seconds
        }
        
        # Performance metrics
        self.performance_metrics = {
            'page_load_time': 0,
            'dom_ready_time': 0,
            'first_paint_time': 0,
            'first_contentful_paint': 0
        }
    
    def generate_session_id(self) -> str:
        """Generate unique session ID"""
        return str(uuid.uuid4())
    
    def generate_fingerprint(self, request_data: Dict[str, Any]) -> UserFingerprint:
        """Generate device fingerprint from request data"""
        # Extract fingerprint components
        user_agent = request_data.get('user_agent', '')
        screen_resolution = request_data.get('screen_resolution', '')
        color_depth = request_data.get('color_depth', 24)
        timezone = request_data.get('timezone', '')
        language = request_data.get('language', '')
        platform = request_data.get('platform', '')
        cookies_enabled = request_data.get('cookies_enabled', True)
        plugins = request_data.get('plugins', [])
        canvas_fingerprint = request_data.get('canvas_fingerprint', '')
        webgl_fingerprint = request_data.get('webgl_fingerprint', '')
        fonts = request_data.get('fonts', [])
        
        # Generate fingerprint hash
        fingerprint_data = f"{user_agent}|{screen_resolution}|{color_depth}|{timezone}|{language}|{platform}|{canvas_fingerprint}|{webgl_fingerprint}"
        fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        fingerprint = UserFingerprint(
            fingerprint_id=fingerprint_hash,
            user_agent=user_agent,
            screen_resolution=screen_resolution,
            color_depth=color_depth,
            timezone=timezone,
            language=language,
            platform=platform,
            cookies_enabled=cookies_enabled,
            plugins=plugins,
            canvas_fingerprint=canvas_fingerprint,
            webgl_fingerprint=webgl_fingerprint,
            fonts=fonts
        )
        
        self.fingerprints[fingerprint_hash] = fingerprint
        return fingerprint
    
    def track_event(self, event_type: str, session_id: str, 
                   data: Dict[str, Any], user_agent: str = '', 
                   ip_address: str = '') -> str:
        """Track a user event"""
        event_id = str(uuid.uuid4())
        
        event = TrackingEvent(
            event_id=event_id,
            session_id=session_id,
            event_type=event_type,
            timestamp=datetime.now(),
            data=data,
            user_agent=user_agent,
            ip_address=ip_address
        )
        
        # Store event
        self.events.append(event)
        
        # Update session data
        self.sessions[session_id][event_type] = self.sessions[session_id].get(event_type, [])
        self.sessions[session_id][event_type].append(event)
        
        # Trigger event handlers
        for handler in self.event_handlers[event_type]:
            try:
                handler(event)
            except Exception as e:
                print(f"Event handler error: {e}")
        
        return event_id
    
    def track_page_view(self, session_id: str, page_url: str, 
                       referrer: str = '', user_agent: str = '', 
                       ip_address: str = '') -> str:
        """Track page view"""
        data = {
            'page_url': page_url,
            'referrer': referrer,
            'timestamp': time.time()
        }
        
        return self.track_event('page_view', session_id, data, user_agent, ip_address)
    
    def track_click(self, session_id: str, element_id: str, 
                   element_type: str, coordinates: tuple, 
                   user_agent: str = '', ip_address: str = '') -> str:
        """Track click event"""
        data = {
            'element_id': element_id,
            'element_type': element_type,
            'coordinates': coordinates,
            'timestamp': time.time()
        }
        
        return self.track_event('click', session_id, data, user_agent, ip_address)
    
    def track_form_interaction(self, session_id: str, form_id: str, 
                             field_name: str, field_type: str, 
                             interaction_type: str, user_agent: str = '', 
                             ip_address: str = '') -> str:
        """Track form interaction"""
        data = {
            'form_id': form_id,
            'field_name': field_name,
            'field_type': field_type,
            'interaction_type': interaction_type,  # focus, blur, input, change
            'timestamp': time.time()
        }
        
        return self.track_event('form_interaction', session_id, data, user_agent, ip_address)
    
    def track_scroll(self, session_id: str, scroll_depth: float, 
                    scroll_direction: str, user_agent: str = '', 
                    ip_address: str = '') -> str:
        """Track scroll behavior"""
        data = {
            'scroll_depth': scroll_depth,
            'scroll_direction': scroll_direction,
            'timestamp': time.time()
        }
        
        return self.track_event('scroll', session_id, data, user_agent, ip_address)
    
    def track_mouse_movement(self, session_id: str, coordinates: tuple, 
                           movement_type: str = 'move', user_agent: str = '', 
                           ip_address: str = '') -> str:
        """Track mouse movement"""
        data = {
            'coordinates': coordinates,
            'movement_type': movement_type,
            'timestamp': time.time()
        }
        
        return self.track_event('mouse_movement', session_id, data, user_agent, ip_address)
    
    def track_keystroke(self, session_id: str, field_name: str, 
                        key_value: str, key_type: str, 
                        user_agent: str = '', ip_address: str = '') -> str:
        """Track keystroke events"""
        data = {
            'field_name': field_name,
            'key_value': key_value,
            'key_type': key_type,  # character, special, backspace
            'timestamp': time.time()
        }
        
        return self.track_event('keystroke', session_id, data, user_agent, ip_address)
    
    def track_form_submission(self, session_id: str, form_id: str, 
                            form_data: Dict[str, Any], success: bool, 
                            user_agent: str = '', ip_address: str = '') -> str:
        """Track form submission"""
        data = {
            'form_id': form_id,
            'form_data': form_data,
            'success': success,
            'timestamp': time.time()
        }
        
        return self.track_event('form_submission', session_id, data, user_agent, ip_address)
    
    def track_performance(self, session_id: str, metric_name: str, 
                         metric_value: float, user_agent: str = '', 
                         ip_address: str = '') -> str:
        """Track performance metrics"""
        data = {
            'metric_name': metric_name,
            'metric_value': metric_value,
            'timestamp': time.time()
        }
        
        return self.track_event('performance', session_id, data, user_agent, ip_address)
    
    def track_error(self, session_id: str, error_type: str, 
                   error_message: str, error_context: Dict[str, Any], 
                   user_agent: str = '', ip_address: str = '') -> str:
        """Track error events"""
        data = {
            'error_type': error_type,
            'error_message': error_message,
            'error_context': error_context,
            'timestamp': time.time()
        }
        
        return self.track_event('error', session_id, data, user_agent, ip_address)
    
    def add_event_handler(self, event_type: str, handler: Callable) -> None:
        """Add event handler for specific event type"""
        self.event_handlers[event_type].append(handler)
    
    def get_session_events(self, session_id: str, event_type: str = None) -> List[TrackingEvent]:
        """Get all events for a session"""
        if event_type:
            return self.sessions[session_id].get(event_type, [])
        else:
            all_events = []
            for events in self.sessions[session_id].values():
                all_events.extend(events)
            return sorted(all_events, key=lambda x: x.timestamp)
    
    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """Get session summary statistics"""
        session_events = self.get_session_events(session_id)
        
        if not session_events:
            return {}
        
        # Calculate session duration
        start_time = min(event.timestamp for event in session_events)
        end_time = max(event.timestamp for event in session_events)
        duration = (end_time - start_time).total_seconds()
        
        # Count event types
        event_counts = defaultdict(int)
        for event in session_events:
            event_counts[event.event_type] += 1
        
        # Calculate interaction metrics
        click_events = [e for e in session_events if e.event_type == 'click']
        scroll_events = [e for e in session_events if e.event_type == 'scroll']
        form_events = [e for e in session_events if e.event_type == 'form_interaction']
        
        # Calculate scroll depth
        max_scroll_depth = 0
        if scroll_events:
            max_scroll_depth = max(e.data.get('scroll_depth', 0) for e in scroll_events)
        
        # Check for form submission
        form_submission = any(e for e in session_events if e.event_type == 'form_submission')
        
        return {
            'session_id': session_id,
            'duration': duration,
            'total_events': len(session_events),
            'event_counts': dict(event_counts),
            'click_count': len(click_events),
            'scroll_depth': max_scroll_depth,
            'form_interactions': len(form_events),
            'form_submitted': form_submission,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat()
        }
    
    def generate_tracking_script(self, tracking_endpoint: str, 
                               session_id: str = None) -> str:
        """Generate JavaScript tracking script"""
        script = f"""
(function() {{
    var sessionId = '{session_id or "auto-generate"}';
    var trackingEndpoint = '{tracking_endpoint}';
    var trackingConfig = {json.dumps(self.tracking_config)};
    
    // Auto-generate session ID if needed
    if (sessionId === 'auto-generate') {{
        sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }}
    
    // Tracking functions
    function trackEvent(eventType, data) {{
        fetch(trackingEndpoint + '/track', {{
            method: 'POST',
            headers: {{
                'Content-Type': 'application/json'
            }},
            body: JSON.stringify({{
                session_id: sessionId,
                event_type: eventType,
                data: data,
                user_agent: navigator.userAgent,
                timestamp: new Date().toISOString()
            }})
        }}).catch(console.error);
    }}
    
    // Page view tracking
    trackEvent('page_view', {{
        page_url: window.location.href,
        referrer: document.referrer,
        title: document.title
    }});
    
    // Click tracking
    if (trackingConfig.track_clicks) {{
        document.addEventListener('click', function(e) {{
            trackEvent('click', {{
                element_id: e.target.id || '',
                element_type: e.target.tagName.toLowerCase(),
                coordinates: [e.clientX, e.clientY],
                text: e.target.textContent || ''
            }});
        }});
    }}
    
    // Scroll tracking
    if (trackingConfig.track_scroll) {{
        var maxScrollDepth = 0;
        window.addEventListener('scroll', function() {{
            var scrollDepth = (window.scrollY / document.body.scrollHeight) * 100;
            if (scrollDepth > maxScrollDepth) {{
                maxScrollDepth = scrollDepth;
                trackEvent('scroll', {{
                    scroll_depth: scrollDepth,
                    scroll_direction: 'down'
                }});
            }}
        }});
    }}
    
    // Form tracking
    if (trackingConfig.track_forms) {{
        document.addEventListener('focus', function(e) {{
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {{
                trackEvent('form_interaction', {{
                    form_id: e.target.form?.id || '',
                    field_name: e.target.name || '',
                    field_type: e.target.type || '',
                    interaction_type: 'focus'
                }});
            }}
        }}, true);
        
        document.addEventListener('blur', function(e) {{
            if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') {{
                trackEvent('form_interaction', {{
                    form_id: e.target.form?.id || '',
                    field_name: e.target.name || '',
                    field_type: e.target.type || '',
                    interaction_type: 'blur'
                }});
            }}
        }}, true);
        
        document.addEventListener('submit', function(e) {{
            var formData = new FormData(e.target);
            var data = {{}};
            for (var [key, value] of formData.entries()) {{
                data[key] = value;
            }}
            
            trackEvent('form_submission', {{
                form_id: e.target.id || '',
                form_data: data,
                success: true
            }});
        }});
    }}
    
    // Performance tracking
    if (trackingConfig.track_performance && window.performance) {{
        window.addEventListener('load', function() {{
            setTimeout(function() {{
                var perfData = window.performance.timing;
                trackEvent('performance', {{
                    page_load_time: perfData.loadEventEnd - perfData.navigationStart,
                    dom_ready_time: perfData.domContentLoadedEventEnd - perfData.navigationStart,
                    first_paint: performance.getEntriesByType('paint')[0]?.startTime || 0
                }});
            }}, 0);
        }});
    }}
    
    // Error tracking
    window.addEventListener('error', function(e) {{
        trackEvent('error', {{
            error_type: 'javascript',
            error_message: e.message,
            error_context: {{
                filename: e.filename,
                lineno: e.lineno,
                colno: e.colno
            }}
        }});
    }});
    
    // Make session ID available globally
    window.vantaSessionId = sessionId;
}})();
"""
        return script
    
    def export_data(self, output_file: str = None) -> Dict[str, Any]:
        """Export all tracking data"""
        export_data = {
            'events': [asdict(event) for event in self.events],
            'sessions': {
                session_id: self.get_session_summary(session_id)
                for session_id in self.sessions.keys()
            },
            'fingerprints': {
                fp_id: asdict(fp) for fp_id, fp in self.fingerprints.items()
            },
            'tracking_config': self.tracking_config,
            'export_timestamp': datetime.now().isoformat()
        }
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
        
        return export_data
    
    def clear_data(self) -> None:
        """Clear all tracking data"""
        self.events.clear()
        self.sessions.clear()
        self.fingerprints.clear()

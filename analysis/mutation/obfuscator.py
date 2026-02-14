"""
JavaScript Obfuscator - Advanced Code Obfuscation
==================================================

Generates obfuscated JavaScript for evasion:
- Anti-debugging techniques
- Sandbox detection
- Code obfuscation
- Runtime protection
- Anti-analysis
"""

import random
import string
import base64
import hashlib
from typing import List, Dict, Any
import re


class JavaScriptObfuscator:
    """
    Advanced JavaScript obfuscation for anti-detection.
    Generates multiple evasion techniques.
    """
    
    def __init__(self):
        self.anti_debug_techniques = [
            self._debugger_detection,
            self._console_detection,
            self._devtools_detection,
            self._timing_check,
            self._size_check
        ]
        
        self.sandbox_techniques = [
            self._vm_detection,
            self._headless_detection,
            self._automation_detection,
            self._fingerprint_check
        ]
        
        self.obfuscation_methods = [
            self._base64_obfuscation,
            self._hex_encoding,
            self._unicode_encoding,
            self._array_splitting,
            self._function_renaming
        ]
    
    def generate_evasion_script(self, techniques: List[str] = None) -> str:
        """Generate complete evasion script"""
        if techniques is None:
            # Randomly select techniques
            selected_debug = random.sample(self.anti_debug_techniques, 
                                         random.randint(2, 3))
            selected_sandbox = random.sample(self.sandbox_techniques,
                                           random.randint(2, 3))
            selected_obfuscation = random.sample(self.obfuscation_methods,
                                                random.randint(1, 2))
        else:
            # Use specified techniques
            selected_debug = [getattr(self, f"_{t}") for t in techniques 
                            if hasattr(self, f"_{t}")]
            selected_sandbox = []
            selected_obfuscation = []
        
        # Build script
        script_parts = []
        
        # Add anti-debugging
        for technique in selected_debug:
            script_parts.append(technique())
        
        # Add sandbox detection
        for technique in selected_sandbox:
            script_parts.append(technique())
        
        # Add obfuscation wrapper
        main_code = "console.log('Environment check passed');"
        for obfuscator in selected_obfuscation:
            main_code = obfuscator(main_code)
        
        script_parts.append(main_code)
        
        # Combine and wrap in IIFE
        combined_script = "\n".join(script_parts)
        wrapped_script = f"(function(){{\n{combined_script}\n}})();"
        
        return wrapped_script
    
    def _debugger_detection(self) -> str:
        """Detect debugger presence"""
        return """
(function() {
    var start = performance.now();
    debugger;
    var end = performance.now();
    if (end - start > 100) {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
    }
})();
"""
    
    def _console_detection(self) -> str:
        """Detect console access"""
        return """
(function() {
    var console = window.console;
    var originalLog = console.log;
    console.log = function() {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
        return originalLog.apply(console, arguments);
    };
    
    setInterval(function() {
        if (console.clear || console.dir || console.debug) {
            document.body.innerHTML = '';
            window.location.href = 'about:blank';
        }
    }, 1000);
})();
"""
    
    def _devtools_detection(self) -> str:
        """Detect devtools opening"""
        return """
(function() {
    var devtools = {
        open: false,
        orientation: null
    };
    
    var threshold = 160;
    
    setInterval(function() {
        if (window.outerHeight - window.innerHeight > threshold || 
            window.outerWidth - window.innerWidth > threshold) {
            if (!devtools.open) {
                devtools.open = true;
                document.body.innerHTML = '';
                window.location.href = 'about:blank';
            }
        } else {
            devtools.open = false;
        }
    }, 500);
})();
"""
    
    def _timing_check(self) -> str:
        """Check execution timing"""
        return """
(function() {
    var start = Date.now();
    var result = 0;
    for (var i = 0; i < 1000000; i++) {
        result += Math.random();
    }
    var end = Date.now();
    
    if (end - start > 100) {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
    }
})();
"""
    
    def _size_check(self) -> str:
        """Check window size"""
        return """
(function() {
    if (window.screen.width < 100 || window.screen.height < 100 || 
        window.outerWidth < 100 || window.outerHeight < 100) {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
    }
})();
"""
    
    def _vm_detection(self) -> str:
        """Detect virtual machine"""
        return """
(function() {
    var canvas = document.createElement('canvas');
    var gl = canvas.getContext('webgl');
    
    if (gl) {
        var debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            var renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
            if (renderer.indexOf('VMware') !== -1 || 
                renderer.indexOf('VirtualBox') !== -1 ||
                renderer.indexOf('VirtIO') !== -1) {
                document.body.innerHTML = '';
                window.location.href = 'about:blank';
            }
        }
    }
})();
"""
    
    def _headless_detection(self) -> str:
        """Detect headless browser"""
        return """
(function() {
    if (navigator.webdriver) {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
    }
    
    if (window.chrome && window.chrome.app) {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
    }
    
    if (navigator.plugins.length === 0) {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
    }
})();
"""
    
    def _automation_detection(self) -> str:
        """Detect automation tools"""
        return """
(function() {
    var detected = false;
    
    // Check for Selenium
    if (window.document.documentElement.getAttribute('selenium')) {
        detected = true;
    }
    
    // Check for PhantomJS
    if (window.callPhantom || window._phantom) {
        detected = true;
    }
    
    // Check for unusual user agents
    if (navigator.userAgent.indexOf('Headless') !== -1 ||
        navigator.userAgent.indexOf('PhantomJS') !== -1 ||
        navigator.userAgent.indexOf('SlimerJS') !== -1) {
        detected = true;
    }
    
    if (detected) {
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
    }
})();
"""
    
    def _fingerprint_check(self) -> str:
        """Check browser fingerprint"""
        return """
(function() {
    var fingerprint = [
        navigator.userAgent,
        navigator.language,
        screen.colorDepth,
        screen.width + 'x' + screen.height,
        new Date().getTimezoneOffset(),
        !!window.sessionStorage,
        !!window.localStorage
    ].join('|');
    
    var hash = btoa(fingerprint);
    
    // Check if fingerprint matches known automation tools
    var suspicious = ['PHANTOM', 'SELENIUM', 'HEADLESS'];
    for (var i = 0; i < suspicious.length; i++) {
        if (hash.indexOf(suspicious[i]) !== -1) {
            document.body.innerHTML = '';
            window.location.href = 'about:blank';
        }
    }
})();
"""
    
    def _base64_obfuscation(self, code: str) -> str:
        """Base64 encode JavaScript code"""
        encoded = base64.b64encode(code.encode()).decode()
        return f"atob('{encoded}');"
    
    def _hex_encoding(self, code: str) -> str:
        """Hex encode JavaScript code"""
        hex_encoded = ''.join(f'\\x{ord(c):02x}' for c in code)
        return f"eval('{hex_encoded}');"
    
    def _unicode_encoding(self, code: str) -> str:
        """Unicode encode JavaScript code"""
        unicode_encoded = ''.join(f'\\u{ord(c):04x}' for c in code)
        return f"eval('{unicode_encoded}');"
    
    def _array_splitting(self, code: str) -> str:
        """Split code into character array"""
        chars = [f"'{c}'" for c in code]
        array_str = f"[{','.join(chars)}]"
        return f"eval({array_str}.join(''));"
    
    def _function_renaming(self, code: str) -> str:
        """Rename functions randomly"""
        # Simple function renaming
        function_map = {}
        functions = re.findall(r'function\s+(\w+)', code)
        
        for func in functions:
            new_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            function_map[func] = new_name
        
        # Replace function names
        for old_name, new_name in function_map.items():
            code = code.replace(f'function {old_name}', f'function {new_name}')
            code = code.replace(f'{old_name}(', f'{new_name}(')
        
        return code
    
    def generate_anti_tampering(self) -> str:
        """Generate anti-tampering protection"""
        return """
(function() {
    var originalCode = arguments.callee.toString();
    
    setInterval(function() {
        if (arguments.callee.toString() !== originalCode) {
            document.body.innerHTML = '';
            window.location.href = 'about:blank';
        }
    }, 1000);
    
    // Prevent right-click
    document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        return false;
    });
    
    // Prevent F12 and other devtools shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.keyCode === 123 || // F12
            (e.ctrlKey && e.shiftKey && e.keyCode === 73) || // Ctrl+Shift+I
            (e.ctrlKey && e.shiftKey && e.keyCode === 74) || // Ctrl+Shift+J
            (e.ctrlKey && e.keyCode === 85)) { // Ctrl+U
            e.preventDefault();
            return false;
        }
    });
})();
"""
    
    def generate_runtime_protection(self) -> str:
        """Generate runtime protection"""
        return """
(function() {
    // Prevent code inspection
    var _0x1234 = function() {
        var _0x5678 = function() {
            return 'devtools' in window;
        };
        
        if (_0x5678()) {
            while (true) {
                debugger;
            }
        }
    };
    
    setInterval(_0x1234, 1000);
    
    // Check for modified DOM
    var originalHTML = document.documentElement.outerHTML;
    setInterval(function() {
        if (document.documentElement.outerHTML !== originalHTML) {
            document.body.innerHTML = '';
            window.location.href = 'about:blank';
        }
    }, 500);
})();
"""
    
    def generate_crypto_mining_detection(self) -> str:
        """Generate crypto mining detection"""
        return """
(function() {
    var originalCanvas = document.createElement('canvas');
    var ctx = originalCanvas.getContext('2d');
    
    // Check for high CPU usage
    var start = performance.now();
    var result = 0;
    for (var i = 0; i < 10000000; i++) {
        result += Math.sqrt(i);
    }
    var end = performance.now();
    
    if (end - start < 100) {
        // Too fast - likely in a VM/sandbox
        document.body.innerHTML = '';
        window.location.href = 'about:blank';
    }
    
    // Check for WebAssembly crypto mining
    if (typeof WebAssembly === 'object') {
        var memory = new WebAssembly.Memory({ initial: 256 });
        if (memory.buffer.byteLength > 16777216) {
            document.body.innerHTML = '';
            window.location.href = 'about:blank';
        }
    }
})();
"""
    
    def generate_network_check(self) -> allowed_domains: List[str] = None) -> str:
        """Generate network connectivity check"""
        if allowed_domains is None:
            allowed_domains = ['google.com', 'facebook.com', 'microsoft.com']
        
        checks = []
        for domain in allowed_domains:
            check = f"""
fetch('https://{domain}/favicon.ico', {{
    method: 'HEAD',
    mode: 'no-cors'
}}).catch(function() {{
    document.body.innerHTML = '';
    window.location.href = 'about:blank';
}});
"""
            checks.append(check)
        
        return f"(function(){{\n{''.join(checks)}\n}})();"

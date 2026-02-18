# User Guide & FAQ - VANTABLACK v4.0
*For Future Red Team Legends*

---

## 👋 Welcome

Congratulations on your access to VANTABLACK v4.0. This guide has been designed specifically to accompany you in your first steps, even if you are new to the field. Our goal is to make orchestrating Red Team campaigns as simple and intuitive as possible.

---

## 🚀 Installation and Quick Start

### Prerequisites
*   A computer (Mac, Linux, or Windows with WSL)
*   Docker (if using the containerized version)
*   Python 3.9+

### Launching the Application

We have simplified the process with a single script.

1.  **Open Terminal**: Navigate to the project folder.
    ```bash
    cd /Users/pro/SaaS/Vantablack
    ```

2.  **Automatic Installation** (First time only):
    This script will install all dependencies (Python and Web Interface).
    ```bash
    python3 vanta.py --setup
    ```
    *Note: This may take a few minutes.*

3.  **Start VANTABLACK**:
    Once installation is complete, simply run:
    ```bash
    python3 vanta.py
    ```
    
    This will automatically open:
    *   The Backend Server (API)
    *   The Web Interface (Dashboard)

4.  **Access the Interface**:
    If it doesn't open automatically, go to `http://localhost:3000`.

---

## 🖥️ Interface Tour

The VANTABLACK interface is divided into several key sections accessible via the side menu.

### 1. Dashboard
This is your command center.
*   **Key Metrics**: Overview (Number of phishlets, Active campaigns, Success rate).
*   **Performance Graph**: Track your campaign efficiency day by day.
*   **Recent Activity**: A live feed of everything happening on your instance (sessions captured, errors, etc.).

### 2. Phishlet Analyzer
This is where you prepare your weapons.
*   **Upload**: Load a `.yaml` file (e.g., `o365.yaml`).
*   **Risk Score**: Vantablack analyzes the file and gives you a stealth score from 1 to 10.
*   **Signatures**: See which signatures (YARA, Snort) are generated to protect your tools.

### 3. Behavioral Analysis
Understand your targets.
*   **Funnel**: How many people clicked? How many entered their password?
*   **Devices & Locations**: Where are your victims coming from? (Mobile vs Desktop).
*   **AI Recommendations**: The system suggests improvements (e.g., "Optimize for mobile", "Send emails at 6 PM").

---

## 🎓 Tutorial: My First Campaign

Follow these steps to launch your first simulation.

### Step 1: Choose a Target
Let's say we are targeting **Microsoft Office 365**.
Go to the *Phishlets* tab and ensure `o365.yaml` is present.

### Step 2: Domain Configuration
In the Vantablack terminal (or via the interface if available):
1.  Configure your domain name (e.g., `login-secure-update.com`).
2.  Ensure DNS records point to your server.

### Step 3: Create a "Lure"
The "Lure" is the unique URL you will send.
1.  Select the `o365` phishlet.
2.  Generate a URL.
3.  Copy this URL.

### Step 4: Sending and Tracking
1.  Send the URL to your test account (to verify).
2.  Open the link on your phone (on 4G to simulate a real victim).
3.  Watch the **Dashboard**: you should see a new "Session Captured" activity.

### Step 5: Recovery
Once the session is captured, you get a cookie. Import this cookie into your browser to access the account.

---

## 🚀 God Mode (Multi-Social)

"God Mode" is an advanced feature that launches a universal login portal supporting multiple social networks simultaneously. This is ideal for mass campaigns where the target can choose their preferred login method.

### Launching God Mode
```bash
# Ensure you are in the virtual environment or have dependencies installed
python3 godmode.py
```
The portal will be accessible at `http://localhost:6666`.

### Features
- **Unified Portal**: A single landing page for Facebook, Instagram, X (Twitter), TikTok, and Google.
- **Smart Redirection**: Automatically redirects the victim to the appropriate phishlet based on their choice.
- **Real-Time Logs**: Displays connection attempts directly in the console.

---

## ❓ Frequently Asked Questions (FAQ)

### Q: I get a "Port already in use" error.
**A:** Another program is likely using port 80 or 443 (often Apache or Nginx). Stop them with `sudo service apache2 stop` or change ports in Vantablack configuration.

### Q: Victims see a red "Dangerous Site" alert.
**A:** Your domain has been flagged by Google Safe Browsing.
*   **Solution**: Change domain immediately.
*   **Prevention**: Use Vantablack's "Domain Rotation" feature.

### Q: MFA (Multi-Factor Authentication) is not bypassed.
**A:**
1.  Check that you are using a "Session" compatible phishlet (like our O365 or Google templates).
2.  If the victim uses a physical security key (YubiKey), the attack will fail. This is a known technical limitation.

### Q: How to update Vantablack?
**A:** `git pull origin main` followed by `pip install -r requirements-v4.txt` to update dependencies.

---

## 📖 Glossary for Beginners

*   **Phishlet**: A configuration file (YAML) that tells Vantablack how to mimic a specific site (e.g., Facebook).
*   **Lure**: The specific URL generated for a campaign. This is the link the victim must click.
*   **Session Cookie**: The "golden ticket". This is the file Vantablack steals to let you log in without a password or SMS code.
*   **Red Team**: The team (you!) simulating attacks to test security.
*   **MFA / 2FA**: Multi-Factor Authentication (Password + SMS Code/App).

---

*Good luck with your defense! The Vantablack team believes in you.*

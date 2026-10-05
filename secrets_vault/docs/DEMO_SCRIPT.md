# 5–10 Minute Evaluation Demo

## 1. Start (30 sec)
```bash
./run.sh
```
Explain: "This is a Linux C++ encrypted secrets vault with RBAC and a Linux character device audit driver."

## 2. Authentication (1 min)
First run creates `admin`. Login with the admin account.

Explain PBKDF2-HMAC-SHA256 + random salt and that the plaintext password is not stored.

## 3. RBAC (2 min)
```text
adduser alice USER
adduser guest GUEST
```
Create a secret:
```text
put company_secret
list
get company_secret
```
Explain that USER owns its secrets, ADMIN has full access, and GUEST is read-only.

## 4. Encryption (1 min)
Show that the secret is stored as an encrypted binary blob:
```bash
ls -l data/secrets/
xxd data/secrets/company_secret.enc | head
```
Explain AES-256-GCM, IV and authentication tag.

## 5. Audit + driver (2 min)
```text
audit
```
If the driver is loaded:
```bash
dmesg | tail -n 20
```
Explain user-space → `/dev/vault_logger` → kernel-space driver → kernel log.

## 6. Tests (30 sec)
```bash
make test
bash tests/rbac_test.sh
```
Conclude with architecture, security limitations, and future scope.

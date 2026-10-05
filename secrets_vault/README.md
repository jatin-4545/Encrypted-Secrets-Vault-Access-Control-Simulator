# Encrypted Secrets Vault & Access-Control Simulator

A Linux/C++17 Capstone project demonstrating **software architecture, operating-system concepts, cryptography, role-based access control (RBAC), secure storage, audit logging, and a Linux character device driver**.

## Features

- C++17 only for application code; designed for Linux.
- AES-256-GCM authenticated encryption for secret values.
- PBKDF2-HMAC-SHA256 password hashing with per-user random salt.
- RBAC roles: `ADMIN`, `USER`, `GUEST`.
- Owner-based access control: users can access their own secrets; admins can access all secrets; guests are read-only.
- Persistent metadata and encrypted secret files.
- Audit trail for authentication and vault operations.
- Optional Linux kernel character-device driver `/dev/vault_logger` used as an audit-event sink.
- Makefile, smoke test, documentation, and GitHub-ready structure.

## Architecture

```text
+------------------------- User / CLI --------------------------+
| Authentication | RBAC | Vault Commands | Session Management |
+------------------------------+--------------------------------+
                               |
                               v
+----------------------- Application Layer ---------------------+
| Vault Service | AES-256-GCM | PBKDF2 | Metadata | Audit API |
+------------------------------+--------------------------------+
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
       encrypted secrets/             metadata/users
                 |                           |
                 +-------------+-------------+
                               |
                               v
                 /dev/vault_logger (optional)
                               |
                               v
                   Linux Character Device
                               |
                               v
                          Kernel log
```

## Requirements

Ubuntu/Debian Linux is recommended.

```bash
sudo apt update
sudo apt install -y g++ make libssl-dev
```

For the optional kernel module:

```bash
sudo apt install -y linux-headers-$(uname -r)
```

## Build and run

```bash
make
./bin/secrets_vault
```

On first run the application creates an `admin` account. Choose a password of at least 8 characters.

The program stores its data under `./data` by default. You can specify another directory:

```bash
./bin/secrets_vault ./data
```

## Demo flow for evaluation

1. First launch -> create admin password.
2. Login as `admin`.
3. `adduser alice USER` and create Alice's password.
4. `put bank_pin` -> enter a secret.
5. `list` -> show metadata.
6. `get bank_pin` -> decrypt the secret.
7. `audit` -> demonstrate audit events.
8. Explain that RBAC prevents `GUEST` from writing/deleting and prevents normal users from accessing another user's secret.

## Linux Device Driver

The driver is intentionally an **optional kernel component** because loading a kernel module requires root privileges and matching Linux kernel headers. The main application still works safely with a file-based audit fallback.

Build/load:

```bash
cd driver
make
sudo insmod vault_logger.ko
sudo chmod 666 /dev/vault_logger
ls -l /dev/vault_logger
```

Then run the vault from the project root:

```bash
./bin/secrets_vault
```

Audit events are sent to `/dev/vault_logger` when available. Inspect kernel messages:

```bash
dmesg | tail -n 30
```

Unload:

```bash
sudo rmmod vault_logger
```

## Test

```bash
make test
```

The smoke test creates an isolated test data directory, creates the admin account, stores an encrypted secret, retrieves it, lists it, and checks the audit log.

## Security notes

This is an educational simulator, not a production password manager. Passwords are not stored in plaintext. Secret values are encrypted with AES-256-GCM. The current session password is held in process memory only. A production vault should use a dedicated key-management mechanism, memory locking/zeroization, stronger threat modeling, secure deletion, filesystem permissions, and external key storage.

## GitHub submission structure

```text
Encrypted-Secrets-Vault/
├── README.md
├── Makefile
├── include/
│   └── vault.hpp
├── src/
│   ├── main.cpp
│   └── vault.cpp
├── driver/
│   ├── Makefile
│   ├── vault_logger.c
│   └── install_driver.sh
├── tests/
│   └── smoke_test.sh
├── docs/
│   └── ARCHITECTURE.md
└── data/
    └── .gitkeep
```

Do **not** commit real secrets, passwords, generated `data/` files, `.ko` modules, or private test output.

## Suggested viva points

- Why AES-256-GCM? It provides confidentiality plus integrity/authentication.
- Why PBKDF2? Passwords are converted into a derived key/hash using a salt and high iteration count, making brute-force attacks more expensive.
- What is RBAC? Permissions are assigned through roles rather than individual hard-coded checks.
- Why a character driver? It demonstrates the Linux user-space/kernel-space boundary and device-file I/O.
- What happens if the driver is absent? The application falls back to `data/audit.log`, so the vault remains usable.
- Which architecture concepts are demonstrated? Layering, separation of concerns, persistent storage, access-control boundary, and kernel/user-space interaction.

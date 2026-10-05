# Architecture and Design Notes

## 1. Modules

### CLI layer
Handles login, command parsing, input, and presentation.

### Vault service
Manages users, secret metadata, ownership, RBAC checks, and audit calls.

### Cryptography layer
Uses OpenSSL EVP AES-256-GCM for encryption and PBKDF2-HMAC-SHA256 for password/key derivation.

### Storage layer
Stores user records and metadata separately from encrypted secret blobs. Secret files contain a format marker, salt, IV, authentication tag, and ciphertext.

### Audit layer
Attempts to write events to `/dev/vault_logger`. If the device is not present, it writes to `data/audit.log`.

### Kernel driver
A Linux character device accepts audit records from user space and emits them through the kernel log. This demonstrates `copy_from_user`, device registration, file operations, mutex synchronization, and kernel/user-space interaction.

## 2. Access-control matrix

| Operation | ADMIN | USER | GUEST |
|---|---:|---:|---:|
| Login | Yes | Yes | Yes |
| Create user | Yes | No | No |
| Create secret | Yes | Yes | No |
| Read own secret | Yes | Yes | Yes |
| Read another user's secret | Yes | No | No |
| Delete own secret | Yes | Yes | No |
| Delete another user's secret | Yes | No | No |

## 3. Threats addressed

- Plaintext password storage -> salted PBKDF2.
- Ciphertext modification -> GCM authentication tag.
- Unauthorized secret access -> RBAC + owner checks.
- Missing audit visibility -> audit file + optional kernel device.

## 4. Limitations

- Educational project; not production-ready.
- Session password remains in process memory while logged in.
- The demo driver logs audit events to the kernel log; it is not a complete tamper-proof audit subsystem.
- Secure erase and hardware-backed key storage are outside the scope.

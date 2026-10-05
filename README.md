# Encrypted Secrets Vault & Access-Control Simulator

## Capstone Project

A Linux-based C++ security application that demonstrates authentication,
Role-Based Access Control (RBAC), encrypted secret storage, audit
logging, and Linux character-device driver concepts.

## Features

-   C++ command-line application for Linux
-   ADMIN, USER and GUEST roles
-   User authentication
-   Role-Based Access Control (RBAC)
-   AES-256-GCM authenticated encryption for secrets
-   PBKDF2-HMAC-SHA256 for password/key derivation
-   Encrypted secret storage
-   Secret retrieval and deletion
-   Password change
-   Audit logging
-   Linux character-device driver in `driver/vault_logger.c`
-   Automated smoke and RBAC tests
-   Makefile-based build

## Project Structure

``` text
Encrypted-Secrets-Vault/
├── README.md
├── Makefile
├── run.sh
├── .gitignore
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
│   ├── smoke_test.sh
│   └── rbac_test.sh
├── docs/
│   ├── ARCHITECTURE.md
│   └── DEMO_SCRIPT.md
└── data/
```

## Requirements

Recommended:

-   Ubuntu 22.04/24.04 or another Linux distribution
-   g++
-   make
-   OpenSSL development libraries
-   unzip
-   build-essential
-   Linux kernel headers for the driver

Install dependencies:

``` bash
sudo apt update
sudo apt install g++ make libssl-dev unzip build-essential -y
```

For the driver:

``` bash
sudo apt install linux-headers-$(uname -r) -y
```

> The main application can run in WSL. Linux kernel-module support can
> be limited in WSL, so use native Ubuntu or an Ubuntu VM for the
> strongest device-driver demonstration.

## Build

Clone the repository:

``` bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Encrypted-Secrets-Vault
```

Build:

``` bash
make
```

The executable is:

``` text
bin/secrets_vault
```

## Run

Run the application:

``` bash
./bin/secrets_vault
```

or:

``` bash
chmod +x run.sh
./run.sh
```

On the first run, create the administrator password when prompted.

After login, the prompt is:

``` text
vault>
```

Use:

``` text
help
```

to see all commands.

## Main Commands

### Create a user

``` text
adduser <name> <role>
```

Example:

``` text
adduser alice USER
```

### Store a secret

``` text
put <id>
```

Example:

``` text
put database_password
```

### Retrieve a secret

``` text
get <id>
```

Example:

``` text
get database_password
```

### List accessible secrets

``` text
list
```

### Delete a secret

``` text
del <id>
```

### Change password

``` text
passwd
```

### Show current user and role

``` text
whoami
```

### Show audit log

``` text
audit
```

### Logout / Exit

``` text
logout
exit
```

## Example Demonstration

Login as the administrator:

``` text
Username: admin
Password: ********
Logged in as admin [ADMIN]
```

Create a user:

``` text
vault> adduser alice USER
```

Store a test secret:

``` text
vault> put database_password
```

Retrieve it:

``` text
vault> get database_password
```

Show the audit log:

``` text
vault> audit
```

The main security flow is:

``` text
User
  |
  v
Authentication
  |
  v
RBAC Authorization
  |
  v
AES-256-GCM Encryption
  |
  v
Encrypted Storage
  |
  v
Authorized Decryption
  |
  v
Audit Logging
```

## Automated Tests

Run the smoke test:

``` bash
./tests/smoke_test.sh
```

Expected:

``` text
SMOKE TEST PASSED
```

Run the RBAC test:

``` bash
./tests/rbac_test.sh
```

Expected:

``` text
RBAC TEST PASSED
```

## Linux Character Device Driver

Driver source:

``` text
driver/vault_logger.c
```

Build:

``` bash
cd driver
make
```

This should produce:

``` text
vault_logger.ko
```

Load:

``` bash
sudo insmod vault_logger.ko
```

Check:

``` bash
lsmod | grep vault_logger
```

Check the device:

``` bash
ls -l /dev/vault_logger
```

View kernel messages:

``` bash
sudo dmesg | tail -20
```

Remove the module:

``` bash
sudo rmmod vault_logger
```

## Troubleshooting

If `g++` is missing:

``` bash
sudo apt install g++
```

If `make` is missing:

``` bash
sudo apt install make
```

If OpenSSL headers are missing:

``` bash
sudo apt install libssl-dev
```

Then rebuild:

``` bash
make clean
make
```

If the executable is not executable:

``` bash
chmod +x bin/secrets_vault
```

## Capstone Requirement Mapping

  Requirement             Implementation
  ----------------------- ------------------------------------------
  C/C++ only              C++ application + C Linux driver
  Linux OS                Ubuntu/Linux
  Linux Device Driver     `driver/vault_logger.c`
  Software Architecture   Vault, crypto, RBAC and audit components
  Source Code             `src/`, `include/`, `driver/`
  Documentation           `README.md`, `docs/`
  Testing                 `tests/`
  GitHub Submission       Git repository
  Demonstration           CLI, RBAC, encryption, audit and driver

## GitHub Upload

``` bash
git init
git add .
git commit -m "Initial Capstone project"
git branch -M main
git remote add origin <YOUR_GITHUB_REPOSITORY_URL>
git push -u origin main
```

Do not commit real passwords, private keys, or sensitive runtime
secrets.

## Recommended 5--10 Minute Evaluation

1.  Explain the project objective.
2.  Show the architecture and project structure.
3.  Run `make`.
4.  Start `./bin/secrets_vault`.
5.  Login as ADMIN.
6.  Create a USER.
7.  Store a secret.
8.  Retrieve the secret.
9.  Demonstrate RBAC.
10. Show the audit log.
11. Run the automated tests.
12. Explain the Linux character-device driver.
13. Show the GitHub repository.

## Author

**Jatin Kumar**

B.Tech. Student\
Siksha 'O' Anusandhan University, ITER, Odisha

**Project:** Encrypted Secrets Vault & Access-Control Simulator

## License

This project is developed for academic/educational Capstone purposes.

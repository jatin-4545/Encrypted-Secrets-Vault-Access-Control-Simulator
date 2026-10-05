#!/usr/bin/env bash
set -euo pipefail
ROOT="./data_test_rbac"
rm -rf "$ROOT"
# Admin creates alice and bob, stores admin secret, then alice tries to access admin secret.
printf 'Admin123!\nadmin\nAdmin123!\nadduser alice USER\nAlice123!\nadduser bob USER\nBob12345!\nput admin_secret\nadmin-only\nget admin_secret\nexit\n' | ./bin/secrets_vault "$ROOT" >/tmp/admin.out
# Alice can login and must not see admin's secret.
printf 'alice\nAlice123!\nlist\nget admin_secret\nexit\n' | ./bin/secrets_vault "$ROOT" >/tmp/alice.out
! grep -q 'admin_secret |' /tmp/alice.out
grep -q 'ACCESS DENIED' /tmp/alice.out
echo 'RBAC TEST PASSED'

#!/usr/bin/env bash
set -euo pipefail
ROOT="./data_test"
rm -rf "$ROOT"
printf 'Admin123!\nadmin\nAdmin123!\nput demo\nmy secret value\nget demo\nlist\naudit\nexit\n' | ./bin/secrets_vault "$ROOT" > /tmp/vault_test.out
cat /tmp/vault_test.out
grep -q 'Encrypted secret stored.' /tmp/vault_test.out
grep -q 'SECRET: my secret value' /tmp/vault_test.out
grep -q 'demo | owner=admin' /tmp/vault_test.out
grep -q 'action=PUT_SECRET' /tmp/vault_test.out
echo 'SMOKE TEST PASSED'

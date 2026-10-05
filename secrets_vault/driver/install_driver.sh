#!/usr/bin/env bash
set -euo pipefail
make
sudo insmod vault_logger.ko
sudo chmod 666 /dev/vault_logger
ls -l /dev/vault_logger
echo 'Driver loaded. Check kernel events with: dmesg | tail -n 20'

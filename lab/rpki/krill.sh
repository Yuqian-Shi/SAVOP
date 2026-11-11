#!/usr/bin/env bash
set -e
update-ca-certificates
rsync --daemon
/root/.cargo/bin/krill -c /var/krill/data/krill.conf 

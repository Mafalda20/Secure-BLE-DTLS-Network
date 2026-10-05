#!/usr/bin/env bash
set -euo pipefail

pki_dir="${HOME}/.config/sic/pki"
exec openssl s_server \
    -dtls1_2 \
    -accept 4444 \
    -cert "$pki_dir/dtls.crt" \
    -key "$pki_dir/dtls.key" \
    -CAfile "$pki_dir/ca.crt" \
    -Verify 1 \
    -state

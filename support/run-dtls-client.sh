#!/usr/bin/env bash
set -euo pipefail

pki_dir="${HOME}/.config/sic/pki"
exec openssl s_client \
    -dtls1_2 \
    -connect 127.0.0.1:5555 \
    -cert "$pki_dir/dtls.crt" \
    -key "$pki_dir/dtls.key" \
    -CAfile "$pki_dir/ca.crt" \
    -verify_return_error \
    -state

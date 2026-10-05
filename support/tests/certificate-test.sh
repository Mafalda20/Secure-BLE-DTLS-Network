#!/usr/bin/env bash
set -euo pipefail

role="${1:-}"
case "$role" in
    sink|node) ;;
    *)
        echo "Uso: $0 sink|node" >&2
        exit 2
        ;;
esac

config_dir="${HOME}/.config/sic"
pki_dir="${config_dir}/pki"
nid_file="${config_dir}/nid"
ca_cert="${pki_dir}/ca.crt"
device_cert="${pki_dir}/device.crt"
device_key="${pki_dir}/device.key"
dtls_cert="${pki_dir}/dtls.crt"
dtls_key="${pki_dir}/dtls.key"

for required in \
    "$nid_file" "$ca_cert" "$device_cert" "$device_key" \
    "$dtls_cert" "$dtls_key"; do
    if [[ ! -r "$required" ]]; then
        echo "[FAIL] ficheiro ausente ou ilegivel: $required" >&2
        exit 1
    fi
done

nid="$(tr -d '[:space:]' < "$nid_file")"
if [[ ! "$nid" =~ ^[0-9a-fA-F]{32}$ ]]; then
    echo "[FAIL] NID persistente invalido" >&2
    exit 1
fi

openssl verify -CAfile "$ca_cert" "$device_cert" >/dev/null
echo "[PASS] certificado pertence a CA configurada"

certificate_text="$(openssl x509 -in "$device_cert" -noout -text)"
grep -Fq "$nid" <<< "$certificate_text"
echo "[PASS] certificado contem o NID persistente"

grep -Fq "$role" <<< "$certificate_text"
echo "[PASS] certificado contem o papel $role"

key_public_hash="$({ openssl pkey -in "$device_key" -pubout 2>/dev/null; } | openssl sha256)"
cert_public_hash="$(openssl x509 -in "$device_cert" -pubkey -noout | openssl sha256)"
if [[ "$key_public_hash" != "$cert_public_hash" ]]; then
    echo "[FAIL] certificado nao corresponde a chave privada" >&2
    exit 1
fi
echo "[PASS] certificado corresponde a chave privada local"

key_mode="$(stat -c '%a' "$device_key")"
if [[ "$key_mode" != "600" ]]; then
    echo "[FAIL] chave privada tem modo $key_mode em vez de 600" >&2
    exit 1
fi
echo "[PASS] chave privada esta protegida com modo 600"

openssl verify -CAfile "$ca_cert" "$dtls_cert" >/dev/null
dtls_text="$(openssl x509 -in "$dtls_cert" -noout -text)"
grep -Fq "$nid" <<< "$dtls_text"
grep -Fq "$role" <<< "$dtls_text"
dtls_key_hash="$({ openssl pkey -in "$dtls_key" -pubout 2>/dev/null; } | openssl sha256)"
dtls_cert_hash="$(openssl x509 -in "$dtls_cert" -pubkey -noout | openssl sha256)"
if [[ "$dtls_key_hash" != "$dtls_cert_hash" ]]; then
    echo "[FAIL] certificado DTLS nao corresponde a chave privada" >&2
    exit 1
fi
echo "[PASS] certificado DTLS ECDSA pertence a CA, contem NID/papel e corresponde a chave"

echo "NID=$nid"
openssl x509 -in "$device_cert" -noout -subject -serial -fingerprint -sha256

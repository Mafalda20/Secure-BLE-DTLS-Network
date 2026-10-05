#!/usr/bin/env bash
set -euo pipefail

command_name="${1:-}"
session_dir="${2:-}"

if [[ -z "$command_name" || -z "$session_dir" ]]; then
    echo "Uso: $0 prepare DIR | finalize DIR NID PAPEL" >&2
    exit 2
fi

pki_dir="${HOME}/.config/sic/pki"
mkdir -p "$session_dir"
chmod 700 "$session_dir"

case "$command_name" in
    prepare)
        openssl genpkey \
            -algorithm X25519 \
            -out "$session_dir/ephemeral.key"
        chmod 600 "$session_dir/ephemeral.key"

        openssl pkey \
            -in "$session_dir/ephemeral.key" \
            -pubout \
            -out "$session_dir/ephemeral.pub"

        openssl pkeyutl \
            -sign \
            -inkey "$pki_dir/device.key" \
            -rawin \
            -in "$session_dir/ephemeral.pub" \
            -out "$session_dir/ephemeral.sig"

        cp "$pki_dir/device.crt" "$session_dir/device.crt"
        chmod 644 \
            "$session_dir/ephemeral.pub" \
            "$session_dir/ephemeral.sig" \
            "$session_dir/device.crt"

        echo "[PASS] material efemero criado e assinado"
        ;;

    finalize)
        expected_nid="${3:-}"
        expected_role="${4:-}"
        if [[ ! "$expected_nid" =~ ^[0-9a-fA-F]{32}$ ]] ||
           [[ "$expected_role" != "sink" && "$expected_role" != "node" ]]; then
            echo "NID ou papel esperado invalido" >&2
            exit 2
        fi

        for peer_file in peer.crt peer-ephemeral.pub peer-ephemeral.sig; do
            if [[ ! -r "$session_dir/$peer_file" ]]; then
                echo "[FAIL] falta $session_dir/$peer_file" >&2
                exit 1
            fi
        done

        openssl verify \
            -CAfile "$pki_dir/ca.crt" \
            "$session_dir/peer.crt" >/dev/null
        echo "[PASS] certificado do peer pertence a CA"

        peer_text="$(openssl x509 -in "$session_dir/peer.crt" -noout -text)"
        grep -Fq "$expected_nid" <<< "$peer_text"
        grep -Fq "$expected_role" <<< "$peer_text"
        echo "[PASS] NID e papel do peer autenticados"

        openssl x509 \
            -in "$session_dir/peer.crt" \
            -pubkey \
            -noout \
            -out "$session_dir/peer-identity.pub"

        openssl pkeyutl \
            -verify \
            -pubin \
            -inkey "$session_dir/peer-identity.pub" \
            -rawin \
            -in "$session_dir/peer-ephemeral.pub" \
            -sigfile "$session_dir/peer-ephemeral.sig" >/dev/null
        echo "[PASS] peer provou posse da chave privada certificada"

        openssl pkeyutl \
            -derive \
            -inkey "$session_dir/ephemeral.key" \
            -peerkey "$session_dir/peer-ephemeral.pub" \
            -out "$session_dir/shared.secret"
        chmod 600 "$session_dir/shared.secret"

        secret_hex="$(xxd -p -c 256 "$session_dir/shared.secret")"
        openssl kdf \
            -binary \
            -keylen 32 \
            -kdfopt digest:SHA256 \
            -kdfopt "hexkey:$secret_hex" \
            -kdfopt salt:SIC-Especial-link-v1 \
            -kdfopt info:authenticated-BLE-link \
            -out "$session_dir/session.key" \
            HKDF
        chmod 600 "$session_dir/session.key"

        echo "[PASS] session key X25519/HKDF derivada"
        sha256sum "$session_dir/session.key" | awk '{print "SESSION_KEY_SHA256=" $1}'
        ;;

    *)
        echo "Comando desconhecido: $command_name" >&2
        exit 2
        ;;
esac

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -z "${RELAY_KEYSTORE_PASSWORD:-}" ]]; then
  echo 'Defina RELAY_KEYSTORE_PASSWORD (mínimo 6 caracteres) antes de executar.' >&2
  exit 1
fi
if [[ -e server.p12 || -e server.crt ]]; then
  echo 'server.p12 ou server.crt já existem. Não sobrescrever para evitar quebra do pinning.' >&2
  exit 1
fi
keytool -genkeypair -alias servidor -keyalg RSA -keysize 3072 -sigalg SHA256withRSA \
  -dname 'CN=Servidor Relay, OU=Seguranca, O=Trabalho Pratico 3' -validity 365 \
  -keystore server.p12 -storetype PKCS12 \
  -storepass "$RELAY_KEYSTORE_PASSWORD" -keypass "$RELAY_KEYSTORE_PASSWORD" -noprompt
keytool -exportcert -rfc -alias servidor -keystore server.p12 \
  -storepass "$RELAY_KEYSTORE_PASSWORD" -file server.crt
echo 'Criados server.p12 (privado) e server.crt (para distribuir aos clientes fora da rede).'

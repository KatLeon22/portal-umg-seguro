#!/usr/bin/env bash
# Configuración de HashiCorp Vault para el laboratorio (modo dev = solo pruebas).
# 1) En otra terminal:  vault server -dev -dev-root-token-id="$(openssl rand -hex 16)"
#    (el token raíz solo se usa para esta configuración inicial y luego se descarta)
# 2) export VAULT_ADDR=http://127.0.0.1:8200 ; export VAULT_TOKEN=<token raíz dev>
set -euo pipefail
: "${VAULT_ADDR:?defina VAULT_ADDR}"

vault secrets list | grep -q '^secret/' || vault secrets enable -path=secret kv-v2
vault kv metadata put -max-versions=5 secret/portal-umg/app 2>/dev/null || true

# Secretos generados con CSPRNG directamente en Vault: nunca pasan por el repositorio
vault kv put secret/portal-umg/app \
  FLASK_SECRET_KEY="$(openssl rand -base64 48 | tr -d '\n')" \
  DATA_ENC_KEYS="v1:$(openssl rand -base64 32)" \
  BLIND_INDEX_KEY="$(openssl rand -base64 32)" \
  DATABASE_URL="sqlite:///instance/portal.db"

vault policy write portal-umg-app vault/politica-portal.hcl
vault policy write portal-umg-rotacion vault/politica-operador-rotacion.hcl

vault auth list | grep -q '^approle/' || vault auth enable approle
vault write auth/approle/role/portal-umg \
  token_policies="portal-umg-app" \
  token_ttl=1h token_max_ttl=4h \
  secret_id_ttl=24h secret_id_num_uses=1 \
  token_bound_cidrs="127.0.0.1/32" secret_id_bound_cidrs="127.0.0.1/32"

echo "ROLE_ID:";   vault read -field=role_id auth/approle/role/portal-umg/role-id
echo "SECRET_ID (un solo uso, 24 h):"; vault write -f -field=secret_id auth/approle/role/portal-umg/secret-id
echo "Arranque:  SECRETS_BACKEND=vault VAULT_ROLE_ID=... VAULT_SECRET_ID=... python run.py"

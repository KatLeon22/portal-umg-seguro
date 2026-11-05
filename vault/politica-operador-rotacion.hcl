# Política del operador de seguridad: rota y revoca, pero la aplicación no la posee.
path "secret/data/portal-umg/app"      { capabilities = ["create", "update", "read"] }
path "secret/metadata/portal-umg/app"  { capabilities = ["read", "update"] }
path "secret/destroy/portal-umg/app"   { capabilities = ["update"] }
path "auth/approle/role/portal-umg/secret-id"          { capabilities = ["update"] }
path "auth/approle/role/portal-umg/secret-id-accessor/destroy" { capabilities = ["update"] }

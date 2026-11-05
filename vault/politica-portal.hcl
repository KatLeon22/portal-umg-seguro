# Política de MÍNIMO PRIVILEGIO para la aplicación: solo puede LEER su propio secreto.
# No puede listar, escribir, borrar ni leer secretos de otras aplicaciones.
path "secret/data/portal-umg/app" {
  capabilities = ["read"]
}

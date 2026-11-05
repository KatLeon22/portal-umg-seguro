"""
Carga de secretos y configuración (Fase II-C: Gestión de secretos).

Ningún secreto vive en el código fuente. Los valores se obtienen de una
fuente externa, en este orden:
  1. HashiCorp Vault (KV v2, autenticación AppRole) si SECRETS_BACKEND=vault
  2. Variables de entorno del proceso (inyectadas por systemd, Docker o un
     archivo .env con permisos 600 que NUNCA se versiona).

Si falta un secreto obligatorio la aplicación NO arranca (fail-closed) y el
mensaje de error nombra la variable, nunca su valor.
"""
import base64
import os

SECRETOS_OBLIGATORIOS = (
    "FLASK_SECRET_KEY",   # firma de cookies de sesión
    "DATA_ENC_KEYS",      # claves AES-256-GCM versionadas: "v2:<b64>,v1:<b64>"
    "BLIND_INDEX_KEY",    # clave HMAC para índices de búsqueda sobre datos cifrados
    "DATABASE_URL",       # credencial/cadena de conexión a la base de datos
)


class ConfigError(RuntimeError):
    """Error de configuración. Nunca incluye el valor de un secreto."""


def _leer_desde_vault(entorno: dict) -> dict:
    """Lee los secretos desde Vault con AppRole (sin tokens en el código)."""
    try:
        import hvac  # dependencia opcional (requirements-vault.txt)
    except ImportError as exc:
        raise ConfigError("SECRETS_BACKEND=vault requiere el paquete hvac") from exc

    cliente = hvac.Client(url=entorno["VAULT_ADDR"])
    # role_id y secret_id los entrega el orquestador en el despliegue;
    # el secret_id es de un solo uso y de vida corta (ver vault/configurar_vault.sh)
    cliente.auth.approle.login(
        role_id=entorno["VAULT_ROLE_ID"],
        secret_id=entorno["VAULT_SECRET_ID"],
    )
    respuesta = cliente.secrets.kv.v2.read_secret_version(
        path=entorno.get("VAULT_SECRET_PATH", "portal-umg/app"),
        mount_point=entorno.get("VAULT_MOUNT", "secret"),
        raise_on_deleted_version=True,
    )
    return respuesta["data"]["data"]


def cargar_secretos(entorno: dict | None = None) -> dict:
    """Devuelve un diccionario con los secretos validados."""
    entorno = dict(os.environ if entorno is None else entorno)
    if entorno.get("SECRETS_BACKEND", "env") == "vault":
        origen = _leer_desde_vault(entorno)
    else:
        origen = entorno

    faltantes = [n for n in SECRETOS_OBLIGATORIOS if not origen.get(n)]
    if faltantes:
        raise ConfigError(
            "Faltan secretos obligatorios: " + ", ".join(faltantes)
            + ". Defínalos en Vault o en el entorno (ver .env.example)."
        )

    if len(origen["FLASK_SECRET_KEY"]) < 32:
        raise ConfigError("FLASK_SECRET_KEY debe tener al menos 32 caracteres")

    claves = _parsear_claves(origen["DATA_ENC_KEYS"])
    indice = _b64_32(origen["BLIND_INDEX_KEY"], "BLIND_INDEX_KEY")

    return {
        "SECRET_KEY": origen["FLASK_SECRET_KEY"],
        "DATA_ENC_KEYS": claves,               # {kid: bytes}; la primera es la activa
        "DATA_ENC_ACTIVE_KID": next(iter(claves)),
        "BLIND_INDEX_KEY": indice,
        "DATABASE_URL": origen["DATABASE_URL"],
    }


def _b64_32(valor: str, nombre: str) -> bytes:
    try:
        clave = base64.b64decode(valor, validate=True)
    except Exception as exc:
        raise ConfigError(f"{nombre} no es Base64 válido") from exc
    if len(clave) != 32:
        raise ConfigError(f"{nombre} debe decodificar a 32 bytes (256 bits)")
    return clave


def _parsear_claves(valor: str) -> dict:
    claves = {}
    for parte in valor.split(","):
        if ":" not in parte:
            raise ConfigError("DATA_ENC_KEYS debe tener el formato kid:base64,...")
        kid, b64 = parte.strip().split(":", 1)
        if not kid.isalnum():
            raise ConfigError("Identificador de clave inválido en DATA_ENC_KEYS")
        claves[kid] = _b64_32(b64, f"DATA_ENC_KEYS[{kid}]")
    return claves

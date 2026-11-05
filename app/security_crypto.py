"""
Fase II-A y II-B: contraseñas y protección criptográfica de datos.

No se implementa ningún algoritmo propio. Se usan bibliotecas reconocidas:
  * Contraseñas: werkzeug.security con scrypt (hashlib/OpenSSL por debajo).
    Parámetros N=2^17, r=8, p=1, la configuración mínima recomendada por la
    OWASP Password Storage Cheat Sheet para scrypt. Sal aleatoria de 16
    caracteres generada con el módulo `secrets` (CSPRNG) por cada usuario.
  * Datos en reposo: AES-256-GCM (cifrado autenticado, AEAD) de la biblioteca
    `cryptography` (pyca), nonce de 96 bits aleatorio por mensaje y datos
    asociados (AAD) que atan el texto cifrado a su registro.
  * Búsqueda sobre datos cifrados: índice ciego HMAC-SHA256 con clave propia.
"""
import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.security import check_password_hash, generate_password_hash

METODO_KDF = "scrypt:131072:8:1"
LONGITUD_SAL = 16

# Hash de relleno: se verifica contra él cuando el usuario no existe, para que
# el tiempo de respuesta no revele qué correos están registrados.
_HASH_RELLENO = generate_password_hash("relleno-no-valido", METODO_KDF, LONGITUD_SAL)


# --------------------------------------------------------------- contraseñas
def hash_password(password: str) -> str:
    """Devuelve 'scrypt:N:r:p$<sal>$<hash hex>'. Sal nueva en cada llamada."""
    return generate_password_hash(password, method=METODO_KDF, salt_length=LONGITUD_SAL)


def verificar_password(hash_almacenado: str | None, password: str) -> bool:
    """Verificación en tiempo constante (hmac.compare_digest dentro de werkzeug)."""
    if not hash_almacenado:
        check_password_hash(_HASH_RELLENO, password)
        return False
    return check_password_hash(hash_almacenado, password)


def requiere_rehash(hash_almacenado: str) -> bool:
    """True si el hash usa parámetros antiguos y debe recalcularse al iniciar sesión."""
    return not hash_almacenado.startswith(METODO_KDF + "$")


def sha256_inseguro(password: str) -> str:
    """ANTIPATRÓN usado solo en el laboratorio para demostrar el problema."""
    return hashlib.sha256(password.encode()).hexdigest()


# ------------------------------------------------------- cifrado en reposo
class CifradorDatos:
    """Cifra campos sensibles con AES-256-GCM y claves versionadas.

    Formato almacenado:  <kid>:<base64(nonce(12) || texto_cifrado || tag(16))>
    El identificador de clave (kid) permite rotar claves sin perder la
    capacidad de descifrar registros antiguos (ver scripts/rotar_clave_datos.py).
    """

    def __init__(self, claves: dict, kid_activo: str, clave_indice: bytes):
        self._claves = claves
        self._kid_activo = kid_activo
        self._clave_indice = clave_indice

    def cifrar(self, texto: str, contexto: str) -> str:
        nonce = os.urandom(12)  # nunca se reutiliza un nonce con la misma clave
        datos = AESGCM(self._claves[self._kid_activo]).encrypt(
            nonce, texto.encode("utf-8"), contexto.encode("utf-8")
        )
        return f"{self._kid_activo}:{base64.b64encode(nonce + datos).decode()}"

    def descifrar(self, token: str, contexto: str) -> str:
        kid, b64 = token.split(":", 1)
        if kid not in self._claves:
            raise ValueError("Clave de cifrado desconocida o revocada")
        bruto = base64.b64decode(b64)
        try:
            texto = AESGCM(self._claves[kid]).decrypt(
                bruto[:12], bruto[12:], contexto.encode("utf-8")
            )
        except InvalidTag as exc:
            # El dato fue alterado o se intentó usar en otro registro
            raise ValueError("Integridad del dato cifrado comprometida") from exc
        return texto.decode("utf-8")

    def kid_de(self, token: str) -> str:
        return token.split(":", 1)[0]

    def indice_ciego(self, valor: str) -> str:
        """HMAC-SHA256 determinista: permite buscar por DPI sin descifrar la tabla."""
        return hmac.new(self._clave_indice, valor.encode("utf-8"), hashlib.sha256).hexdigest()


def enmascarar_dpi(dpi: str) -> str:
    return "*" * 9 + dpi[-4:]

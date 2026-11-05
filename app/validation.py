"""
Fase I-A: Validación de entradas.

Principios aplicados:
  * Normalizar ANTES de validar (Unicode NFC/NFKC, recorte de espacios), para
    que la validación se haga sobre la misma forma del dato que se usará.
  * Listas de permitidos (allowlist) con longitud mínima y máxima, no listas
    de bloqueo de "caracteres peligrosos".
  * Validación en el servidor (la del navegador es solo usabilidad).

IMPORTANTE: que un dato pase la validación significa que cumple las reglas de
NEGOCIO (forma, rango, longitud). NO significa que sea seguro insertarlo en
SQL, HTML o en un comando. Ejemplo: "O'Brien" es un apellido válido y aun así
rompe una consulta SQL concatenada. Por eso cada intérprete tiene su propio
control: consultas parametrizadas (SQL), codificación de salida según el
contexto (HTML/JS) y listas de argumentos sin shell (sistema operativo).
"""
import re
import unicodedata
from decimal import Decimal, InvalidOperation


class ValidationError(ValueError):
    """Error de validación con mensaje apto para mostrar al usuario."""


EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}$")
# Formato de carné UMG: código de carrera (4) - año (2) - correlativo (1 a 6)
CARNET_RE = re.compile(r"^\d{4}-\d{2}-\d{1,6}$")
# Letras (incluye tildes, ü y ñ), espacio, guion y apóstrofo; 2 a 60 caracteres
NOMBRE_RE = re.compile(r"^[A-Za-zÁÉÍÓÚÜÑáéíóúüñ][A-Za-zÁÉÍÓÚÜÑáéíóúüñ' -]{1,59}$")
# Búsqueda: letras, dígitos, espacio, guion, punto, @ y apóstrofo; 1 a 50 caracteres
BUSQUEDA_RE = re.compile(r"^[0-9A-Za-zÁÉÍÓÚÜÑáéíóúüñ' .@-]{1,50}$")
DPI_RE = re.compile(r"^\d{13}$")
NOMBRE_REPORTE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")  # no puede iniciar con "-" (opción)


def _normalizar(valor, forma="NFC") -> str:
    if not isinstance(valor, str):
        raise ValidationError("Se esperaba texto")
    valor = unicodedata.normalize(forma, valor).strip()
    if any(unicodedata.category(c) == "Cc" for c in valor):  # \n, \r, \t, \x00...
        raise ValidationError("El dato contiene caracteres de control")
    return re.sub(r"\s+", " ", valor)


def validar_email(valor: str) -> str:
    valor = _normalizar(valor, "NFKC").lower()
    if len(valor) > 254 or not EMAIL_RE.fullmatch(valor):
        raise ValidationError("Correo electrónico inválido")
    return valor


def validar_carnet(valor: str) -> str:
    valor = _normalizar(valor, "NFKC")
    if not CARNET_RE.fullmatch(valor):
        raise ValidationError("Carné inválido (formato esperado: 0000-00-000000)")
    return valor


def validar_nombre(valor: str, campo: str = "Nombre") -> str:
    valor = _normalizar(valor, "NFC")
    if not NOMBRE_RE.fullmatch(valor):
        raise ValidationError(f"{campo} inválido: solo letras, espacios, guion y apóstrofo (2-60)")
    return valor


def validar_calificacion(valor) -> Decimal:
    texto = _normalizar(str(valor), "NFKC")
    try:
        nota = Decimal(texto)
    except InvalidOperation as exc:
        raise ValidationError("La calificación debe ser numérica") from exc
    if not nota.is_finite() or nota < 0 or nota > 100:
        raise ValidationError("La calificación debe estar entre 0 y 100")
    if nota.as_tuple().exponent < -2:
        raise ValidationError("La calificación admite como máximo 2 decimales")
    return nota


def validar_busqueda(valor: str) -> str:
    # NFKC convierte variantes de ancho completo (＜ ＞ ＇) a su forma ASCII, de
    # modo que no puedan "esquivar" la lista de permitidos y transformarse después.
    valor = _normalizar(valor, "NFKC")
    if not BUSQUEDA_RE.fullmatch(valor):
        raise ValidationError("Parámetro de búsqueda inválido (1-50 caracteres permitidos)")
    return valor


def validar_dpi(valor: str) -> str:
    valor = _normalizar(valor, "NFKC").replace(" ", "")
    if not DPI_RE.fullmatch(valor):
        raise ValidationError("El DPI debe tener 13 dígitos")
    return valor


def validar_password_nueva(valor: str) -> str:
    # ASVS 2.1: mínimo 12 caracteres, máximo 128, se permiten todos los caracteres
    if not isinstance(valor, str) or not 12 <= len(valor) <= 128:
        raise ValidationError("La contraseña debe tener entre 12 y 128 caracteres")
    return valor


def validar_nombre_reporte(valor: str) -> str:
    valor = _normalizar(valor, "NFKC")
    if not NOMBRE_REPORTE_RE.fullmatch(valor):
        raise ValidationError("Nombre de reporte inválido: a-z, 0-9, guion y guion bajo (1-40)")
    return valor

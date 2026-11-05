"""
Fase II-E: Registro seguro (Secure Logging).

Diseño:
  * Formato JSON estructurado (una línea por evento): evita la inyección de
    registros (CRLF) porque los saltos de línea quedan escapados y facilita
    el envío a un SIEM.
  * Catálogo cerrado de eventos (EVENTOS): qué se registra está decidido de
    antemano, no se vuelcan solicitudes HTTP completas.
  * Minimización: se registran identificadores internos (user_id) y datos
    enmascarados; nunca contraseñas, tokens, cookies, claves ni cadenas de
    conexión.
  * Filtro de redacción como segunda barrera: si un desarrollador pasa por
    error un campo sensible, se sustituye por [REDACTADO] antes de escribirse.
"""
import json
import logging
import re
import uuid
from datetime import datetime, timezone

EVENTOS = {
    "auth.login.exito", "auth.login.fallo", "auth.cuenta.bloqueada", "auth.logout",
    "auth.registro", "expediente.consulta", "expediente.acceso.denegado",
    "calificacion.modificacion", "comentario.publicado", "reporte.generado",
    "admin.acceso", "error.interno", "validacion.rechazo",
}

CLAVES_SENSIBLES = re.compile(
    r"pass|pwd|contrase|token|secret|clave|key|authorization|cookie|session|"
    r"database_url|dsn|dpi|tarjeta|card",
    re.IGNORECASE,
)

PATRONES_SENSIBLES = [
    (re.compile(r"(?i)(password|contrase(ñ|n)a|pwd|passwd)\s*[=:]\s*\S+"), r"\1=[REDACTADO]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTADO]"),
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b"), "[TOKEN-REDACTADO]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[AWS-KEY-REDACTADA]"),
    (re.compile(r"(?i)\b[a-z]+://[^:\s/]+:[^@\s]+@"), "[URL-CON-CREDENCIAL]@"),
    (re.compile(r"\b\d{13}\b"), "[DPI-REDACTADO]"),
]


def redactar_texto(texto: str) -> str:
    for patron, reemplazo in PATRONES_SENSIBLES:
        texto = patron.sub(reemplazo, texto)
    return texto


def _redactar(valor, clave=""):
    if clave and CLAVES_SENSIBLES.search(clave):
        return "[REDACTADO]"
    if isinstance(valor, dict):
        return {k: _redactar(v, k) for k, v in valor.items()}
    if isinstance(valor, (list, tuple)):
        return [_redactar(v) for v in valor]
    if isinstance(valor, str):
        return redactar_texto(valor)[:300]
    return valor


def enmascarar_email(email: str) -> str:
    try:
        usuario, dominio = email.split("@", 1)
    except (ValueError, AttributeError):
        return "[email-invalido]"
    return f"{usuario[:1]}***@{dominio}"


def enmascarar_carnet(carnet: str) -> str:
    return f"****-**-{carnet[-3:]}" if carnet else ""


class FormateadorJSON(logging.Formatter):
    def format(self, record):
        base = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "nivel": record.levelname,
            "evento": getattr(record, "evento", "app.mensaje"),
            "mensaje": redactar_texto(record.getMessage()),
        }
        base.update(_redactar(getattr(record, "campos", {})))
        if record.exc_info:
            # La traza queda SOLO en el registro del servidor y también se redacta
            base["traza"] = redactar_texto(self.formatException(record.exc_info))[-2000:]
        return json.dumps(base, ensure_ascii=False)


def configurar_logger(ruta_archivo: str | None = None) -> logging.Logger:
    logger = logging.getLogger("portal.seguridad")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    manejador = logging.FileHandler(ruta_archivo, encoding="utf-8") if ruta_archivo else logging.StreamHandler()
    manejador.setFormatter(FormateadorJSON())
    logger.addHandler(manejador)
    return logger


def registrar(evento: str, nivel: int = logging.INFO, mensaje: str = "", **campos):
    if evento not in EVENTOS:
        raise ValueError(f"Evento no catalogado: {evento}")
    logging.getLogger("portal.seguridad").log(
        nivel, mensaje or evento, extra={"evento": evento, "campos": campos}
    )


def nuevo_id_incidente() -> str:
    return uuid.uuid4().hex[:12]

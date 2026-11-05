# ANTIPATRÓN (Fase II-E): registros que exponen información sensible. NO USAR.
import logging

logging.basicConfig(filename="app.log", level=logging.DEBUG)
log = logging.getLogger(__name__)


def login(request, usuario, db_url):
    # 1) contraseña en claro, 2) cookie de sesión, 3) cadena de conexión con credencial,
    # 4) correo completo y DPI, 5) texto libre del usuario sin escapar (inyección de líneas)
    log.info(f"Login intento email={request.form['email']} password={request.form['password']}")
    log.debug(f"Headers: {dict(request.headers)}  Cookies: {request.cookies}")
    log.debug(f"Conectando a {db_url}")
    log.info(f"Usuario {usuario.email} DPI {usuario.dpi} consultó su expediente")

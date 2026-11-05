"""Arranca el portal SOLO por HTTPS (TLS 1.2 como mínimo)."""
import ssl

from dotenv import load_dotenv
from werkzeug.serving import WSGIRequestHandler

load_dotenv()
from app import create_app  # noqa: E402


class ManejadorSinVersion(WSGIRequestHandler):
    """Oculta la versión del servidor (hallazgo residual: divulgación de información).

    Por defecto el servidor de desarrollo envía «Server: Werkzeug/x.y Python/x.y».
    En producción la cabecera la controla Nginx con «server_tokens off».
    """

    def version_string(self) -> str:
        return "Portal"


def contexto_tls(cert="certs/servidor.crt", clave="certs/servidor.key") -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2     # se rechazan SSLv3, TLS 1.0 y 1.1
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")   # solo suites AEAD con secreto perfecto hacia adelante
    ctx.options |= ssl.OP_NO_COMPRESSION             # mitiga CRIME
    ctx.load_cert_chain(cert, clave)
    return ctx


if __name__ == "__main__":
    app = create_app()
    app.run(host="127.0.0.1", port=8443, ssl_context=contexto_tls(), debug=False,
            request_handler=ManejadorSinVersion)

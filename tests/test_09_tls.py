"""Fase II-B: protección en tránsito — el portal solo atiende por TLS >= 1.2."""
import re
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from werkzeug.serving import make_server

from tests.base import RAIZ, PruebaPortal
from run import contexto_tls


class TestTLS(PruebaPortal):
    def setUp(self):
        super().setUp()
        certs = Path(self.tmp) / "certs"
        certs.mkdir()
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "1",
                        "-nodes", "-keyout", certs / "k.pem", "-out", certs / "c.pem",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True)
        self.cert = certs / "c.pem"
        self.server = make_server("127.0.0.1", 0, self.app, ssl_context=contexto_tls(certs / "c.pem", certs / "k.pem"))
        self.puerto = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def tearDown(self):
        self.server.shutdown()
        super().tearDown()

    def _cliente(self, **ajustes):
        ctx = ssl.create_default_context(cafile=str(self.cert))
        for k, v in ajustes.items():
            setattr(ctx, k, v)
        return ctx

    def test_https_negocia_tls_moderno(self):
        with socket.create_connection(("127.0.0.1", self.puerto)) as s:
            with self._cliente().wrap_socket(s, server_hostname="localhost") as tls:
                version, cifrado = tls.version(), tls.cipher()
                tls.sendall(b"GET /login HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                respuesta = b""
                while chunk := tls.recv(4096):
                    respuesta += chunk
        cabeceras = respuesta.split(b"\r\n\r\n")[0].decode()
        print(f"\n[SEGURO] versión negociada: {version}; suite: {cifrado[0]}")
        visibles = [re.sub(r"session=[^;]+", "session=<valor firmado>", l) for l in cabeceras.splitlines()
                    if l.lower().startswith(("http/", "strict", "set-cookie"))]
        print("[SEGURO]", visibles)
        self.assertIn(version, ("TLSv1.2", "TLSv1.3"))
        self.assertIn("Strict-Transport-Security: max-age=31536000", cabeceras)
        self.assertRegex(cabeceras, r"Set-Cookie: session=.*Secure.*HttpOnly")

    def test_rechaza_tls_1_1(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(str(self.cert))
        import warnings
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        try:
            ctx.set_ciphers("ALL:@SECLEVEL=0")
        except ssl.SSLError:
            pass
        with self.assertRaises((ssl.SSLError, ConnectionResetError, OSError)) as e:
            with socket.create_connection(("127.0.0.1", self.puerto)) as s:
                with ctx.wrap_socket(s, server_hostname="localhost"):
                    pass
        print("\n[SEGURO] cliente TLS 1.1 rechazado:", type(e.exception).__name__, str(e.exception)[:90])

    def test_texto_plano_no_es_atendido(self):
        with socket.create_connection(("127.0.0.1", self.puerto), timeout=5) as s:
            s.sendall(b"GET /login HTTP/1.1\r\nHost: localhost\r\n\r\n")
            try:
                datos = s.recv(1024)
            except (ConnectionResetError, socket.timeout):
                datos = b""
        print("\n[SEGURO] respuesta a HTTP sin TLS:", datos[:40] or "conexión cerrada")
        self.assertNotIn(b"200 OK", datos)

    def test_certificado_no_confiable_es_rechazado(self):
        ctx = ssl.create_default_context()        # sin la CA del laboratorio
        with self.assertRaises(ssl.SSLCertVerificationError):
            with socket.create_connection(("127.0.0.1", self.puerto)) as s:
                with ctx.wrap_socket(s, server_hostname="localhost"):
                    pass


if __name__ == "__main__":
    unittest.main(verbosity=2)

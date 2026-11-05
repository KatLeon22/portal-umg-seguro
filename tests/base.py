"""Utilidades comunes de las pruebas: entorno aislado con secretos de prueba."""
import base64
import os
import re
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))

from app import create_app  # noqa: E402
from app.config import cargar_secretos  # noqa: E402
from scripts.init_db import inicializar  # noqa: E402


def entorno_prueba(tmp: Path) -> dict:
    """Secretos aleatorios generados en cada ejecución: nada fijo en el repositorio."""
    return {
        "FLASK_SECRET_KEY": secrets.token_urlsafe(48),
        "DATA_ENC_KEYS": "v1:" + base64.b64encode(os.urandom(32)).decode(),
        "BLIND_INDEX_KEY": base64.b64encode(os.urandom(32)).decode(),
        "DATABASE_URL": f"sqlite:///{tmp / 'portal.db'}",
        "REPORT_DIR": str(tmp / "reportes"),
    }


class PruebaPortal(unittest.TestCase):
    LAB = True

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.entorno = entorno_prueba(self.tmp)
        self.ruta_log = str(self.tmp / "seguridad.log")
        inicializar(cargar_secretos(self.entorno))
        import logging, warnings
        warnings.simplefilter("ignore", ResourceWarning)
        self.app = create_app(self.entorno, lab_mode=self.LAB, ruta_log=self.ruta_log)
        self.app.testing = False  # usar los manejadores de error reales
        self.app.logger.setLevel("ERROR")  # silencia el aviso de LAB_MODE en la salida
        self.cliente = self.app.test_client()

    def tearDown(self):
        self._tmp.cleanup()

    # --- ayudantes HTTP (todas las solicitudes por https para la cookie Secure)
    def get(self, ruta, **kw):
        return self.cliente.get(ruta, base_url="https://localhost", **kw)

    def post(self, ruta, data=None, **kw):
        data = dict(data or {})
        if not ruta.startswith("/lab/"):
            data.setdefault("csrf_token", self._csrf())
        return self.cliente.post(ruta, data=data, base_url="https://localhost", **kw)

    def _csrf(self):
        html = self.get("/login").get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def login(self, email, password):
        return self.post("/login", {"email": email, "password": password})

    def leer_log(self):
        for h in __import__("logging").getLogger("portal.seguridad").handlers:
            h.flush()
        return Path(self.ruta_log).read_text(encoding="utf-8") if Path(self.ruta_log).exists() else ""

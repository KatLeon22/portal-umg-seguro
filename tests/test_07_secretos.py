"""Fase II-C: gestión de secretos fuera del código."""
import re
import unittest

from tests.base import RAIZ, PruebaPortal
from app import create_app
from app.config import ConfigError, cargar_secretos

PATRONES = [
    re.compile(r"""(?i)(password|passwd|secret|token|api_?key)\s*=\s*["'][^"'{}]{8,}["']"""),
    re.compile(r"[a-z]+://[^:\s/]+:[^@\s]+@"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
]
EXCLUIDOS = {"lab_antipatrones"}


class TestSecretos(PruebaPortal):
    def test_app_obtiene_credenciales_de_fuente_externa(self):
        self.assertEqual(self.app.config["DATABASE_URL"], self.entorno["DATABASE_URL"])
        self.assertEqual(self.app.config["SECRET_KEY"], self.entorno["FLASK_SECRET_KEY"])
        print("\n[SEGURO] DATABASE_URL leída del entorno inyectado:", self.app.config["DATABASE_URL"][:18] + "...")

    def test_sin_secretos_no_arranca(self):
        incompleto = dict(self.entorno)
        del incompleto["DATA_ENC_KEYS"]
        with self.assertRaises(ConfigError) as ctx:
            create_app(incompleto)
        print("\n[SEGURO] error de arranque:", ctx.exception)
        self.assertNotIn(self.entorno["FLASK_SECRET_KEY"], str(ctx.exception))

    def test_clave_debil_rechazada(self):
        debil = dict(self.entorno, FLASK_SECRET_KEY="portal-umg-2026")
        with self.assertRaises(ConfigError):
            cargar_secretos(debil)

    def test_codigo_fuente_sin_credenciales(self):
        hallazgos = []
        for ruta in list((RAIZ / "app").rglob("*.py")) + [RAIZ / "run.py"]:
            if EXCLUIDOS & set(ruta.parts):
                continue
            for n, linea in enumerate(ruta.read_text(encoding="utf-8").splitlines(), 1):
                if any(p.search(linea) for p in PATRONES):
                    hallazgos.append(f"{ruta.relative_to(RAIZ)}:{n}")
        print("\n[SEGURO] credenciales encontradas en app/:", hallazgos or "ninguna")
        self.assertEqual(hallazgos, [])

    def test_env_ignorado_por_git(self):
        gitignore = (RAIZ / ".gitignore").read_text()
        for patron in (".env", "certs/", "instance/", "*.key"):
            self.assertIn(patron, gitignore)


if __name__ == "__main__":
    unittest.main(verbosity=2)

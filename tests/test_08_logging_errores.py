"""Fase II-E: registro seguro y manejo de errores."""
import json
import logging
import unittest

from tests.base import PruebaPortal
from app.secure_logging import registrar

PASSWORD_FALLIDA = "MiClaveSecreta#999"


class TestLogging(PruebaPortal):
    def eventos(self):
        return [json.loads(l) for l in self.leer_log().splitlines() if l.strip()]

    def test_login_fallido_sin_password(self):
        self.login("docente@portal.test", PASSWORD_FALLIDA)
        contenido = self.leer_log()
        evento = [e for e in self.eventos() if e["evento"] == "auth.login.fallo"][-1]
        print("\n[SEGURO] registro generado:", json.dumps(evento, ensure_ascii=False))
        self.assertNotIn(PASSWORD_FALLIDA, contenido)
        self.assertEqual(evento["email"], "d***@portal.test")
        self.assertEqual(evento["motivo"], "credenciales_invalidas")

    def test_contraste_log_inseguro(self):
        """El endpoint de laboratorio reproduce el registro inseguro original."""
        self.post("/lab/login", {"email": "docente@portal.test", "password": PASSWORD_FALLIDA})
        for h in logging.getLogger("portal.inseguro").handlers:
            h.flush()
        inseguro = (self.tmp / "inseguro.log").read_text(encoding="utf-8")
        print("\n[INSEGURO] línea de log:", inseguro.strip().splitlines()[-1][:170])
        self.assertIn(PASSWORD_FALLIDA, inseguro)

    def test_eventos_de_negocio(self):
        self.login("admin@portal.test", "Admin#Laboratorio2026")
        self.get("/expediente/5190-25-1001")
        self.get("/admin")
        tipos = {e["evento"] for e in self.eventos()}
        print("\n[SEGURO] eventos registrados:", sorted(tipos))
        self.assertTrue({"auth.login.exito", "expediente.consulta", "admin.acceso"} <= tipos)
        consulta = [e for e in self.eventos() if e["evento"] == "expediente.consulta"][0]
        self.assertEqual(consulta["carnet"], "****-**-001")

    def test_modificacion_registrada(self):
        self.login("docente@portal.test", "Docente#Laboratorio2026")
        self.post("/calificaciones/1", {"nota": "95"})
        mod = [e for e in self.eventos() if e["evento"] == "calificacion.modificacion"][0]
        self.assertEqual((mod["valor_anterior"], mod["valor_nuevo"]), ("85", "95"))

    def test_redaccion_defensiva(self):
        registrar("error.interno", logging.ERROR, mensaje="password=Hola123 Bearer abc.def.ghi",
                  token="ghp_FAKE", clave_api="x", dpi="1000000000101", nota="2610000000000")
        ultimo = self.eventos()[-1]
        print("\n[SEGURO] evento redactado:", json.dumps(ultimo, ensure_ascii=False))
        texto = json.dumps(ultimo)
        for fuga in ("Hola123", "abc.def.ghi", "ghp_FAKE", "1000000000101", "2610000000000"):
            self.assertNotIn(fuga, texto)

    def test_inyeccion_de_registros(self):
        self.login("docente@portal.test\n{\"evento\":\"auth.login.exito\"}", "x")
        for linea in self.leer_log().splitlines():
            json.loads(linea)   # cada línea sigue siendo UN evento JSON válido

    def test_error_interno_no_expone_detalles(self):
        self.login("admin@portal.test", "Admin#Laboratorio2026")
        r = self.get("/diagnostico/error")
        html = r.get_data(as_text=True)
        cuerpo = " ".join(html.split())
        print("\n[SEGURO] respuesta al usuario (HTTP %d): %s" % (r.status_code, cuerpo[cuerpo.find("<h1>"):cuerpo.find("</main>")]))
        self.assertEqual(r.status_code, 500)
        for fuga in ("Traceback", "sqlite:///", "ghp_", "RuntimeError", self.entorno["DATABASE_URL"]):
            self.assertNotIn(fuga, html)
        error = [e for e in self.eventos() if e["evento"] == "error.interno"][-1]
        self.assertIn(error["incidente"], html)              # correlación usuario <-> servidor
        self.assertNotIn("A1b2C3d4E5f6G7h8I9j0", json.dumps(error))
        print("[SEGURO] traza en servidor (redactada):", error["traza"].splitlines()[-1])


if __name__ == "__main__":
    unittest.main(verbosity=2)

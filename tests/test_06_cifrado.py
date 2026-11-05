"""Fase II-B: cifrado de datos en reposo (AES-256-GCM) y manejo de claves."""
import base64
import os
import unittest

from tests.base import PruebaPortal
from app.db import conectar
from app.security_crypto import CifradorDatos


class TestCifrado(PruebaPortal):
    def cifrador(self):
        return self.app.extensions["cifrador"]

    def test_bd_no_contiene_dpi_en_claro(self):
        bruto = open(self.entorno["DATABASE_URL"].replace("sqlite:///", ""), "rb").read()
        self.assertNotIn(b"1000000000101", bruto)
        self.assertNotIn(b"5550-0101", bruto)
        fila = conectar(self.entorno["DATABASE_URL"]).execute(
            "SELECT carnet, dpi_cifrado, dpi_indice FROM estudiantes LIMIT 1").fetchone()
        print("\n[SEGURO] dpi_cifrado:", fila["dpi_cifrado"], "\n[SEGURO] dpi_indice:", fila["dpi_indice"])
        self.assertTrue(fila["dpi_cifrado"].startswith("v1:"))

    def test_ida_y_vuelta_y_nonce_unico(self):
        c = self.cifrador()
        a, b = c.cifrar("1000000000101", "estudiante:X:dpi"), c.cifrar("1000000000101", "estudiante:X:dpi")
        self.assertNotEqual(a, b)                                # nonce aleatorio distinto
        self.assertEqual(c.descifrar(a, "estudiante:X:dpi"), "1000000000101")

    def test_alteracion_detectada(self):
        c = self.cifrador()
        token = c.cifrar("1000000000101", "estudiante:X:dpi")
        kid, b64 = token.split(":", 1)
        bruto = bytearray(base64.b64decode(b64))
        bruto[15] ^= 0x01                                         # un solo bit alterado
        with self.assertRaises(ValueError):
            c.descifrar(kid + ":" + base64.b64encode(bytes(bruto)).decode(), "estudiante:X:dpi")

    def test_aad_impide_mover_dato_a_otro_registro(self):
        c = self.cifrador()
        token = c.cifrar("1000000000101", "estudiante:5190-25-1001:dpi")
        with self.assertRaises(ValueError):
            c.descifrar(token, "estudiante:5190-25-1002:dpi")

    def test_rotacion_de_claves(self):
        v1, v2, idx = os.urandom(32), os.urandom(32), os.urandom(32)
        viejo = CifradorDatos({"v1": v1}, "v1", idx)
        token_v1 = viejo.cifrar("dato", "ctx")
        nuevo = CifradorDatos({"v2": v2, "v1": v1}, "v2", idx)  # v2 activa, v1 solo descifra
        self.assertEqual(nuevo.descifrar(token_v1, "ctx"), "dato")
        self.assertTrue(nuevo.cifrar("dato", "ctx").startswith("v2:"))
        revocado = CifradorDatos({"v2": v2}, "v2", idx)          # v1 retirada tras re-cifrar
        with self.assertRaises(ValueError):
            revocado.descifrar(token_v1, "ctx")

    def test_busqueda_por_indice_ciego(self):
        c = self.cifrador()
        fila = conectar(self.entorno["DATABASE_URL"]).execute(
            "SELECT carnet FROM estudiantes WHERE dpi_indice = ?", (c.indice_ciego("1000000000303"),)).fetchone()
        self.assertEqual(fila["carnet"], "5190-25-1003")

    def test_expediente_muestra_dpi_enmascarado(self):
        self.login("ana.lopez@portal.test", "Estudiante#Lab2026")
        html = self.get("/expediente/5190-25-1001").get_data(as_text=True)
        self.assertIn("*********0101", html)
        self.assertNotIn("1000000000101", html)
        self.assertEqual(self.get("/expediente/5190-25-1002").status_code, 403)   # sin IDOR


if __name__ == "__main__":
    unittest.main(verbosity=2)

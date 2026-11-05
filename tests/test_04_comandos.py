"""Fase I-D: Inyección de comandos en la compresión de reportes."""
import ast
import tarfile
import unittest
from pathlib import Path

from tests.base import RAIZ, PruebaPortal
from app.reports import comprimir_reporte_con_binario, comprimir_reporte_seguro, escribir_csv
from app.validation import ValidationError


class TestComandos(PruebaPortal):
    def test_vulnerable_ejecuta_comando_inyectado(self):
        marca = self.tmp / "PWNED.txt"
        r = self.get("/lab/reporte", query_string={"nombre": f"base; id > {marca}; echo"})
        print("\n[VULNERABLE] comando:", r.get_json()["comando_ejecutado"])
        print("[VULNERABLE] archivo creado por el atacante:", marca.exists(), "->", marca.read_text().strip() if marca.exists() else "")
        self.assertTrue(marca.exists())

    def test_seguro_rechaza_metacaracteres(self):
        directorio = self.tmp / "rep"
        directorio.mkdir()
        marca = self.tmp / "PWNED2.txt"
        for ataque in [f"base; id > {marca}", "base$(id)", "../../etc/passwd", "a|b", "-rf"]:
            with self.assertRaises((ValidationError, ValueError), msg=ataque):
                comprimir_reporte_seguro(directorio, ataque)
        self.assertFalse(marca.exists())

    def test_seguro_flujo_valido_tarfile_y_binario(self):
        directorio = self.tmp / "rep"
        directorio.mkdir()
        escribir_csv(directorio, "notas_2026", [{"carnet": "5190-25-1", "nombre": "=CMD()", "apellido": "X", "curso": "SA", "nota": "90"}])
        for funcion in (comprimir_reporte_seguro, comprimir_reporte_con_binario):
            destino = funcion(directorio, "notas_2026")
            with tarfile.open(destino) as t:
                self.assertEqual(t.getnames(), ["notas_2026.csv"])
        self.assertIn("'=CMD()", (directorio / "notas_2026.csv").read_text())  # CSV injection neutralizada

    def test_endpoint_seguro_admin(self):
        self.login("admin@portal.test", "Admin#Laboratorio2026")
        r = self.post("/reportes", {"nombre": "x; touch /tmp/pwn"})
        self.assertEqual(r.status_code, 400)
        r = self.post("/reportes", {"nombre": "reporte_notas"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["Content-Type"], "application/gzip")

    def test_codigo_seguro_no_usa_shell(self):
        """Análisis estático: ninguna llamada a subprocess en el módulo seguro usa shell=True."""
        arbol = ast.parse((RAIZ / "app/reports.py").read_text())
        for nodo in ast.walk(arbol):
            if isinstance(nodo, ast.Call) and getattr(nodo.func, "attr", "") == "run":
                kw = {k.arg: k.value for k in nodo.keywords}
                self.assertIs(kw["shell"].value, False)
                self.assertIsInstance(nodo.args[0], ast.List)   # lista de argumentos


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Fase I-B: SQL Injection — versión vulnerable vs. consulta parametrizada."""
import sqlite3
import unittest

from tests.base import PruebaPortal
from app.db import conectar
from app.lab_vulnerable import buscar_vulnerable

PAYLOAD_TAUTOLOGIA = "zzz' OR apellido LIKE '"
PAYLOAD_UNION = "zzz' UNION SELECT email, password_sha256, 'x' FROM usuarios_legado --"


class TestSQLInjection(PruebaPortal):
    def test_vulnerable_tautologia_devuelve_todo(self):
        db = conectar(self.entorno["DATABASE_URL"])
        sql, filas = buscar_vulnerable(db, PAYLOAD_TAUTOLOGIA)
        print("\n[VULNERABLE] SQL final:", sql, "\n[VULNERABLE] filas:", len(filas))
        self.assertEqual(len(filas), 5)          # 'zzz' no existe y aun así devuelve los 5

    def test_vulnerable_union_extrae_hashes(self):
        db = conectar(self.entorno["DATABASE_URL"])
        sql, filas = buscar_vulnerable(db, PAYLOAD_UNION)
        print("\n[VULNERABLE] SQL final:", sql)
        for f in filas:
            print("[VULNERABLE] fila extraída:", tuple(f))
        self.assertTrue(any(len(f[1]) == 64 for f in filas))  # hashes SHA-256 expuestos

    def test_vulnerable_apellido_valido_rompe_sql(self):
        db = conectar(self.entorno["DATABASE_URL"])
        with self.assertRaises(sqlite3.OperationalError):
            buscar_vulnerable(db, "O'Brien")

    def test_vulnerable_login_bypass(self):
        r = self.post("/lab/login", {"email": "admin@portal.test' --", "password": "cualquiera"})
        print("\n[VULNERABLE] respuesta login:", r.get_json())
        self.assertTrue(r.get_json()["autenticado"])

    def test_seguro_payload_no_altera_estructura(self):
        self.login("docente@portal.test", "Docente#Laboratorio2026")
        for payload in [PAYLOAD_TAUTOLOGIA, "x' OR nombre LIKE '"]:
            r = self.get("/estudiantes/buscar", query_string={"q": payload})
            html = r.get_data(as_text=True)
            print(f"\n[SEGURO] q={payload!r} -> HTTP {r.status_code}, 'Resultados: 0' en HTML: {'Resultados: 0' in html}")
            self.assertEqual(r.status_code, 200)       # pasa la validación (contiene ' y espacios)
            self.assertIn("Resultados: 0", html)       # tratado como texto literal

    def test_seguro_apellido_con_apostrofo_funciona(self):
        self.login("docente@portal.test", "Docente#Laboratorio2026")
        html = self.get("/estudiantes/buscar", query_string={"q": "O'Brien"}).get_data(as_text=True)
        self.assertIn("Resultados: 1", html)
        self.assertIn("O&#39;Brien", html)             # además, salida codificada

    def test_seguro_comodines_like_escapados(self):
        self.login("docente@portal.test", "Docente#Laboratorio2026")
        html = self.get("/estudiantes/buscar", query_string={"q": "%"}).get_data(as_text=True)
        self.assertIn("Resultados: 0", html)

    def test_parametro_es_dato_no_codigo(self):
        """Demostración directa en el motor: el plan de ejecución no cambia."""
        db = conectar(self.entorno["DATABASE_URL"])
        sql = "SELECT carnet FROM estudiantes WHERE apellido = ?"
        plan_normal = db.execute("EXPLAIN " + sql, ("López",)).fetchall()
        plan_ataque = db.execute("EXPLAIN " + sql, (PAYLOAD_TAUTOLOGIA,)).fetchall()
        self.assertEqual([tuple(x)[1] for x in plan_normal], [tuple(x)[1] for x in plan_ataque])
        self.assertEqual(db.execute(sql, (PAYLOAD_TAUTOLOGIA,)).fetchall(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

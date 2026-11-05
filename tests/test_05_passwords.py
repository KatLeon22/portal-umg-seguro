"""Fase II-A: almacenamiento seguro de contraseñas (scrypt con sal)."""
import hashlib
import time
import unittest

from tests.base import PruebaPortal
from app.db import conectar
from app.security_crypto import hash_password, verificar_password


class TestPasswords(PruebaPortal):
    def test_hash_almacenado_es_kdf_con_sal(self):
        db = conectar(self.entorno["DATABASE_URL"])
        fila = db.execute("SELECT email, password_hash FROM usuarios WHERE rol='docente'").fetchone()
        metodo, sal, derivado = fila["password_hash"].split("$")
        print(f"\n[SEGURO] registro en BD: {fila['email']} -> {metodo}${sal}${derivado[:24]}...")
        self.assertEqual(metodo, "scrypt:131072:8:1")
        self.assertEqual(len(sal), 16)
        self.assertEqual(len(derivado), 128)              # 64 bytes en hexadecimal
        self.assertNotIn("Docente#Laboratorio2026", fila["password_hash"])

    def test_misma_password_distinta_sal_distinto_hash(self):
        h1, h2 = hash_password("Clave#Compartida1"), hash_password("Clave#Compartida1")
        print("\n[SEGURO] hash 1:", h1[:60], "...\n[SEGURO] hash 2:", h2[:60], "...")
        self.assertNotEqual(h1, h2)
        self.assertTrue(verificar_password(h1, "Clave#Compartida1"))
        self.assertTrue(verificar_password(h2, "Clave#Compartida1"))

    def test_sha256_simple_es_determinista(self):
        db = conectar(self.entorno["DATABASE_URL"])
        a = hashlib.sha256(b"Clave#Compartida1").hexdigest()
        b = hashlib.sha256(b"Clave#Compartida1").hexdigest()
        self.assertEqual(a, b)   # mismo hash para usuarios distintos -> tablas precalculadas
        legado = db.execute("SELECT password_sha256 FROM usuarios_legado LIMIT 1").fetchone()[0]
        print("\n[INSEGURO] SHA-256 sin sal en tabla legado:", legado)

    def test_costo_comparado(self):
        n = 200_000
        t0 = time.perf_counter()
        for i in range(n):
            hashlib.sha256(b"intento%d" % i).digest()
        sha_por_s = n / (time.perf_counter() - t0)
        t0 = time.perf_counter()
        hash_password("intento-unico")
        scrypt_s = time.perf_counter() - t0
        print(f"\n[MEDICIÓN] SHA-256: ~{sha_por_s:,.0f} intentos/s en 1 núcleo de CPU")
        print(f"[MEDICIÓN] scrypt N=2^17: {scrypt_s*1000:.0f} ms por intento (~{1/scrypt_s:.1f} intentos/s) y 128 MiB de RAM")
        self.assertGreater(sha_por_s * scrypt_s, 10_000)

    def test_login_correcto_e_incorrecto(self):
        malo = self.login("docente@portal.test", "ClaveEquivocada123")
        self.assertEqual(malo.status_code, 401)
        self.assertIn("Credenciales inválidas", malo.get_data(as_text=True))
        inexistente = self.login("nadie@portal.test", "ClaveEquivocada123")
        self.assertEqual(inexistente.status_code, 401)
        self.assertEqual(malo.get_data(as_text=True).count("Credenciales"),
                         inexistente.get_data(as_text=True).count("Credenciales"))
        bueno = self.login("docente@portal.test", "Docente#Laboratorio2026")
        print(f"\n[SEGURO] contraseña incorrecta -> HTTP {malo.status_code}; correcta -> HTTP {bueno.status_code} (redirección)")
        self.assertEqual(bueno.status_code, 302)

    def test_bloqueo_tras_5_fallos(self):
        for _ in range(5):
            self.login("ana.lopez@portal.test", "IntentoFallido00")
        r = self.login("ana.lopez@portal.test", "Estudiante#Lab2026")   # correcta pero bloqueada
        self.assertEqual(r.status_code, 401)
        self.assertIn("auth.cuenta.bloqueada", self.leer_log())


if __name__ == "__main__":
    unittest.main(verbosity=2)

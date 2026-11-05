"""Fase I-A: validación de entradas."""
import unittest
from decimal import Decimal

from tests.base import RAIZ  # noqa: F401  (configura sys.path)
from app.validation import (ValidationError, validar_busqueda, validar_calificacion,
                            validar_carnet, validar_email, validar_nombre)


class TestValidacion(unittest.TestCase):
    def test_email(self):
        self.assertEqual(validar_email("  Ana.Lopez@Portal.TEST "), "ana.lopez@portal.test")
        for malo in ["sin-arroba", "a@b", "x@y.c", "<script>@x.com", "a@b.com\nBcc:x@y.com"]:
            with self.assertRaises(ValidationError, msg=malo):
                validar_email(malo)

    def test_carnet(self):
        self.assertEqual(validar_carnet("5190-25-1001"), "5190-25-1001")
        for malo in ["5190-25", "5190-25-1001' OR '1'='1", "../../etc/passwd", "５１９０-２５-１"]:
            if malo.startswith("５"):
                # NFKC convierte los dígitos de ancho completo y el valor resultante es válido
                self.assertEqual(validar_carnet(malo), "5190-25-1")
                continue
            with self.assertRaises(ValidationError, msg=malo):
                validar_carnet(malo)

    def test_nombres(self):
        self.assertEqual(validar_nombre("María José"), "María José")
        self.assertEqual(validar_nombre("O'Brien"), "O'Brien")   # válido... ¡y contiene '
        for malo in ["<b>Ana</b>", "Ana; DROP TABLE", "A", "Ana\x00", "x" * 61]:
            with self.assertRaises(ValidationError, msg=malo):
                validar_nombre(malo)

    def test_calificaciones(self):
        self.assertEqual(validar_calificacion("85.50"), Decimal("85.50"))
        for malo in ["-1", "100.01", "NaN", "Infinity", "1e3", "90.123", "abc"]:
            with self.assertRaises(ValidationError, msg=malo):
                validar_calificacion(malo)

    def test_busqueda_normaliza_antes_de_validar(self):
        self.assertEqual(validar_busqueda("  Pérez   López "), "Pérez López")
        # Ancho completo: NFKC lo convierte en < > y la lista de permitidos lo rechaza
        for malo in ["＜script＞", "<script>", "a" * 51, "x%' --", "1;ls"]:
            with self.assertRaises(ValidationError, msg=malo):
                validar_busqueda(malo)

    def test_valido_no_significa_seguro(self):
        """Un dato VÁLIDO puede romper un intérprete si se concatena."""
        apellido = validar_nombre("O'Brien")
        sql_concatenado = "SELECT * FROM estudiantes WHERE apellido = '" + apellido + "'"
        self.assertEqual(sql_concatenado.count("'"), 3)  # comillas desbalanceadas
        busqueda = validar_busqueda("' OR apellido LIKE '")
        self.assertIn("'", busqueda)  # también pasa la allowlist de búsqueda


if __name__ == "__main__":
    unittest.main(verbosity=2)

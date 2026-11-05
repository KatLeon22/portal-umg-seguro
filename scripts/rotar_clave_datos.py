"""Rotación de la clave de cifrado de datos (Fase II-B).

Procedimiento:
  1. Generar la nueva clave y anteponerla en DATA_ENC_KEYS:  v2:<nueva>,v1:<anterior>
     (v2 pasa a ser la activa; v1 queda solo para descifrar).
  2. Ejecutar este script: re-cifra cada campo con v2 dentro de una transacción.
  3. Verificar que ningún registro conserve el prefijo v1:  (el script lo comprueba).
  4. Retirar v1 de DATA_ENC_KEYS / Vault y destruir esa versión.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dotenv import load_dotenv  # noqa: E402

load_dotenv()
from app.config import cargar_secretos  # noqa: E402
from app.db import conectar  # noqa: E402
from app.security_crypto import CifradorDatos  # noqa: E402

CAMPOS = {"dpi_cifrado": "dpi", "telefono_cifrado": "telefono"}


def rotar():
    s = cargar_secretos()
    cif = CifradorDatos(s["DATA_ENC_KEYS"], s["DATA_ENC_ACTIVE_KID"], s["BLIND_INDEX_KEY"])
    db = conectar(s["DATABASE_URL"])
    actualizados = 0
    with db:  # transacción: todo o nada
        for fila in db.execute("SELECT id, carnet, dpi_cifrado, telefono_cifrado FROM estudiantes").fetchall():
            for columna, etiqueta in CAMPOS.items():
                token = fila[columna]
                if token and cif.kid_de(token) != s["DATA_ENC_ACTIVE_KID"]:
                    ctx = f"estudiante:{fila['carnet']}:{etiqueta}"
                    nuevo = cif.cifrar(cif.descifrar(token, ctx), ctx)
                    db.execute(f"UPDATE estudiantes SET {columna} = ? WHERE id = ?", (nuevo, fila["id"]))
                    actualizados += 1
    pendientes = db.execute(
        "SELECT COUNT(*) FROM estudiantes WHERE dpi_cifrado NOT LIKE ? OR telefono_cifrado NOT LIKE ?",
        (s["DATA_ENC_ACTIVE_KID"] + ":%",) * 2).fetchone()[0]
    print(f"Campos re-cifrados: {actualizados}. Registros con clave anterior: {pendientes}.")
    return pendientes


if __name__ == "__main__":
    raise SystemExit(1 if rotar() else 0)

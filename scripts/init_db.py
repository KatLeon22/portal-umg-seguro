"""Crea la base de datos del laboratorio con datos 100 % FICTICIOS."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dotenv import load_dotenv  # noqa: E402

load_dotenv()
from app.config import cargar_secretos  # noqa: E402
from app.db import conectar, crear_esquema, ruta_sqlite  # noqa: E402
from app.security_crypto import CifradorDatos, hash_password, sha256_inseguro  # noqa: E402

USUARIOS = [  # contraseñas de laboratorio (ficticias, documentadas en README)
    ("admin@portal.test", "Admin#Laboratorio2026", "admin", None),
    ("docente@portal.test", "Docente#Laboratorio2026", "docente", None),
    ("ana.lopez@portal.test", "Estudiante#Lab2026", "estudiante", "5190-25-1001"),
]
ESTUDIANTES = [  # carné, nombre, apellido, correo, DPI ficticio, teléfono ficticio
    ("5190-25-1001", "Ana", "López", "ana.lopez@portal.test", "1000000000101", "5550-0101"),
    ("5190-25-1002", "Bruno", "Martínez", "bruno.m@portal.test", "1000000000202", "5550-0202"),
    ("5190-25-1003", "Carla", "O'Brien", "carla.ob@portal.test", "1000000000303", "5550-0303"),
    ("5190-25-1004", "Diego", "Pérez", "diego.p@portal.test", "1000000000404", "5550-0404"),
    ("5190-25-1005", "Elena", "Ramírez", "elena.r@portal.test", "1000000000505", "5550-0505"),
]


def inicializar(secretos=None):
    secretos = secretos or cargar_secretos()
    ruta = Path(ruta_sqlite(secretos["DATABASE_URL"]))
    ruta.parent.mkdir(parents=True, exist_ok=True)
    if ruta.exists():
        ruta.unlink()
    cif = CifradorDatos(secretos["DATA_ENC_KEYS"], secretos["DATA_ENC_ACTIVE_KID"], secretos["BLIND_INDEX_KEY"])
    db = conectar(secretos["DATABASE_URL"])
    crear_esquema(db)
    for email, pwd, rol, carnet in USUARIOS:
        db.execute("INSERT INTO usuarios (email, password_hash, rol, carnet) VALUES (?,?,?,?)",
                   (email, hash_password(pwd), rol, carnet))
        db.execute("INSERT INTO usuarios_legado (email, password_sha256) VALUES (?,?)",
                   (email, sha256_inseguro(pwd)))
    for carnet, nom, ape, email, dpi, tel in ESTUDIANTES:
        cur = db.execute(
            "INSERT INTO estudiantes (carnet,nombre,apellido,email,dpi_cifrado,dpi_indice,telefono_cifrado) "
            "VALUES (?,?,?,?,?,?,?)",
            (carnet, nom, ape, email,
             cif.cifrar(dpi, f"estudiante:{carnet}:dpi"), cif.indice_ciego(dpi),
             cif.cifrar(tel, f"estudiante:{carnet}:telefono")))
        for curso, nota in (("Seguridad en Aplicaciones", "85"), ("Estándares de Seguridad", "90")):
            db.execute("INSERT INTO calificaciones (estudiante_id, curso, nota) VALUES (?,?,?)",
                       (cur.lastrowid, curso, nota))
    db.commit()
    db.close()
    return ruta


if __name__ == "__main__":
    print("Base de datos creada en", inicializar())

import sqlite3

from flask import current_app, g

ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    rol TEXT NOT NULL CHECK (rol IN ('estudiante','docente','admin')),
    carnet TEXT,
    intentos_fallidos INTEGER NOT NULL DEFAULT 0,
    bloqueado_hasta TEXT
);
CREATE TABLE IF NOT EXISTS estudiantes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    carnet TEXT NOT NULL UNIQUE,
    nombre TEXT NOT NULL,
    apellido TEXT NOT NULL,
    email TEXT NOT NULL,
    dpi_cifrado TEXT NOT NULL,      -- AES-256-GCM (kid:base64)
    dpi_indice TEXT NOT NULL,       -- HMAC-SHA256 para búsquedas exactas
    telefono_cifrado TEXT
);
CREATE TABLE IF NOT EXISTS calificaciones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    estudiante_id INTEGER NOT NULL REFERENCES estudiantes(id),
    curso TEXT NOT NULL,
    nota TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS comentarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    autor TEXT NOT NULL,
    contenido TEXT NOT NULL,
    creado TEXT NOT NULL DEFAULT (datetime('now'))
);
-- Tabla del laboratorio que reproduce el almacenamiento inseguro original
CREATE TABLE IF NOT EXISTS usuarios_legado (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password_sha256 TEXT NOT NULL
);
"""


def ruta_sqlite(database_url: str) -> str:
    if not database_url.startswith("sqlite:///"):
        raise ValueError("El laboratorio solo admite DATABASE_URL de tipo sqlite:///")
    return database_url[len("sqlite:///"):]


def conectar(database_url: str) -> sqlite3.Connection:
    conexion = sqlite3.connect(ruta_sqlite(database_url))
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON")
    return conexion


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = conectar(current_app.config["DATABASE_URL"])
    return g.db


def cerrar_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def crear_esquema(conexion: sqlite3.Connection):
    conexion.executescript(ESQUEMA)
    conexion.commit()

"""
=====================================================================
 RUTAS VULNERABLES DE LABORATORIO — SOLO CON LAB_MODE=1
 Reproducen de forma controlada las debilidades señaladas por la
 auditoría para demostrar el ataque y compararlo con la corrección.
 Nunca deben habilitarse fuera del entorno de laboratorio.
=====================================================================
"""
import logging
from pathlib import Path

from flask import Blueprint, current_app, render_template, request
from markupsafe import Markup

from .db import get_db
from .reports import comprimir_reporte_vulnerable, escribir_csv
from .security_crypto import sha256_inseguro

bp = Blueprint("lab", __name__, url_prefix="/lab")


def _log_inseguro() -> logging.Logger:
    """Logger del antipatrón: texto plano, nivel DEBUG, sin redacción."""
    logger = logging.getLogger("portal.inseguro")
    ruta = current_app.config["LOG_INSEGURO"]
    if not any(getattr(h, "baseFilename", None) == str(Path(ruta).resolve()) for h in logger.handlers):
        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()
        manejador = logging.FileHandler(ruta, encoding="utf-8")
        manejador.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(manejador)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
    return logger


# ---- I-B  SQL Injection: concatenación de la entrada en la sentencia ----
def buscar_vulnerable(db, q: str):
    sql = ("SELECT carnet, nombre, apellido FROM estudiantes "
           "WHERE apellido LIKE '%" + q + "%' ORDER BY apellido")
    return sql, db.execute(sql).fetchall()


@bp.get("/buscar")
def buscar():
    q = request.args.get("q", "")
    sql, filas = buscar_vulnerable(get_db(), q) if q else ("", [])
    # Muestra la sentencia final para evidenciar cómo cambió su estructura
    return render_template("lab/buscar.html", q=q, sql=sql, resultados=filas)


@bp.post("/login")
def login():
    email = request.form.get("email", "")
    password = request.form.get("password", "")
    sql = ("SELECT id, email FROM usuarios_legado WHERE email = '" + email +
           "' AND password_sha256 = '" + sha256_inseguro(password) + "'")
    # ---- II-E  Registro INSEGURO: vuelca la contraseña en el log ----
    _log_inseguro().info(f"Intento de login email={email} password={password} sql={sql}")
    fila = get_db().execute(sql).fetchone()
    return ({"autenticado": bool(fila), "como": fila["email"] if fila else None}, 200)


# ---- I-C  XSS almacenado: el comentario se marca como HTML "seguro" ----
@bp.route("/comentarios", methods=["GET", "POST"])
def comentarios():
    db = get_db()
    if request.method == "POST":
        db.execute("INSERT INTO comentarios (autor, contenido) VALUES (?, ?)",
                   ("lab", request.form.get("contenido", "")))
        db.commit()
    filas = db.execute("SELECT autor, contenido FROM comentarios ORDER BY id DESC").fetchall()
    return render_template("lab/comentarios.html", comentarios=filas)


# ---- I-C  XSS reflejado: el parámetro se concatena en HTML sin codificar ----
@bp.get("/saludo")
def saludo():
    nombre = request.args.get("nombre", "")
    return Markup("<h1>Bienvenido, " + nombre + "</h1>")


# ---- I-C  XSS basado en DOM: el fragmento #... se inserta con innerHTML ----
@bp.get("/dom")
def dom():
    return render_template("lab/dom.html")


# ---- I-D  Inyección de comandos: nombre de reporte concatenado al shell ----
@bp.get("/reporte")
def reporte():
    nombre = request.args.get("nombre", "reporte")
    directorio = Path(current_app.config["REPORT_DIR"])
    directorio.mkdir(parents=True, exist_ok=True)
    try:
        escribir_csv(directorio, "base", [])
    except OSError:
        pass
    codigo = comprimir_reporte_vulnerable(str(directorio), nombre)
    return {"comando_ejecutado": f"tar -czf {directorio}/{nombre}.tar.gz -C {directorio} {nombre}.csv",
            "codigo_salida": codigo}

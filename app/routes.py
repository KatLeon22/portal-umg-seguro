"""Rutas SEGURAS del portal académico."""
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from flask import (Blueprint, abort, current_app, flash, redirect, render_template,
                   request, send_file, session, url_for)

from .db import get_db
from .reports import comprimir_reporte_seguro, escribir_csv
from .secure_logging import enmascarar_carnet, enmascarar_email, registrar
from .security_crypto import (enmascarar_dpi, hash_password, requiere_rehash,
                              verificar_password)
from .validation import (ValidationError, validar_busqueda, validar_calificacion,
                         validar_carnet, validar_email, validar_nombre,
                         validar_nombre_reporte, validar_password_nueva)

bp = Blueprint("portal", __name__)

MAX_INTENTOS = 5
MINUTOS_BLOQUEO = 15


def _ip():
    return request.remote_addr


def requiere_rol(*roles):
    def decorador(vista):
        @wraps(vista)
        def envoltura(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("portal.login"))
            if roles and session.get("rol") not in roles:
                abort(403)
            return vista(*args, **kwargs)
        return envoltura
    return decorador


@bp.get("/")
def inicio():
    return render_template("inicio.html")


# ------------------------------------------------------------- registro
@bp.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        try:
            email = validar_email(request.form.get("email", ""))
            password = validar_password_nueva(request.form.get("password", ""))
            carnet = validar_carnet(request.form.get("carnet", ""))
        except ValidationError as exc:
            registrar("validacion.rechazo", logging.WARNING, ruta="/registro", motivo=str(exc), ip=_ip())
            flash(str(exc))
            return render_template("registro.html"), 400
        db = get_db()
        if db.execute("SELECT 1 FROM usuarios WHERE email = ?", (email,)).fetchone():
            flash("No fue posible completar el registro.")  # no confirma existencia
            return render_template("registro.html"), 400
        db.execute(
            "INSERT INTO usuarios (email, password_hash, rol, carnet) VALUES (?, ?, 'estudiante', ?)",
            (email, hash_password(password), carnet),
        )
        db.commit()
        registrar("auth.registro", email=enmascarar_email(email), ip=_ip())
        flash("Registro completado. Inicie sesión.")
        return redirect(url_for("portal.login"))
    return render_template("registro.html")


# --------------------------------------------------------- inicio de sesión
@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    password = request.form.get("password", "")
    try:
        email = validar_email(request.form.get("email", ""))
    except ValidationError:
        email = None

    db = get_db()
    usuario = db.execute("SELECT * FROM usuarios WHERE email = ?", (email,)).fetchone() if email else None
    ahora = datetime.now(timezone.utc)

    if usuario and usuario["bloqueado_hasta"] and datetime.fromisoformat(usuario["bloqueado_hasta"]) > ahora:
        verificar_password(None, password)  # tiempo de respuesta uniforme
        registrar("auth.login.fallo", logging.WARNING, user_id=usuario["id"], motivo="cuenta_bloqueada", ip=_ip())
        flash("Credenciales inválidas.")
        return render_template("login.html"), 401

    if not verificar_password(usuario["password_hash"] if usuario else None, password):
        if usuario:
            intentos = usuario["intentos_fallidos"] + 1
            bloqueo = (ahora + timedelta(minutes=MINUTOS_BLOQUEO)).isoformat() if intentos >= MAX_INTENTOS else None
            db.execute("UPDATE usuarios SET intentos_fallidos = ?, bloqueado_hasta = ? WHERE id = ?",
                       (intentos, bloqueo, usuario["id"]))
            db.commit()
            if bloqueo:
                registrar("auth.cuenta.bloqueada", logging.WARNING, user_id=usuario["id"], ip=_ip())
        registrar("auth.login.fallo", logging.WARNING,
                  email=enmascarar_email(email) if email else "[invalido]",
                  user_id=usuario["id"] if usuario else None,
                  motivo="credenciales_invalidas", ip=_ip())
        flash("Credenciales inválidas.")  # mismo mensaje exista o no el usuario
        return render_template("login.html"), 401

    if requiere_rehash(usuario["password_hash"]):
        db.execute("UPDATE usuarios SET password_hash = ? WHERE id = ?", (hash_password(password), usuario["id"]))
    db.execute("UPDATE usuarios SET intentos_fallidos = 0, bloqueado_hasta = NULL WHERE id = ?", (usuario["id"],))
    db.commit()

    session.clear()  # evita fijación de sesión
    session.update(user_id=usuario["id"], rol=usuario["rol"], carnet=usuario["carnet"])
    session.permanent = True
    registrar("auth.login.exito", user_id=usuario["id"], rol=usuario["rol"], ip=_ip())
    if usuario["rol"] == "admin":
        registrar("admin.acceso", user_id=usuario["id"], recurso="login_admin", ip=_ip())
    return redirect(url_for("portal.inicio"))


@bp.post("/logout")
def logout():
    registrar("auth.logout", user_id=session.get("user_id"), ip=_ip())
    session.clear()
    return redirect(url_for("portal.login"))


# -------------------------------------------------- búsqueda (SQLi corregida)
@bp.get("/estudiantes/buscar")
@requiere_rol("docente", "admin")
def buscar_estudiantes():
    q = request.args.get("q", "")
    resultados = []
    if q:
        try:
            q = validar_busqueda(q)
        except ValidationError as exc:
            flash(str(exc))
            return render_template("buscar.html", q=q, resultados=[]), 400
        # La consulta es una plantilla FIJA. El valor viaja aparte como parámetro
        # y el motor lo trata siempre como dato, nunca como código SQL.
        patron = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        resultados = get_db().execute(
            "SELECT carnet, nombre, apellido FROM estudiantes "
            "WHERE apellido LIKE ? ESCAPE '\\' OR nombre LIKE ? ESCAPE '\\' ORDER BY apellido LIMIT 50",
            (patron, patron),
        ).fetchall()
    return render_template("buscar.html", q=q, resultados=resultados)


# ----------------------------------------- expediente (control de acceso + log)
@bp.get("/expediente/<carnet>")
@requiere_rol("estudiante", "docente", "admin")
def expediente(carnet):
    try:
        carnet = validar_carnet(carnet)
    except ValidationError:
        abort(404)
    if session["rol"] == "estudiante" and session.get("carnet") != carnet:
        registrar("expediente.acceso.denegado", logging.WARNING, user_id=session["user_id"],
                  carnet=enmascarar_carnet(carnet), ip=_ip())
        abort(403)  # evita IDOR: un estudiante solo ve su propio expediente
    db = get_db()
    est = db.execute("SELECT * FROM estudiantes WHERE carnet = ?", (carnet,)).fetchone()
    if not est:
        abort(404)
    notas = db.execute("SELECT id, curso, nota FROM calificaciones WHERE estudiante_id = ?", (est["id"],)).fetchall()
    cifrador = current_app.extensions["cifrador"]
    dpi = cifrador.descifrar(est["dpi_cifrado"], contexto=f"estudiante:{est['carnet']}:dpi")
    registrar("expediente.consulta", user_id=session["user_id"], rol=session["rol"],
              carnet=enmascarar_carnet(carnet), ip=_ip())
    return render_template("expediente.html", est=est, notas=notas, dpi=enmascarar_dpi(dpi))


@bp.post("/calificaciones/<int:cal_id>")
@requiere_rol("docente", "admin")
def modificar_calificacion(cal_id):
    try:
        nota = validar_calificacion(request.form.get("nota", ""))
    except ValidationError as exc:
        flash(str(exc))
        abort(400)
    db = get_db()
    anterior = db.execute("SELECT nota FROM calificaciones WHERE id = ?", (cal_id,)).fetchone()
    if not anterior:
        abort(404)
    db.execute("UPDATE calificaciones SET nota = ? WHERE id = ?", (str(nota), cal_id))
    db.commit()
    registrar("calificacion.modificacion", user_id=session["user_id"], calificacion_id=cal_id,
              valor_anterior=anterior["nota"], valor_nuevo=str(nota), ip=_ip())
    flash("Calificación actualizada.")
    return redirect(request.referrer or url_for("portal.inicio"))


# ------------------------------------------------- comentarios (XSS corregido)
@bp.route("/comentarios", methods=["GET", "POST"])
@requiere_rol("estudiante", "docente", "admin")
def comentarios():
    db = get_db()
    if request.method == "POST":
        contenido = request.form.get("contenido", "").strip()
        if not 1 <= len(contenido) <= 1000:
            flash("El comentario debe tener entre 1 y 1000 caracteres.")
        else:
            # Se almacena el texto tal cual; se CODIFICA AL MOSTRARLO (Jinja2 autoescape)
            db.execute("INSERT INTO comentarios (autor, contenido) VALUES (?, ?)",
                       (f"usuario-{session['user_id']}", contenido))
            db.commit()
            registrar("comentario.publicado", user_id=session["user_id"], longitud=len(contenido))
        return redirect(url_for("portal.comentarios"))
    filas = db.execute("SELECT autor, contenido, creado FROM comentarios ORDER BY id DESC LIMIT 50").fetchall()
    return render_template("comentarios.html", comentarios=filas)


# ---------------------------------------------- reportes (comando corregido)
@bp.post("/reportes")
@requiere_rol("admin")
def generar_reporte():
    try:
        nombre = validar_nombre_reporte(request.form.get("nombre", ""))
    except ValidationError as exc:
        registrar("validacion.rechazo", logging.WARNING, ruta="/reportes", motivo=str(exc),
                  user_id=session["user_id"], ip=_ip())
        abort(400)
    directorio = Path(current_app.config["REPORT_DIR"])
    directorio.mkdir(parents=True, exist_ok=True)
    filas = get_db().execute(
        "SELECT e.carnet, e.nombre, e.apellido, c.curso, c.nota FROM estudiantes e "
        "JOIN calificaciones c ON c.estudiante_id = e.id ORDER BY e.carnet"
    ).fetchall()
    escribir_csv(directorio, nombre, [dict(f) for f in filas])
    archivo = comprimir_reporte_seguro(directorio, nombre)
    registrar("reporte.generado", user_id=session["user_id"], reporte=nombre, filas=len(filas), ip=_ip())
    return send_file(archivo.resolve(), as_attachment=True, mimetype="application/gzip")


@bp.get("/admin")
@requiere_rol("admin")
def panel_admin():
    registrar("admin.acceso", user_id=session["user_id"], recurso="/admin", ip=_ip())
    return render_template("admin.html")


@bp.get("/diagnostico/error")
@requiere_rol("admin")
def provocar_error():
    """Ruta de prueba: simula un fallo interno cuyo mensaje contiene un secreto."""
    raise RuntimeError(
        "Fallo de conexión a " + current_app.config["DATABASE_URL"]
        + " usando token=ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    )

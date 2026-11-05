"""Fábrica de la aplicación Portal Académico (laboratorio MASI 2026)."""
import logging
import os
import secrets
from pathlib import Path

from flask import Flask, abort, render_template, request, session
from werkzeug.exceptions import HTTPException

from .config import cargar_secretos
from .db import cerrar_db
from .secure_logging import configurar_logger, nuevo_id_incidente
from .security_crypto import CifradorDatos

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)


def create_app(entorno: dict | None = None, lab_mode: bool | None = None,
               ruta_log: str | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)

    secretos = cargar_secretos(entorno)          # falla si falta algún secreto
    app.config.update(
        SECRET_KEY=secretos["SECRET_KEY"],
        DATABASE_URL=secretos["DATABASE_URL"],
        SESSION_COOKIE_SECURE=True,              # la cookie solo viaja por HTTPS
        SESSION_COOKIE_HTTPONLY=True,            # inaccesible desde JavaScript
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_CONTENT_LENGTH=64 * 1024,
        REPORT_DIR=Path((entorno or os.environ).get("REPORT_DIR", "instance/reportes")),
        PROPAGATE_EXCEPTIONS=False,
    )
    app.extensions["cifrador"] = CifradorDatos(
        secretos["DATA_ENC_KEYS"], secretos["DATA_ENC_ACTIVE_KID"], secretos["BLIND_INDEX_KEY"]
    )
    del secretos  # no se conservan copias innecesarias en memoria del objeto app

    ruta_log = ruta_log or (entorno or os.environ).get("LOG_PATH")
    configurar_logger(ruta_log)
    app.config["LOG_INSEGURO"] = str(Path(ruta_log or "instance/seguridad.log").with_name("inseguro.log"))
    app.teardown_appcontext(cerrar_db)

    # ----------------------------------------------------------- CSRF simple
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def verificar_csrf():
        if request.method == "POST" and not request.path.startswith("/lab/"):
            enviado = request.form.get("csrf_token", "")
            if not enviado or not secrets.compare_digest(enviado, session.get("csrf", "")):
                abort(400)

    # --------------------------------------------- encabezados de seguridad
    @app.after_request
    def encabezados(resp):
        if not request.path.startswith("/lab/"):
            resp.headers["Content-Security-Policy"] = CSP
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers.pop("Server", None)
        return resp

    # ------------------------------------------------- manejo de errores
    @app.errorhandler(HTTPException)
    def error_http(exc):
        return render_template("error.html", codigo=exc.code, incidente=None), exc.code

    @app.errorhandler(Exception)
    def error_interno(exc):
        incidente = nuevo_id_incidente()
        # Detalle técnico (redactado) solo en el servidor; al usuario, un id
        logging.getLogger("portal.seguridad").error(
            "Excepción no controlada", exc_info=exc,
            extra={"evento": "error.interno",
                   "campos": {"incidente": incidente, "ruta": request.path,
                              "user_id": session.get("user_id")}},
        )
        return render_template("error.html", codigo=500, incidente=incidente), 500

    from .routes import bp as rutas
    app.register_blueprint(rutas)

    if lab_mode is None:
        lab_mode = (entorno or os.environ).get("LAB_MODE") == "1"
    if lab_mode:
        from .lab_vulnerable import bp as lab
        app.register_blueprint(lab)
        app.logger.warning("LAB_MODE activo: rutas vulnerables expuestas en /lab (solo laboratorio)")

    return app

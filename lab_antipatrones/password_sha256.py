# ANTIPATRÓN (Fase II-A): contraseña con SHA-256 simple, sin sal ni factor de costo.
import hashlib


def guardar_password(db, email, password):
    db.execute("INSERT INTO usuarios_legado (email, password_sha256) VALUES (?, ?)",
               (email, hashlib.sha256(password.encode()).hexdigest()))

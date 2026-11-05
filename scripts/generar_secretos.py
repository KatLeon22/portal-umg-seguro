"""Genera un archivo .env de LABORATORIO con secretos aleatorios (CSPRNG).

Uso:  python scripts/generar_secretos.py
El archivo se crea con permisos 600 y está excluido por .gitignore.
En producción estos valores se guardan en Vault (vault/configurar_vault.sh).
"""
import base64
import os
import secrets
import stat
from pathlib import Path

ruta = Path(".env")
if ruta.exists():
    raise SystemExit(".env ya existe; no se sobrescribe. Bórrelo explícitamente para regenerarlo.")

b64 = lambda n: base64.b64encode(secrets.token_bytes(n)).decode()
contenido = f"""# Generado por scripts/generar_secretos.py — NO VERSIONAR
FLASK_SECRET_KEY={secrets.token_urlsafe(48)}
DATA_ENC_KEYS=v1:{b64(32)}
BLIND_INDEX_KEY={b64(32)}
DATABASE_URL=sqlite:///instance/portal.db
REPORT_DIR=instance/reportes
LOG_PATH=instance/seguridad.log
LAB_MODE=1
"""
fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, stat.S_IRUSR | stat.S_IWUSR)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    f.write(contenido)
if os.name == "nt":
    print("Archivo .env creado. En Windows queda protegido por los permisos NTFS de su perfil de usuario;")
    print("no lo comparta ni lo suba al repositorio (.gitignore ya lo excluye).")
else:
    print("Archivo .env creado con permisos 600 (solo lectura/escritura del propietario).")

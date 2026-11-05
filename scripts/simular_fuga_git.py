"""Fase II-D: simulación CONTROLADA de la fuga de credenciales en Git.

Funciona en Windows y Linux (requiere Git instalado). Crea un repositorio de
laboratorio APARTE del proyecto, filtra credenciales FICTICIAS generadas al azar,
las "borra" en un commit posterior y demuestra que siguen en el historial.
Si Gitleaks o TruffleHog están instalados, los ejecuta y guarda su salida.
Uso:  python scripts/simular_fuga_git.py
"""
import re
import secrets
import shutil
import stat
import string
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
REPO = RAIZ / "laboratorio-fuga-git"
EVID = RAIZ / "evidencias"


def git(*args, capturar=True):
    return subprocess.run(["git", *args], cwd=REPO, check=True, capture_output=capturar,
                          text=True, encoding="utf-8").stdout


def azar(alfabeto, n):
    return "".join(secrets.choice(alfabeto) for _ in range(n))


def _forzar_borrado(func, ruta, _exc):
    Path(ruta).chmod(stat.S_IWRITE)   # en Windows .git contiene archivos de solo lectura
    func(ruta)


def main():
    if not shutil.which("git"):
        sys.exit("Git no está instalado. En Windows: winget install --id Git.Git -e")
    EVID.mkdir(exist_ok=True)
    if REPO.exists():
        shutil.rmtree(REPO, onerror=_forzar_borrado)
    REPO.mkdir()

    letras = string.ascii_letters + string.digits
    token_gh = "ghp_" + azar(letras, 36)
    aws_id = "AKIA" + azar(string.ascii_uppercase + "234567", 16)
    aws_secreto = azar(letras + "+/", 40)
    db_pass = azar(letras, 20)

    git("init", "-q")
    git("checkout", "-q", "-b", "main")
    git("config", "user.name", "Desarrollador Laboratorio")
    git("config", "user.email", "dev@portal.test")

    print("== 1. Commit inicial (sin secretos)")
    (REPO / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n", encoding="utf-8")
    git("add", "."); git("commit", "-qm", "Estructura inicial del portal")

    print("== 2. Commit con la FUGA (credenciales ficticias en el código)")
    (REPO / "config.py").write_text(
        "# Configuración de reportes\n"
        'DB_HOST = "10.0.5.20"\nDB_USER = "admin_portal"\n'
        f'DB_PASSWORD = "{db_pass}"\nGITHUB_TOKEN = "{token_gh}"\n'
        f'AWS_ACCESS_KEY_ID = "{aws_id}"\nAWS_SECRET_ACCESS_KEY = "{aws_secreto}"\n', encoding="utf-8")
    git("add", "."); git("commit", "-qm", "Agrega integración de reportes")
    commit_fuga = git("rev-parse", "--short", "HEAD").strip()

    print("== 3. Commit que 'elimina' las credenciales (corrección ingenua)")
    (REPO / "config.py").write_text(
        'import os\nDB_HOST = os.environ["DB_HOST"]\nDB_USER = os.environ["DB_USER"]\n'
        'DB_PASSWORD = os.environ["DB_PASSWORD"]\n', encoding="utf-8")
    git("add", "."); git("commit", "-qm", "Elimina credenciales del código")

    actual = (REPO / "config.py").read_text(encoding="utf-8")
    viejo = git("show", f"{commit_fuga}:config.py")
    recortado = re.sub(r'(= ")(.{6}).*(")', r"\1\2…[recortado en la evidencia]\3", viejo)
    objetos = [l for l in git("rev-list", "--all", "--objects").splitlines() if l.endswith("config.py")]
    informe = "\n".join([
        "### Historial del repositorio de laboratorio", git("log", "--oneline").strip(), "",
        "### ¿Está el token en la versión actual (HEAD)?",
        "Sí (¡error!)" if "ghp_" in actual else "No: el archivo actual ya no contiene el token.", "",
        "### ¿Sigue en el historial? git log -S <token> (pickaxe)",
        git("log", "--oneline", "-S", token_gh).strip(), "",
        f"### Recuperación del secreto desde el commit {commit_fuga} (git show {commit_fuga}:config.py)",
        recortado.strip(), "",
        "### Ambas versiones de config.py siguen guardadas como objetos en la base de datos de Git",
        *objetos, ""])
    print(informe)
    (EVID / "fuga_git_historial.txt").write_text(informe, encoding="utf-8")

    gitleaks = shutil.which("gitleaks")
    if gitleaks:
        print("== 4. Gitleaks sobre TODO el historial")
        ayuda = subprocess.run([gitleaks, "git", "--help"], capture_output=True)
        if ayuda.returncode == 0:   # v8.19 o superior
            historial = [gitleaks, "git", "-v", "--redact", "--report-format", "json",
                         "--report-path", str(EVID / "gitleaks_reporte.json"), "."]
            solo_archivos = [gitleaks, "dir", "-v", "--redact", "config.py", "app.py"]
        else:
            historial = [gitleaks, "detect", "-v", "--redact", "--source", ".", "--report-format", "json",
                         "--report-path", str(EVID / "gitleaks_reporte.json")]
            solo_archivos = [gitleaks, "detect", "-v", "--redact", "--no-git", "--source", "."]
        for nombre, cmd in (("gitleaks_salida.txt", historial), ("gitleaks_solo_archivos.txt", solo_archivos)):
            r = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, encoding="utf-8", errors="replace")
            print(r.stdout + r.stderr)
            (EVID / nombre).write_text(r.stdout + r.stderr, encoding="utf-8")
    else:
        print("Gitleaks no está instalado. Descargue el .zip para Windows (windows_x64) desde")
        print("https://github.com/gitleaks/gitleaks/releases , descomprímalo y ejecute:")
        print(f'   cd "{REPO}"')
        print("   gitleaks git -v --redact .")
    if shutil.which("trufflehog"):
        r = subprocess.run(["trufflehog", "git", REPO.as_uri(), "--no-update"], capture_output=True, text=True)
        (EVID / "trufflehog_salida.txt").write_text(r.stdout + r.stderr, encoding="utf-8")


if __name__ == "__main__":
    main()

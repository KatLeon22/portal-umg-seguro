"""Fase II-D: corrección del historial DESPUÉS de revocar/rotar la credencial.

Requiere:  pip install git-filter-repo   (funciona en Windows y Linux)
Uso:  python scripts/remediar_historial.py <ruta_repo> <archivo_con_valores_a_borrar>
El archivo de valores contiene un secreto por línea y NO se versiona.
"""
import shutil
import subprocess
import sys

if len(sys.argv) != 3:
    sys.exit(__doc__)
repo, secretos = sys.argv[1], sys.argv[2]
ejecutar = lambda *c: subprocess.run(list(c), cwd=repo, check=True)
ejecutar(sys.executable, "-m", "git_filter_repo", "--force", "--replace-text", secretos)
ejecutar("git", "reflog", "expire", "--expire=now", "--all")
ejecutar("git", "gc", "--prune=now", "--aggressive")
if shutil.which("gitleaks"):
    subprocess.run(["gitleaks", "git", "-v", "--redact", "."], cwd=repo)
print("Historial reescrito (valores sustituidos por ***REMOVED***).")
print("En el remoto: git push --force --all y --tags; pedir purga de caché y que todos vuelvan a clonar.")

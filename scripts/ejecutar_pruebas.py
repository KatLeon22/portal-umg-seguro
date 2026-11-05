"""Ejecuta TODAS las pruebas técnicas y guarda la salida como evidencia.
Uso (Windows o Linux):  python scripts/ejecutar_pruebas.py
"""
import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
(RAIZ / "evidencias").mkdir(exist_ok=True)
proc = subprocess.run(
    [sys.executable, "-X", "utf8", "-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
    cwd=RAIZ, capture_output=True, text=True, encoding="utf-8", errors="replace",
)
salida = proc.stdout + proc.stderr
(RAIZ / "evidencias" / "resultado_pruebas.txt").write_text(salida, encoding="utf-8")
print(salida)
print("Evidencia guardada en evidencias/resultado_pruebas.txt")
sys.exit(proc.returncode)

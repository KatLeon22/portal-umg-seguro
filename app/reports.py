"""
Fase I-D: Inyección de comandos en la generación/compresión de reportes.

Versión VULNERABLE: construye una cadena y la entrega a /bin/sh mediante
os.system(). Cualquier metacarácter del shell (; | & $( ) ` > <) contenido en
el nombre del reporte se interpreta como un comando adicional.

Versión SEGURA (defensa en profundidad):
  1. Validación con lista de permitidos del nombre (a-z, 0-9, _ y -).
  2. Preferencia por una API nativa (tarfile) que no invoca ningún shell.
  3. Si se requiere un binario externo: subprocess.run con LISTA de
     argumentos, shell=False, ruta absoluta del ejecutable (Linux o Windows), "--" para cortar
     la interpretación de opciones, entorno mínimo y tiempo límite.
  4. Confinamiento de rutas al directorio de reportes (sin ../).
  5. Privilegios mínimos en el despliegue: usuario de servicio sin shell y
     con escritura solo en el directorio de reportes (deploy/portal-reportes.service).
"""
import csv
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

from .validation import validar_nombre_reporte

ES_WINDOWS = os.name == "nt"


def _tar_absoluto() -> str:
    """Ruta ABSOLUTA del ejecutable (no se confía en el PATH del usuario)."""
    if ES_WINDOWS:
        ruta = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tar.exe"
    else:
        ruta = Path("/usr/bin/tar")
    if not ruta.exists():
        encontrado = shutil.which("tar")
        if not encontrado:
            raise FileNotFoundError("No se encontró el ejecutable tar")
        ruta = Path(encontrado)
    return str(ruta)


def _entorno_minimo() -> dict:
    if ES_WINDOWS:
        raiz = os.environ.get("SystemRoot", r"C:\Windows")
        return {"SystemRoot": raiz, "PATH": raiz + r"\System32"}
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}


def escribir_csv(directorio: Path, nombre: str, filas: list[dict]) -> Path:
    ruta = directorio / f"{nombre}.csv"
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        escritor = csv.DictWriter(f, fieldnames=["carnet", "nombre", "apellido", "curso", "nota"])
        escritor.writeheader()
        for fila in filas:
            # Neutraliza inyección de fórmulas en Excel (CSV injection)
            escritor.writerow({k: _celda_segura(v) for k, v in fila.items()})
    return ruta


def _celda_segura(valor):
    texto = str(valor)
    return "'" + texto if texto[:1] in ("=", "+", "-", "@", "\t", "\r") else texto


# --------------------------------------------------------------- VULNERABLE
def comprimir_reporte_vulnerable(directorio: str, nombre: str) -> int:
    """NO USAR. Solo existe para la demostración controlada del laboratorio."""
    comando = f"tar -czf {directorio}/{nombre}.tar.gz -C {directorio} {nombre}.csv"
    return os.system(comando)  # noqa: S605 — vulnerable a propósito (/bin/sh o cmd.exe)


# ------------------------------------------------------------------ SEGURA
def _ruta_confinada(directorio: Path, nombre_archivo: str) -> Path:
    ruta = (directorio / nombre_archivo).resolve()
    if ruta.parent != directorio.resolve():
        raise ValueError("Ruta fuera del directorio de reportes")
    return ruta


def comprimir_reporte_seguro(directorio: Path, nombre: str) -> Path:
    """Opción recomendada: biblioteca estándar, sin procesos ni shell."""
    nombre = validar_nombre_reporte(nombre)
    origen = _ruta_confinada(directorio, f"{nombre}.csv")
    destino = _ruta_confinada(directorio, f"{nombre}.tar.gz")
    with tarfile.open(destino, "w:gz") as tar:
        tar.add(origen, arcname=origen.name)
    return destino


def comprimir_reporte_con_binario(directorio: Path, nombre: str) -> Path:
    """Alternativa cuando es obligatorio usar un ejecutable del sistema."""
    nombre = validar_nombre_reporte(nombre)
    origen = _ruta_confinada(directorio, f"{nombre}.csv")
    destino = _ruta_confinada(directorio, f"{nombre}.tar.gz")
    subprocess.run(
        [_tar_absoluto(), "-czf", str(destino), "-C", str(directorio.resolve()), "--", origen.name],
        shell=False,            # el texto nunca llega a /bin/sh ni a cmd.exe
        check=True,
        timeout=30,
        env=_entorno_minimo(),
        stdin=subprocess.DEVNULL,
        capture_output=True,
    )
    return destino

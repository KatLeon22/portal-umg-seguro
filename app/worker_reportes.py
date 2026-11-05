"""Trabajador de compresión de reportes con privilegios mínimos.

Se ejecuta con la identidad 'portal-reportes' (deploy/portal-reportes.service),
separada del proceso web: si el portal fuera comprometido, el atacante no hereda
permisos para escribir fuera de instance/reportes ni para abrir conexiones de red.
Uso:  python -m app.worker_reportes <nombre_reporte>
"""
import os
import sys
from pathlib import Path

from .reports import comprimir_reporte_con_binario


def main(argv):
    if len(argv) != 2:
        print("Uso: python -m app.worker_reportes <nombre_reporte>", file=sys.stderr)
        return 2
    directorio = Path(os.environ.get("REPORT_DIR", "instance/reportes"))
    destino = comprimir_reporte_con_binario(directorio, argv[1])  # valida y usa lista de argumentos
    print(destino)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

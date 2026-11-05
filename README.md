# Portal Académico — Tarea Integradora Semanas 4 y 5 (MASI 2026 · Seguridad en Aplicaciones)

Aplicación de laboratorio en **Python 3.12 + Flask** que reproduce las debilidades
señaladas por la auditoría (rutas `/lab/*`) y su **corrección verificada** (resto
de rutas). Cada control tiene una prueba automatizada en `tests/`.

> ⚠️ Solo para laboratorio. Todas las credenciales, claves, correos, carnés y DPI
> son **ficticios**. Las rutas vulnerables existen únicamente con `LAB_MODE=1`.

## 1. Requisitos
- Python 3.11 o superior, OpenSSL, Git
- Gitleaks 8.x (https://github.com/gitleaks/gitleaks/releases) — y opcionalmente TruffleHog
- Opcional: HashiCorp Vault (`vault` CLI) y `pip install -r requirements-vault.txt`

## 2. Puesta en marcha
```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/generar_secretos.py     # crea .env con secretos aleatorios (permisos 600)
python scripts/init_db.py              # base de datos con datos ficticios (DPI y teléfono cifrados)
python scripts/generar_certificado.py  # certificado TLS autofirmado del laboratorio
python run.py                          # https://localhost:8443  (solo HTTPS, TLS >= 1.2)
```
Usuarios de laboratorio (ficticios):

| Rol | Correo | Contraseña |
|---|---|---|
| admin | admin@portal.test | Admin#Laboratorio2026 |
| docente | docente@portal.test | Docente#Laboratorio2026 |
| estudiante | ana.lopez@portal.test | Estudiante#Lab2026 |

## 3. Pruebas técnicas (evidencia reproducible)
```bash
python scripts/ejecutar_pruebas.py     # 53 pruebas -> evidencias/resultado_pruebas.txt
python scripts/simular_fuga_git.py     # fuga ficticia en repo aparte + Gitleaks/TruffleHog
```

## 4. Estructura
| Ruta | Contenido |
|---|---|
| `app/validation.py` | I-A Validación y normalización de entradas |
| `app/routes.py` | Rutas seguras (SQL parametrizado, autoescape, control de acceso, logging) |
| `app/lab_vulnerable.py` | I-B/I-C/I-D/II-E versiones vulnerables controladas (`/lab/*`) |
| `app/reports.py`, `app/worker_reportes.py` | I-D compresión de reportes sin shell |
| `app/security_crypto.py` | II-A scrypt con sal · II-B AES-256-GCM, índice ciego HMAC |
| `app/config.py` | II-C carga de secretos desde entorno o Vault (AppRole) |
| `app/secure_logging.py` | II-E registro JSON con catálogo de eventos y redacción |
| `run.py`, `deploy/nginx-tls.conf` | II-B TLS 1.2/1.3, HSTS, cookies Secure |
| `vault/` | Políticas de mínimo privilegio y configuración de AppRole |
| `deploy/*.service` | Ejecución con usuarios sin privilegios (systemd) |
| `scripts/simular_fuga_git.py`, `scripts/remediar_historial.py` | II-D fuga y corrección del historial |
| `scripts/rotar_clave_datos.py` | Rotación de la clave de cifrado de datos |
| `.gitleaks.toml`, `.pre-commit-config.yaml`, `.github/workflows/gitleaks.yml` | Detección preventiva de secretos |
| `lab_antipatrones/` | Código inseguro original (solo evidencia, no se ejecuta) |
| `evidencias/` | Salidas de pruebas y herramientas |

## 5. Rutas para la demostración en el navegador
| Vulnerable (LAB) | Corregida |
|---|---|
| `/lab/buscar?q=zzz' OR apellido LIKE '` | `/estudiantes/buscar?q=...` (docente) |
| `/lab/comentarios` (publicar `<script>alert(1)</script>`) | `/comentarios` |
| `/lab/saludo?nombre=<img src=x onerror=alert(1)>` | Jinja2 autoescape + CSP |
| `/lab/dom#filtro=<img src=x onerror=alert(1)>` | `/comentarios#filtro=...` (textContent) |
| `/lab/reporte?nombre=base;id>/tmp/pwned;echo` | `/admin` → Generar reporte |
| `POST /lab/login` (`email=admin@portal.test' --`) | `/login` |

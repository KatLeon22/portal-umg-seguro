# ANTIPATRÓN (Fase II-C): credenciales escritas en el código. Valores FICTICIOS.
SECRET_KEY = "portal-umg-2026"                     # predecible y compartida en todos los ambientes
DATABASE_URL = "postgresql://admin_portal:Adm1nPortal2026!@10.0.5.20:5432/academico"
SMTP_PASSWORD = "Notificaciones#2026"
AES_KEY = b"1234567890abcdef1234567890abcdef"     # clave fija: quien lee el repo descifra la BD

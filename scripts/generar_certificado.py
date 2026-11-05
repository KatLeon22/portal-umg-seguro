"""Certificado TLS autofirmado SOLO para laboratorio (Windows, Linux o macOS).

Se genera con la biblioteca `cryptography`, sin depender de OpenSSL en la línea
de comandos. En producción se usa un certificado de una CA pública.
Uso:  python scripts/generar_certificado.py  [carpeta_destino]
"""
import datetime
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def generar(destino: Path = Path("certs"), dias: int = 90, bits: int = 3072):
    destino.mkdir(parents=True, exist_ok=True)
    clave = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    nombre = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Laboratorio MASI"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    ahora = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(nombre).issuer_name(nombre)
        .public_key(clave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(ahora - datetime.timedelta(minutes=5))
        .not_valid_after(ahora + datetime.timedelta(days=dias))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(clave, hashes.SHA256())
    )
    ruta_clave, ruta_cert = destino / "servidor.key", destino / "servidor.crt"
    fd = os.open(ruta_clave, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(clave.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    ruta_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return ruta_cert, ruta_clave


if __name__ == "__main__":
    c, k = generar(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("certs"))
    print(f"Certificado: {c}\nClave privada: {k} (no se versiona; certs/ está en .gitignore)")

"""TLS hygiene — reads nmap NSE script output (ssl-enum-ciphers, ssl-cert).

No internet needed: run with --script ssl-enum-ciphers,ssl-cert.
"""
import re

from lns.core.rules import rule

WEAK = re.compile(r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|RC4|3DES|DES-CBC|EXPORT|NULL|"
                  r"least strength:\s*[CDEF])", re.I)


@rule(id="tls-weak", source="scanner", severity="high", category="tls",
      title="Configuración TLS débil",
      description="Protocolos o cifrados obsoletos detectados por ssl-enum-ciphers.",
      remediation="Desactiva SSLv3/TLS1.0/1.1 y cifrados RC4/3DES/EXPORT; usa TLS1.2+.")
def tls_weak(ctx):
    out = (ctx.scripts or {}).get("ssl-enum-ciphers", "")
    m = WEAK.search(out)
    if m:
        return True, {"match": m.group(0), "port": ctx.port}
    return False


@rule(id="tls-cert-expired", source="scanner", severity="medium", category="tls",
      title="Certificado TLS caducado o no válido",
      description="ssl-cert indica un certificado caducado o autofirmado.",
      remediation="Renueva el certificado con una CA de confianza.")
def tls_cert_expired(ctx):
    out = (ctx.scripts or {}).get("ssl-cert", "").lower()
    if "expired" in out or "self-signed" in out or "self signed" in out:
        return True, {"port": ctx.port}
    return False

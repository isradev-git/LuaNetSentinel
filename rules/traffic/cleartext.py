"""Traffic rule — credentials sent over unencrypted protocols."""
from lns.core.rules import rule


@rule(id="cleartext-credentials", source="traffic", severity="high",
      category="exposure", title="Credenciales en claro",
      description="Autenticación transmitida sin cifrar (HTTP Basic, FTP, telnet).",
      remediation="Migra a TLS/SSH; rota las credenciales expuestas.")
def cleartext_credentials(ctx):
    if ctx.proto in ("http", "ftp", "telnet") and ctx.has_credentials:
        return True, {"proto": ctx.proto, "detail": ctx.cred_detail}
    return False

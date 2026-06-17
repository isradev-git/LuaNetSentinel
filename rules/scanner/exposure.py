"""Scanner exposure rules — example detections, drop more files here."""
from lns.core.rules import rule

LEGACY = {21: "ftp", 23: "telnet", 3389: "ms-wbt-server", 5900: "vnc"}


@rule(id="ssh-exposed", source="scanner", severity="medium",
      category="exposure", title="SSH expuesto",
      description="Puerto 22 abierto y accesible.",
      remediation="Restringe por firewall/Tailscale; deshabilita auth por password.")
def ssh_exposed(ctx):
    if ctx.port == 22 and ctx.state == "open":
        return True, {"banner": ctx.banner, "state": ctx.state}
    return False


@rule(id="legacy-service", source="scanner", severity="high",
      category="weak-config", title="Servicio legacy/inseguro expuesto",
      description="Protocolo sin cifrar o de administración remota expuesto.",
      remediation="Sustituye por equivalente cifrado (SSH/RDP-gateway) o cierra el puerto.")
def legacy_service(ctx):
    if ctx.state == "open" and ctx.port in LEGACY:
        return True, {"service": ctx.service or LEGACY[ctx.port],
                      "port": ctx.port}
    return False

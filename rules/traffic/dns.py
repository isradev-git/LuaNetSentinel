"""Traffic DNS rules — tunneling / DGA via entropy and label length."""
from lns.core.rules import rule
from lns.util.entropy import shannon


@rule(id="dns-tunneling", source="traffic", severity="high",
      category="suspicious-traffic", title="Posible DNS tunneling / DGA",
      description="Consulta DNS con entropía anómalamente alta.",
      remediation="Inspecciona el host origen; bloquea el dominio en el resolver.")
def dns_tunneling(ctx):
    if ctx.proto == "dns" and ctx.qname and shannon(ctx.qname) > 3.8:
        return True, {"qname": ctx.qname, "entropy": round(shannon(ctx.qname), 2)}
    return False


@rule(id="dns-long-label", source="traffic", severity="medium",
      category="suspicious-traffic", title="Label DNS sospechosamente largo",
      description="Un label DNS >50 chars suele indicar exfiltración por DNS.",
      remediation="Revisa el tráfico DNS del host origen.")
def dns_long_label(ctx):
    if ctx.proto == "dns" and ctx.qname:
        longest = max((len(p) for p in ctx.qname.split(".")), default=0)
        if longest > 50:
            return True, {"qname": ctx.qname, "longest_label": longest}
    return False

"""Web attack signatures. Educational regex — prone to false positives,
not a production WAF (see proyecto.md §22). Confidence is implicit: medium.
"""
import re

from lns.core.rules import rule

SQLI = re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s*'?\d|--\s|\bsleep\s*\(|/\*)", re.I)
XSS = re.compile(r"(<script\b|onerror\s*=|javascript:|<img\b[^>]*onerror)", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.\\|/etc/passwd|\bboot\.ini\b)", re.I)
SCANNERS = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|acunetix|nuclei|wpscan)", re.I)


@rule(id="sqli", source="weblog", severity="high", category="web-attack",
      title="Posible inyección SQL", remediation="Usa consultas parametrizadas; valida entrada.")
def sqli(ctx):
    if ctx.path and SQLI.search(ctx.path):
        return True, {"path": ctx.path, "confidence": "medium"}
    return False


@rule(id="xss", source="weblog", severity="high", category="web-attack",
      title="Posible XSS", remediation="Escapa salida; cabeceras CSP.")
def xss(ctx):
    if ctx.path and XSS.search(ctx.path):
        return True, {"path": ctx.path, "confidence": "medium"}
    return False


@rule(id="path-traversal", source="weblog", severity="high", category="web-attack",
      title="Path traversal", remediation="Normaliza y valida rutas; allowlist.")
def path_traversal(ctx):
    if ctx.path and TRAVERSAL.search(ctx.path):
        return True, {"path": ctx.path, "confidence": "medium"}
    return False


@rule(id="scanner-ua", source="weblog", severity="low", category="web-attack",
      title="User-agent de escáner", remediation="Bloquea/limita UAs de herramientas conocidas.")
def scanner_ua(ctx):
    if ctx.ua and SCANNERS.search(ctx.ua):
        return True, {"ua": ctx.ua}
    return False

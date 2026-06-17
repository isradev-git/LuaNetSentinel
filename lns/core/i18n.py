"""i18n: español (canónico) / inglés. Findings traducidos en render.

Español es la fuente de verdad: reglas y colectores emiten ES y se guarda tal
cual. Inglés es un catálogo indexado por `rule_id` (estáticos = dict; reglas
con texto dinámico = función). UI chrome usa `t(key)`. Idioma resuelto una vez:
--lang  >  LNS_LANG  >  config/settings.yaml  >  'es'.

ponytail: 2 idiomas en dicts. Si crece a N idiomas o a traducción por
colaboradores, migrar a gettext (.po/.mo). Para 2, esto es lo lazy correcto.
"""
from __future__ import annotations

import os
from pathlib import Path

import yaml

LANGS = ("es", "en")
_SETTINGS = Path("config/settings.yaml")
_lang: str | None = None


def _from_settings() -> str | None:
    try:
        return (yaml.safe_load(_SETTINGS.read_text()) or {}).get("lang")
    except Exception:
        return None


def lang() -> str:
    """Current language, resolved once (env > settings > 'es')."""
    global _lang
    if _lang is None:
        raw = os.environ.get("LNS_LANG") or _from_settings() or "es"
        _lang = raw.lower()[:2]
        if _lang not in LANGS:
            _lang = "es"
    return _lang


def configured() -> bool:
    """True si el usuario ya fijó idioma (existe settings.yaml). Primer-uso = False."""
    return _SETTINGS.exists()


def set_lang(code: str | None, persist: bool = False) -> str:
    """Override the language (e.g. --lang). persist=True writes settings.yaml."""
    global _lang
    code = (code or "es").lower()[:2]
    _lang = code if code in LANGS else "es"
    if persist:
        _SETTINGS.parent.mkdir(parents=True, exist_ok=True)
        _SETTINGS.write_text(yaml.safe_dump({"lang": _lang}))
    return _lang


# --- UI chrome (menús, etiquetas, mensajes de CLI/TUI) ---
UI: dict[str, dict[str, str]] = {
    "es": {
        "banner.subtitle": "auditor de red defensivo",
        "tab.dashboard": "Panel", "tab.findings": "Hallazgos", "tab.rules": "Reglas",
        "col.host": "Host", "col.risk": "Riesgo", "col.sev": "Sev",
        "col.rule": "Regla", "col.title": "Título", "col.id": "ID",
        "col.source": "Fuente",
        "input.placeholder": "objetivo CIDR (s/Enter) · ruta .pcap (t) · log web (w)",
        "summary": "Run: {run}   ·   {n} hallazgos   ·   hosts en riesgo: {hi}",
        "hint.empty": "Sin datos todavía.  's' escanea una red  ·  'w' analiza un log web  "
                      "·  't' un .pcap  ·  'l' cambia idioma.",
        "status.exported": "informe HTML escrito en {p}",
        "detail.empty": "Selecciona un hallazgo para ver detalle.",
        "detail.rule": "Regla", "detail.sev": "Severidad", "detail.score": "Score",
        "detail.target": "Objetivo", "detail.evidence": "Evidencia",
        "detail.remediation": "Remediación", "detail.nodesc": "sin descripción",
        "status.scanning": "escaneando {t}…", "status.analyzing": "analizando {t}…",
        "status.blocked": "BLOQUEADO: {e}", "status.error": "error: {e}",
        "bind.quit": "Salir", "bind.refresh": "Recargar", "bind.scan": "Escanear",
        "bind.traffic": "Tráfico", "bind.weblog": "Log web", "bind.export": "Informe",
        "bind.lang": "Idioma",
        "cli.need_pcap": "Indica --pcap o --iface",
        "cli.no_runs": "No hay runs guardados.",
        "cli.report_written": "informe escrito en {p}",
        "cli.app_help": "LuaNetSentinel — auditor de red defensivo (es/en con --lang)",
        "cli.epilog": (
            "Ejemplos:\n"
            "  lns                          abre la TUI interactiva\n"
            "  lns scan 192.168.1.0/24      escaneo autorizado + CVE\n"
            "  lns weblog access.log        firmas de ataque en logs web\n"
            "  lns traffic --pcap cap.pcap  análisis de tráfico\n"
            "  lns report -f html -o r.html informe HTML del último run\n"
            "  lns lang en                  fija el idioma (es|en)\n\n"
            "Idioma: --lang es|en, variable LNS_LANG, o `lns lang`."),
    },
    "en": {
        "banner.subtitle": "defensive network auditor",
        "tab.dashboard": "Dashboard", "tab.findings": "Findings", "tab.rules": "Rules",
        "col.host": "Host", "col.risk": "Risk", "col.sev": "Sev",
        "col.rule": "Rule", "col.title": "Title", "col.id": "ID",
        "col.source": "Source",
        "input.placeholder": "target CIDR (s/Enter) · .pcap path (t) · web log (w)",
        "summary": "Run: {run}   ·   {n} findings   ·   hosts at risk: {hi}",
        "hint.empty": "No data yet.  's' scans a network  ·  'w' analyzes a web log  "
                      "·  't' a .pcap  ·  'l' switches language.",
        "status.exported": "HTML report written to {p}",
        "detail.empty": "Select a finding to see details.",
        "detail.rule": "Rule", "detail.sev": "Severity", "detail.score": "Score",
        "detail.target": "Target", "detail.evidence": "Evidence",
        "detail.remediation": "Remediation", "detail.nodesc": "no description",
        "status.scanning": "scanning {t}…", "status.analyzing": "analyzing {t}…",
        "status.blocked": "BLOCKED: {e}", "status.error": "error: {e}",
        "bind.quit": "Quit", "bind.refresh": "Reload", "bind.scan": "Scan",
        "bind.traffic": "Traffic", "bind.weblog": "Web log", "bind.export": "Report",
        "bind.lang": "Language",
        "cli.need_pcap": "Provide --pcap or --iface",
        "cli.no_runs": "No saved runs.",
        "cli.report_written": "report written to {p}",
        "cli.app_help": "LuaNetSentinel — defensive network auditor (es/en via --lang)",
        "cli.epilog": (
            "Examples:\n"
            "  lns                          open the interactive TUI\n"
            "  lns scan 192.168.1.0/24      authorized scan + CVE\n"
            "  lns weblog access.log        attack signatures in web logs\n"
            "  lns traffic --pcap cap.pcap  traffic analysis\n"
            "  lns report -f html -o r.html HTML report of the latest run\n"
            "  lns lang en                  set the language (es|en)\n\n"
            "Language: --lang es|en, the LNS_LANG env var, or `lns lang`."),
    },
}


def t(key: str, **kw: object) -> str:
    """Translate a UI chrome string by key. Falls back to ES, then to the key."""
    s = UI[lang()].get(key) or UI["es"].get(key, key)
    return s.format(**kw) if kw else s


# --- Findings: ES = lo guardado (canónico); EN = catálogo por rule_id ---
class _Safe(dict):
    def __missing__(self, k: str) -> str:
        return "{" + k + "}"


def _drift_en(f: object) -> dict[str, str]:
    ev = getattr(f, "evidence", None) or {}
    tgt = getattr(f, "target", None) or {}
    desc = "Deviation from the reference state."
    if "ports" in ev:  # host nuevo sin baseline
        return {"title": "New host (no baseline)", "description": desc,
                "remediation": "Confirm the host and set a baseline if legitimate."}
    return {"title": f"New port {tgt.get('port')} vs baseline", "description": desc,
            "remediation": "Verify the service; update the baseline or close the port."}


def _cve_en(f: object) -> dict[str, str]:
    ev = getattr(f, "evidence", None) or {}
    p, v = ev.get("product", ""), ev.get("version", "")
    return {"title": f"Known CVEs in {p} {v}".strip(),
            "description": f"{ev.get('count', '?')} CVE with CVSS>={ev.get('min_cvss', '?')} "
                           "(NVD keyword match; verify exact version).",
            "remediation": f"Update {p} to a version without these CVEs."}


# value = dict de plantillas, o callable(finding)->dict. {placeholders} se rellenan
# desde evidence+target con format_map (claves ausentes se dejan literales).
FINDINGS_EN: dict[str, object] = {
    "ssh-exposed": {
        "title": "SSH exposed",
        "description": "Port 22 open and reachable.",
        "remediation": "Restrict via firewall/Tailscale; disable password auth."},
    "legacy-service": {
        "title": "Legacy/insecure service exposed",
        "description": "Unencrypted or remote-admin protocol exposed.",
        "remediation": "Replace with an encrypted equivalent (SSH/RDP-gateway) or close the port."},
    "tls-weak": {
        "title": "Weak TLS configuration",
        "description": "Obsolete protocols or ciphers detected by ssl-enum-ciphers.",
        "remediation": "Disable SSLv3/TLS1.0/1.1 and RC4/3DES/EXPORT ciphers; use TLS1.2+."},
    "tls-cert-expired": {
        "title": "Expired or invalid TLS certificate",
        "description": "ssl-cert reports an expired or self-signed certificate.",
        "remediation": "Renew the certificate with a trusted CA."},
    "cleartext-credentials": {
        "title": "Cleartext credentials",
        "description": "Authentication transmitted unencrypted (HTTP Basic, FTP, telnet).",
        "remediation": "Move to TLS/SSH; rotate the exposed credentials."},
    "dns-tunneling": {
        "title": "Possible DNS tunneling / DGA",
        "description": "DNS query with abnormally high entropy.",
        "remediation": "Inspect the source host; block the domain at the resolver."},
    "dns-long-label": {
        "title": "Suspiciously long DNS label",
        "description": "A DNS label >50 chars often indicates DNS exfiltration.",
        "remediation": "Review the source host's DNS traffic."},
    "sqli": {
        "title": "Possible SQL injection",
        "remediation": "Use parameterized queries; validate input."},
    "xss": {
        "title": "Possible XSS",
        "remediation": "Escape output; CSP headers."},
    "path-traversal": {
        "title": "Path traversal",
        "remediation": "Normalize and validate paths; allowlist."},
    "scanner-ua": {
        "title": "Scanner user-agent",
        "remediation": "Block/limit user-agents of known tools."},
    "error-spike": {
        "title": "4xx/5xx error spike per IP",
        "description": "One IP generates many errors: possible fuzzing/scanning.",
        "remediation": "Review the IP; consider rate-limit or temporary block."},
    "beaconing": {
        "title": "Periodic beaconing (possible C2)",
        "description": "Regular connections to the same destination: C2 pattern.",
        "remediation": "Isolate the source host and investigate the destination."},
    "arp-spoofing": {
        "title": "ARP spoofing detected",
        "description": "One IP replies with multiple MACs: ARP poisoning.",
        "remediation": "Check the LAN; pin static ARP entries on critical hosts."},
    "drift": _drift_en,
    "cve-known": _cve_en,
}


def tf(finding: object, field: str) -> str:
    """Translate a finding field at render time. ES → stored; EN → catalog."""
    stored = getattr(finding, field, "") or ""
    if lang() == "es":
        return stored
    entry = FINDINGS_EN.get(getattr(finding, "rule_id", None))
    if entry is None:  # regla custom sin traducción → deja el canónico
        return stored
    data = entry(finding) if callable(entry) else entry
    val = data.get(field)
    if val is None:
        return stored
    if "{" in val:
        ctx = _Safe(**(getattr(finding, "evidence", None) or {}),
                    **(getattr(finding, "target", None) or {}))
        val = val.format_map(ctx)
    return val


def translate(finding: object) -> None:
    """In-place translate a finding's title/description/remediation (render copies)."""
    t_, d_, r_ = tf(finding, "title"), tf(finding, "description"), tf(finding, "remediation")
    finding.title, finding.description, finding.remediation = t_, d_, r_


if __name__ == "__main__":
    from .finding import Finding

    set_lang("es")
    f = Finding(rule_id="ssh-exposed", source="scanner", severity="medium",
                category="exposure", title="SSH expuesto",
                description="Puerto 22 abierto y accesible.")
    assert tf(f, "title") == "SSH expuesto"          # ES = canónico
    set_lang("en")
    assert tf(f, "title") == "SSH exposed"            # EN = catálogo
    assert "Port 22" in tf(f, "description")
    cve = Finding(rule_id="cve-known", source="scanner", severity="high",
                  category="vulnerability", title="CVEs conocidos en OpenSSH 7.4",
                  evidence={"product": "OpenSSH", "version": "7.4", "count": 3, "min_cvss": 7.0})
    assert tf(cve, "title") == "Known CVEs in OpenSSH 7.4"   # dinámico
    assert "3 CVE with CVSS>=7.0" in tf(cve, "description")
    drift = Finding(rule_id="drift", source="scanner", severity="medium", category="drift",
                    title="Puerto nuevo 23 respecto al baseline", target={"host": "h", "port": 23})
    assert tf(drift, "title") == "New port 23 vs baseline"
    custom = Finding(rule_id="unknown-rule", source="x", severity="info",
                     category="c", title="algo")
    assert tf(custom, "title") == "algo"             # fallback al canónico
    set_lang("es")
    print("ok i18n")

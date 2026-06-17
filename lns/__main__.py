"""LuaNetSentinel CLI (typer). `lns` with no args -> TUI (later phase)."""
from __future__ import annotations

import typer

from .collectors import scanner
from .core import rules
from .core.scope import OutOfScope, Scope
from .core.store import Store
from .export import json_export

app = typer.Typer(add_completion=False, help="LuaNetSentinel — auditor de red defensivo")
rules_app = typer.Typer(help="Lista y testea reglas")
app.add_typer(rules_app, name="rules")


@app.callback(invoke_without_command=True)
def _root(ctx: typer.Context, db: str = "lns.db"):
    """Sin subcomando: abre la TUI interactiva."""
    if ctx.invoked_subcommand is None:
        from .tui.app import run
        run(db=db)


@app.command()
def scan(target: str, profile: str = typer.Option(None, help="perfil de scope"),
         db: str = "lns.db"):
    """Escaneo autorizado + reglas → run guardado."""
    rules.load_rules()
    try:
        scope = Scope.load(profile=profile)
        findings = scanner.scan(target, scope)
    except OutOfScope as e:
        typer.secho(f"BLOQUEADO: {e}", fg="red", err=True)
        raise typer.Exit(2)
    store = Store(db)
    run_id = store.new_run(scope=scope.profile)
    for f in findings:
        f.run_id = run_id
    store.save(findings)
    typer.echo(json_export.dumps(findings, run_id))


@app.command()
def traffic(pcap: str = typer.Option(None, help="archivo .pcap (offline)"),
            iface: str = typer.Option(None, help="interfaz para captura en vivo"),
            count: int = typer.Option(0, help="paquetes a capturar (0 = sin límite)"),
            db: str = "lns.db"):
    """Análisis de tráfico: --pcap <f> (offline) o --iface <if> (en vivo)."""
    from .collectors import traffic as tr
    if not pcap and not iface:
        typer.secho("Indica --pcap o --iface", fg="red", err=True)
        raise typer.Exit(2)
    packets = tr.read_pcap(pcap) if pcap else tr.live(iface, count=count)
    findings = tr.analyze(packets)
    store = Store(db)
    run_id = store.new_run(scope="traffic")
    for f in findings:
        f.run_id = run_id
    store.save(findings)
    typer.echo(json_export.dumps(findings, run_id))


@app.command()
def weblog(logfile: str, db: str = "lns.db"):
    """Auditoría de logs web (combined format) + firmas de ataque."""
    from .collectors import weblog as wl
    findings = wl.analyze(logfile)
    store = Store(db)
    run_id = store.new_run(scope="weblog")
    for f in findings:
        f.run_id = run_id
    store.save(findings)
    typer.echo(json_export.dumps(findings, run_id))


baseline_app = typer.Typer(help="Gestiona baseline y detecta drift")
app.add_typer(baseline_app, name="baseline")


@baseline_app.command("set")
def baseline_set(host: str, ports: str = typer.Option(..., help="ej: 22,80,443"),
                 db: str = "lns.db"):
    """Fija el baseline (puertos esperados) de un host."""
    Store(db).set_baseline(host, [int(p) for p in ports.split(",") if p.strip()])
    typer.echo(f"baseline fijado para {host}: {ports}")


@baseline_app.command("show")
def baseline_show(host: str = typer.Argument(None), db: str = "lns.db"):
    """Muestra el baseline de un host (o todos)."""
    import json
    store = Store(db)
    data = store.get_baseline(host) if host else store.all_baseline()
    typer.echo(json.dumps(data, indent=2, ensure_ascii=False))


@baseline_app.command("drift")
def baseline_drift(target: str, profile: str = typer.Option(None),
                   db: str = "lns.db"):
    """Escanea el objetivo y reporta drift respecto al baseline."""
    from .collectors import scanner
    from .core import baseline
    try:
        scope = Scope.load(profile=profile)
        scope.guard(target)
    except OutOfScope as e:
        typer.secho(f"BLOQUEADO: {e}", fg="red", err=True)
        raise typer.Exit(2)
    observed = scanner.observed_ports(scanner.run_nmap(target))
    findings = baseline.drift(Store(db), observed)
    typer.echo(json_export.dumps(findings))


@app.command()
def report(run: str, db: str = "lns.db"):
    """Genera informe JSON del run guardado."""
    import json
    rows = Store(db).findings(run)
    typer.echo(json.dumps({"run_id": run, "findings": rows},
                          indent=2, ensure_ascii=False))


@rules_app.command("list")
def rules_list():
    """Lista las reglas registradas."""
    for r in rules.load_rules().values():
        typer.echo(f"{r.id:24} {r.source:8} {r.severity:8} {r.title}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()

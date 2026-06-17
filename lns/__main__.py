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

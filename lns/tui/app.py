"""LuaNetSentinel TUI (textual) — Dashboard / Findings / Rules.

Reads the latest run from the store. Launch interactions (scan/traffic/weblog)
stay in the CLI for now; this is the read/drill-down console.
"""
from __future__ import annotations


from textual.app import App, ComposeResult
from textual.widgets import (DataTable, Footer, Header, Markdown, Static,
                             TabbedContent, TabPane)

from ..core import rules
from ..core.correlation import correlate
from ..core.finding import Finding
from ..core.store import Store

BANNER = "▓▓ LuaNetSentinel ▓▓  auditor de red defensivo · >IZ:: / Glitchbane"

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


class SentinelApp(App):
    CSS_PATH = "theme.tcss"
    TITLE = "LuaNetSentinel"
    BINDINGS = [("q", "quit", "Salir"), ("r", "refresh", "Recargar")]

    def __init__(self, db: str = "lns.db"):
        super().__init__()
        self.db = db
        self._findings: list[dict] = []
        self._run: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Dashboard", id="tab-dash"):
                yield Static(BANNER, id="banner")
                yield Static(id="summary")
                yield DataTable(id="risk")
            with TabPane("Findings", id="tab-find"):
                yield DataTable(id="findings")
                yield Markdown("Selecciona un finding para ver detalle.", id="detail")
            with TabPane("Rules", id="tab-rules"):
                yield DataTable(id="rules")
        yield Footer()

    def on_mount(self) -> None:
        for tid, cols in (("risk", ("Host", "Riesgo")),
                          ("findings", ("Sev", "Regla", "Host", "Título")),
                          ("rules", ("ID", "Fuente", "Sev", "Título"))):
            t = self.query_one(f"#{tid}", DataTable)
            t.cursor_type = "row"
            t.add_columns(*cols)
        self._fill_rules()
        self.action_refresh()

    def action_refresh(self) -> None:
        store = Store(self.db)
        self._run = store.latest_run()
        self._findings = store.findings(self._run) if self._run else []
        store.close()

        findings = [Finding(**d) for d in self._findings]
        risks = correlate(findings)

        summary = self.query_one("#summary", Static)
        summary.update(
            f"Run: {self._run or '—'}   ·   {len(self._findings)} findings   ·   "
            f"hosts en riesgo: {sum(1 for v in risks.values() if v >= 70)}")

        risk_t = self.query_one("#risk", DataTable)
        risk_t.clear()
        for host, r in sorted(risks.items(), key=lambda x: -x[1]):
            risk_t.add_row(host, str(r))

        find_t = self.query_one("#findings", DataTable)
        find_t.clear()
        for d in self._findings:
            find_t.add_row(SEV_ICON.get(d["severity"], "·"), d["rule_id"],
                           d["target"].get("host", "—"), d["title"])

    def _fill_rules(self) -> None:
        t = self.query_one("#rules", DataTable)
        for r in rules.load_rules().values():
            t.add_row(r.id, r.source, r.severity, r.title)

    def on_data_table_row_highlighted(self, event) -> None:
        if event.data_table.id != "findings":
            return
        idx = event.cursor_row
        if not (0 <= idx < len(self._findings)):
            return
        d = self._findings[idx]
        self.query_one("#detail", Markdown).update(
            f"### {SEV_ICON.get(d['severity'],'')} {d['title']}\n\n"
            f"**Regla:** `{d['rule_id']}`  ·  **Severidad:** {d['severity']}  "
            f"·  **Score:** {d['score']}\n\n"
            f"**Objetivo:** `{d['target']}`\n\n"
            f"{d['description'] or '_sin descripción_'}\n\n"
            f"**Evidencia:** `{d['evidence']}`\n\n"
            f"**Remediación:** {d['remediation'] or '—'}")


def run(db: str = "lns.db") -> None:
    SentinelApp(db=db).run()


if __name__ == "__main__":
    run()

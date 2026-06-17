"""LuaNetSentinel TUI (textual) — Dashboard / Findings / Rules.

Reads the latest run, and launches scan/traffic interactively from the
Dashboard input (scope guard runs first, in a worker thread so the UI never
blocks). Bilingual ES/EN: chrome via i18n.t(), findings via i18n.tf(); 'l'
toggles the language and recomposes. weblog stays CLI-only.
"""
from __future__ import annotations

import os
import sys

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Center, Vertical
from textual.screen import ModalScreen
from textual.widgets import (Button, DataTable, Footer, Header, Input, Label,
                             Markdown, Static, TabbedContent, TabPane)

from ..collectors import scanner
from ..core import i18n, rules
from ..core.correlation import correlate
from ..core.finding import Finding
from ..core.scope import OutOfScope, Scope
from ..core.store import Store

BANNER = "▓▓ LuaNetSentinel ▓▓  {sub} · >IZ:: / Glitchbane"

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


class LangScreen(ModalScreen[str]):
    """Primer-uso: elige idioma. Devuelve 'es' | 'en' al descartar."""
    DEFAULT_CSS = """
    LangScreen { align: center middle; }
    #langbox { width: auto; height: auto; padding: 2 4; border: round $accent;
               background: $panel; }
    #langbox Button { margin: 1 2; width: 16; }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="langbox"):
            yield Label("Elige idioma   ·   Choose language")
            with Center():
                yield Button("Español", id="es", variant="primary")
                yield Button("English", id="en")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id)


class SentinelApp(App):
    CSS_PATH = "theme.tcss"
    TITLE = "LuaNetSentinel"
    BINDINGS = [("q", "quit", i18n.t("bind.quit")),
                ("r", "refresh", i18n.t("bind.refresh")),
                ("s", "scan", i18n.t("bind.scan")),
                ("t", "traffic", i18n.t("bind.traffic")),
                ("w", "weblog", i18n.t("bind.weblog")),
                ("e", "export", i18n.t("bind.export")),
                ("l", "lang", i18n.t("bind.lang"))]

    def __init__(self, db: str = "lns.db"):
        super().__init__()
        self.db = db
        self._findings: list[dict] = []
        self._run: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane(i18n.t("tab.dashboard"), id="tab-dash"):
                yield Static(BANNER.format(sub=i18n.t("banner.subtitle")), id="banner")
                yield Input(placeholder=i18n.t("input.placeholder"), id="target")
                yield Static(id="summary")
                yield DataTable(id="risk")
            with TabPane(i18n.t("tab.findings"), id="tab-find"):
                yield DataTable(id="findings")
                yield Markdown(i18n.t("detail.empty"), id="detail")
            with TabPane(i18n.t("tab.rules"), id="tab-rules"):
                yield DataTable(id="rules")
        yield Footer()

    def on_mount(self) -> None:
        self._load()
        # primer-uso (sólo en terminal real): pregunta el idioma una vez
        if sys.stdout.isatty() and not i18n.configured() and not os.environ.get("LNS_LANG"):
            self.push_screen(LangScreen(), self._lang_chosen)

    @work
    async def _lang_chosen(self, code: str | None) -> None:
        if not code:
            return
        i18n.set_lang(code, persist=True)
        await self.recompose()
        self._load()

    def _load(self) -> None:
        """(Re)build tables + data — safe on first mount and after recompose."""
        cols = {"risk": ("col.host", "col.risk"),
                "findings": ("col.sev", "col.rule", "col.host", "col.title"),
                "rules": ("col.id", "col.source", "col.sev", "col.title")}
        for tid, keys in cols.items():
            t = self.query_one(f"#{tid}", DataTable)
            t.cursor_type = "row"
            if not t.columns:
                t.add_columns(*(i18n.t(k) for k in keys))
        self._fill_rules()
        self.action_refresh()

    async def action_lang(self) -> None:
        i18n.set_lang("en" if i18n.lang() == "es" else "es", persist=True)
        await self.recompose()  # reconstruye chrome en el nuevo idioma…
        self._load()            # …y repuebla columnas+datos sobre los nuevos widgets

    def action_refresh(self) -> None:
        store = Store(self.db)
        self._run = store.latest_run()
        self._findings = store.findings(self._run) if self._run else []
        store.close()

        findings = [Finding(**d) for d in self._findings]
        risks = correlate(findings)

        summary = i18n.t("summary", run=self._run or "—", n=len(self._findings),
                         hi=sum(1 for v in risks.values() if v >= 70))
        if not self._findings:  # onboarding: di al usuario qué hacer
            summary += "\n" + i18n.t("hint.empty")
        self.query_one("#summary", Static).update(summary)

        risk_t = self.query_one("#risk", DataTable)
        risk_t.clear()
        for host, r in sorted(risks.items(), key=lambda x: -x[1]):
            risk_t.add_row(host, str(r))

        find_t = self.query_one("#findings", DataTable)
        find_t.clear()
        for d, f in zip(self._findings, findings):
            find_t.add_row(SEV_ICON.get(d["severity"], "·"), d["rule_id"],
                           d["target"].get("host", "—"), i18n.tf(f, "title"))

    def _fill_rules(self) -> None:
        t = self.query_one("#rules", DataTable)
        for r in rules.load_rules().values():
            t.add_row(r.id, r.source, r.severity, r.title)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "target":
            self.action_scan()  # Enter = caso común (escaneo)

    def action_scan(self) -> None:
        target = self.query_one("#target", Input).value.strip()
        if not target:
            return
        scope = Scope.load()  # guard runs inside scanner.scan, before nmap
        # ponytail: no enriquece CVE como el `scan` del CLI; añadir si se pide.
        self._job(i18n.t("status.scanning", t=target), scope.profile,
                  lambda rid: scanner.scan(target, scope, rid))

    def action_traffic(self) -> None:
        pcap = self.query_one("#target", Input).value.strip()
        if not pcap:
            return
        from ..collectors import traffic as tr
        self._job(i18n.t("status.analyzing", t=pcap), "traffic",
                  lambda rid: tr.analyze(tr.read_pcap(pcap), rid))

    def action_weblog(self) -> None:
        path = self.query_one("#target", Input).value.strip()
        if not path:
            return
        from ..collectors import weblog as wl
        self._job(i18n.t("status.analyzing", t=path), "weblog",
                  lambda rid: wl.analyze(path, rid))

    def action_export(self) -> None:
        """Exporta el run actual a informe.html (en el idioma activo)."""
        if not self._run:
            return
        from pathlib import Path

        from ..export import html
        rows = Store(self.db).findings(self._run)
        out = html.to_html([Finding(**r) for r in rows], run_id=self._run)
        path = "informe.html"
        Path(path).write_text(out)
        self.query_one("#summary", Static).update(i18n.t("status.exported", p=path))

    @work(thread=True, exclusive=True)
    def _job(self, label: str, scope_name: str, finder) -> None:
        """Run a blocking collector off the UI thread, persist, refresh."""
        self.call_from_thread(self.query_one("#summary", Static).update, label)
        try:
            rules.load_rules()
            store = Store(self.db)
            run_id = store.new_run(scope=scope_name)
            findings = finder(run_id)
            store.save(findings)
            store.close()
        except OutOfScope as e:
            self.call_from_thread(self.query_one("#summary", Static).update,
                                  i18n.t("status.blocked", e=e))
            return
        except Exception as e:
            self.call_from_thread(self.query_one("#summary", Static).update,
                                  i18n.t("status.error", e=e))
            return
        self.call_from_thread(self.action_refresh)

    def on_data_table_row_highlighted(self, event) -> None:
        if event.data_table.id != "findings":
            return
        idx = event.cursor_row
        if not (0 <= idx < len(self._findings)):
            return
        d = self._findings[idx]
        f = Finding(**d)
        self.query_one("#detail", Markdown).update(
            f"### {SEV_ICON.get(d['severity'],'')} {i18n.tf(f,'title')}\n\n"
            f"**{i18n.t('detail.rule')}:** `{d['rule_id']}`  ·  "
            f"**{i18n.t('detail.sev')}:** {d['severity']}  ·  "
            f"**{i18n.t('detail.score')}:** {d['score']}\n\n"
            f"**{i18n.t('detail.target')}:** `{d['target']}`\n\n"
            f"{i18n.tf(f,'description') or '_' + i18n.t('detail.nodesc') + '_'}\n\n"
            f"**{i18n.t('detail.evidence')}:** `{d['evidence']}`\n\n"
            f"**{i18n.t('detail.remediation')}:** {i18n.tf(f,'remediation') or '—'}")


def run(db: str = "lns.db") -> None:
    SentinelApp(db=db).run()


if __name__ == "__main__":
    run()

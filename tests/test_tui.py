"""TUI smoke test — mounts the app against a seeded store, no crash.

textual's run_test() is async; we drive it via asyncio.run to avoid needing
pytest-asyncio. The logic the TUI calls is tested elsewhere; this checks wiring.
"""
import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.widgets import DataTable, Static

from lns.core import i18n
from lns.core.finding import Finding
from lns.core.store import Store
from lns.tui.app import LangScreen, SentinelApp

ACCESS_LOG = str(Path(__file__).parent / "fixtures" / "access.log")


@pytest.fixture(autouse=True)
def _no_first_run(monkeypatch):
    # evita que el modal de primer-uso se auto-muestre y se coma las teclas
    monkeypatch.setattr(i18n, "configured", lambda: True)


def _seed(path):
    s = Store(path)
    rid = s.new_run(scope="home")
    f = Finding(rule_id="ssh-exposed", source="scanner", severity="medium",
                category="exposure", title="SSH expuesto", score=50, run_id=rid,
                target={"host": "192.168.1.10", "port": 22},
                evidence={"state": "open"})
    s.save([f])
    s.close()


def test_tui_mounts_and_loads(tmp_path):
    db = str(tmp_path / "t.db")
    _seed(db)

    async def _run():
        app = SentinelApp(db=db)
        async with app.run_test() as pilot:
            await pilot.pause()
            # the seeded finding made it into the dashboard tables
            assert len(app._findings) == 1
            assert app._run is not None

    asyncio.run(_run())


def test_tui_scan_persists_and_refreshes(tmp_path, monkeypatch):
    """Typing a target + 's' runs scanner.scan in a worker, saves, refreshes."""
    db = str(tmp_path / "t.db")
    f = Finding(rule_id="x", source="scanner", severity="high",
                category="exposure", title="boom", target={"host": "10.0.0.1"})

    def fake_scan(target, scope, rid):
        f.run_id = rid
        return [f]

    monkeypatch.setattr("lns.tui.app.scanner.scan", fake_scan)
    monkeypatch.setattr("lns.tui.app.Scope.load",
                        classmethod(lambda cls, **k: SimpleNamespace(profile="test")))

    async def _run():
        app = SentinelApp(db=db)
        async with app.run_test() as pilot:
            app.query_one("#target").value = "10.0.0.0/24"
            app.action_scan()
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#findings", DataTable).row_count == 1

    asyncio.run(_run())


def test_tui_language_toggle(tmp_path, monkeypatch):
    """'l' alterna ES↔EN y recompone: el título del finding cambia de idioma."""
    db = str(tmp_path / "t.db")
    _seed(db)  # ssh-exposed → "SSH expuesto"
    monkeypatch.setattr(i18n, "_SETTINGS", tmp_path / "settings.yaml")
    i18n.set_lang("es")

    async def _run():
        app = SentinelApp(db=db)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert app.query_one("#findings", DataTable).get_row_at(0)[3] == "SSH expuesto"
            await pilot.press("l")
            await pilot.pause()
            assert app.query_one("#findings", DataTable).get_row_at(0)[3] == "SSH exposed"

    asyncio.run(_run())
    i18n.set_lang("es")


def test_tui_weblog_action_populates(tmp_path):
    """'w' analiza un log web (fixture) y rellena la tabla de hallazgos."""
    db = str(tmp_path / "t.db")

    async def _run():
        app = SentinelApp(db=db)
        async with app.run_test() as pilot:
            app.query_one("#target").value = ACCESS_LOG
            await pilot.press("w")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert app.query_one("#findings", DataTable).row_count >= 1

    asyncio.run(_run())


def test_tui_export_writes_html(tmp_path, monkeypatch):
    """'e' exporta el run actual a informe.html."""
    db = str(tmp_path / "t.db")
    _seed(db)
    monkeypatch.chdir(tmp_path)  # informe.html cae en tmp

    async def _run():
        app = SentinelApp(db=db)
        async with app.run_test() as pilot:
            await pilot.pause()
            await pilot.press("e")
            await pilot.pause()

    asyncio.run(_run())
    assert (tmp_path / "informe.html").exists()


def test_tui_first_run_language_modal(tmp_path, monkeypatch):
    """El modal de primer-uso fija el idioma y recompone la UI a EN."""
    db = str(tmp_path / "t.db")
    _seed(db)  # ssh-exposed → "SSH expuesto"
    monkeypatch.setattr(i18n, "_SETTINGS", tmp_path / "settings.yaml")
    i18n.set_lang("es")

    async def _run():
        app = SentinelApp(db=db)
        async with app.run_test() as pilot:
            await pilot.pause()
            app.push_screen(LangScreen(), app._lang_chosen)
            await pilot.pause()
            await pilot.click("#en")
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert i18n.lang() == "en"
            assert app.query_one("#findings", DataTable).get_row_at(0)[3] == "SSH exposed"

    asyncio.run(_run())
    i18n.set_lang("es")


def test_tui_empty_state_hint(tmp_path):
    """Sin datos, el resumen muestra la pista de onboarding."""
    db = str(tmp_path / "empty.db")

    async def _run():
        app = SentinelApp(db=db)
        async with app.run_test() as pilot:
            await pilot.pause()
            assert "'s'" in str(app.query_one("#summary", Static).render())

    asyncio.run(_run())

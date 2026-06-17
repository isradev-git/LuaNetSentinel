"""TUI smoke test — mounts the app against a seeded store, no crash.

textual's run_test() is async; we drive it via asyncio.run to avoid needing
pytest-asyncio. The logic the TUI calls is tested elsewhere; this checks wiring.
"""
import asyncio
from types import SimpleNamespace

from textual.widgets import DataTable

from lns.core.finding import Finding
from lns.core.store import Store
from lns.tui.app import SentinelApp


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

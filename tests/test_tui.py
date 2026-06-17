"""TUI smoke test — mounts the app against a seeded store, no crash.

textual's run_test() is async; we drive it via asyncio.run to avoid needing
pytest-asyncio. The logic the TUI calls is tested elsewhere; this checks wiring.
"""
import asyncio

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

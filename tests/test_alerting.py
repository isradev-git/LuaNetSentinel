
from lns.alerting import email_smtp, telegram
from lns.alerting.notify import Notifier
from lns.core.finding import Finding
from lns.core.store import Store
from lns.core.watch import watch


def mk(sev, host="h", port=22):
    return Finding(rule_id="ssh-exposed", source="scanner", severity=sev,
                   category="exposure", title="SSH", score=0,
                   target={"host": host, "port": port})


def test_threshold_filters_below():
    rec = []
    n = Notifier(min_severity="high", channels=[rec.append])
    assert n.notify([mk("low"), mk("medium")]) == 0
    assert rec == []


def test_single_digest_not_per_finding():
    rec = []
    n = Notifier(min_severity="high", channels=[rec.append])
    assert n.notify([mk("high", port=22), mk("critical", port=23)]) == 2
    assert len(rec) == 1  # one batched message


def test_dedup_survives_new_ids():
    # same content, default ts -> different Finding.id each call
    rec = []
    n = Notifier(min_severity="high", channels=[rec.append])
    assert n.notify([mk("high")]) == 1
    assert n.notify([mk("high")]) == 0  # content key dedup, not id
    assert len(rec) == 1


def test_channels_disabled_without_env(monkeypatch):
    for k in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "SMTP_HOST", "SMTP_TO"):
        monkeypatch.delenv(k, raising=False)
    assert telegram.send("x") is False
    assert email_smtp.send("x") is False


def test_watch_alerts_once_across_cycles():
    rec = []
    n = Notifier(min_severity="high", channels=[rec.append])
    watch(lambda rid: [mk("high")], Store(":memory:"), n,
          interval=0, cycles=3, sleep=lambda _: None)
    assert len(rec) == 1  # not 3 — anti-spam holds

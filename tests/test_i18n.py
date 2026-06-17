"""i18n render: ES por defecto (canónico), EN traduce findings en la salida.
El motor (tf, plantillas dinámicas, fallback) se prueba en lns/core/i18n.py."""
import json

import pytest

from lns.core import i18n
from lns.core.finding import Finding
from lns.export import json_export


@pytest.fixture(autouse=True)
def _reset_lang():
    yield
    i18n.set_lang("es")  # no contaminar el resto de la suite


def _ssh():
    return Finding(rule_id="ssh-exposed", source="scanner", severity="medium",
                   category="exposure", title="SSH expuesto",
                   description="Puerto 22 abierto y accesible.",
                   remediation="Restringe por firewall.", target={"host": "h"})


def test_json_default_es():
    i18n.set_lang("es")
    out = json.loads(json_export.dumps([_ssh()], "r"))
    assert out["findings"][0]["title"] == "SSH expuesto"


def test_json_en_translates_findings():
    i18n.set_lang("en")
    f = _ssh()
    out = json.loads(json_export.dumps([f], "r"))
    assert out["findings"][0]["title"] == "SSH exposed"
    assert "Port 22" in out["findings"][0]["description"]
    assert f.title == "SSH expuesto"  # el Finding guardado NO se muta


def test_unknown_rule_keeps_canonical_in_en():
    i18n.set_lang("en")
    f = Finding(rule_id="custom-x", source="x", severity="info",
                category="c", title="algo propio")
    out = json.loads(json_export.dumps([f], "r"))
    assert out["findings"][0]["title"] == "algo propio"

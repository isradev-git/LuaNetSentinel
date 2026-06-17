"""Rule engine: @rule decorator + plugin auto-discovery.

A rule is a function taking a Context (attribute bag) returning bool or
(bool, evidence_dict). Drop a file in rules/<source>/ = new detection.
"""
from __future__ import annotations

import importlib.util
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

from .finding import Finding


class Context(SimpleNamespace):
    """Attribute bag for rules. Missing fields read as None, not AttributeError,
    so a rule can safely read ctx.qname on a packet that has no qname."""

    def __getattr__(self, _name: str) -> Any:
        return None


@dataclass
class Rule:
    id: str
    source: str
    severity: str
    category: str
    title: str
    fn: Callable[[Any], Any]
    description: str = ""
    remediation: str = ""


_REGISTRY: dict[str, Rule] = {}
_LOADED: set[str] = set()  # paths already imported, so load_rules is idempotent


def rule(*, id: str, source: str, severity: str, category: str, title: str,
         description: str = "", remediation: str = ""):
    def deco(fn: Callable[[Any], Any]) -> Callable[[Any], Any]:
        if id in _REGISTRY:
            raise ValueError(f"duplicate rule id {id!r}")
        _REGISTRY[id] = Rule(id, source, severity, category, title, fn,
                             description, remediation)
        return fn
    return deco


def registry() -> dict[str, Rule]:
    return _REGISTRY


def load_rules(root: str | Path = "rules") -> dict[str, Rule]:
    """Import every rules/**/*.py so their @rule decorators register."""
    root = Path(root)
    for path in sorted(root.glob("*/*.py")):
        key = str(path.resolve())
        if path.name.startswith("_") or key in _LOADED:
            continue
        _LOADED.add(key)
        spec = importlib.util.spec_from_file_location(path.stem, path)
        if spec and spec.loader:
            spec.loader.exec_module(importlib.util.module_from_spec(spec))
    return _REGISTRY


def apply(ctx: Any, source: str, run_id: str = "") -> list[Finding]:
    """Run every rule for `source` against ctx, collect Findings."""
    out: list[Finding] = []
    for r in _REGISTRY.values():
        if r.source != source:
            continue
        res = r.fn(ctx)
        hit, evidence = res if isinstance(res, tuple) else (res, {})
        if hit:
            out.append(Finding(
                rule_id=r.id, source=r.source, severity=r.severity,
                category=r.category, title=r.title, description=r.description,
                remediation=r.remediation, evidence=evidence or {},
                target=_target_from(ctx), run_id=run_id))
    return out


def _target_from(ctx: Any) -> dict[str, Any]:
    return {k: getattr(ctx, k, None) for k in ("host", "port", "proto")}


if __name__ == "__main__":
    _REGISTRY.clear()

    @rule(id="t-open", source="scanner", severity="medium",
          category="exposure", title="open port")
    def _t(ctx):
        return ctx.port == 22, {"state": ctx.state}

    findings = apply(Context(host="h", port=22, proto="tcp", state="open"),
                     "scanner", run_id="r1")
    assert len(findings) == 1
    assert findings[0].evidence == {"state": "open"}
    assert findings[0].target["host"] == "h"
    assert apply(Context(host="h", port=80, proto="tcp"), "scanner") == []
    print("ok", findings[0].to_dict())

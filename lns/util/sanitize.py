"""Sanitize evidence (banners, qnames, user-agents) before HTML/JSON export.

A malicious banner must not inject the report. We strip control chars and
cap length; jinja2 autoescape handles HTML entities downstream.
"""
from __future__ import annotations

from typing import Any

MAX_LEN = 512


def clean(value: Any) -> Any:
    if isinstance(value, str):
        # drop control chars except tab/newline, then cap
        s = "".join(c for c in value if c == "\t" or c == "\n" or ord(c) >= 32)
        return s[:MAX_LEN]
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


if __name__ == "__main__":
    assert clean("ok") == "ok"
    assert clean("a\x00b\x07c") == "abc"  # null + bell stripped
    assert clean("x" * 1000) == "x" * MAX_LEN
    assert clean({"banner": "ssh\x00<script>"}) == {"banner": "ssh<script>"}
    print("ok")

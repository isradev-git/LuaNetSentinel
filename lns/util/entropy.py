"""Shannon entropy — used by DNS tunneling / DGA detection."""
from __future__ import annotations

import math
from collections import Counter


def shannon(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


if __name__ == "__main__":
    assert shannon("") == 0.0
    assert shannon("aaaa") == 0.0
    # random-looking string has high entropy
    assert shannon("a8f3kd9xqz1mwp7v") > 3.5
    print("ok")

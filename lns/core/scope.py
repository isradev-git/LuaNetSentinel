"""Scope guard — the engine only acts on authorized CIDRs.

Non-negotiable: out-of-scope targets are rejected before anything launches.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml


class OutOfScope(Exception):
    pass


class Scope:
    def __init__(self, profile: str, cidrs: list[str]):
        self.profile = profile
        self.networks = [ipaddress.ip_network(c, strict=False) for c in cidrs]

    @classmethod
    def load(cls, path: str | Path = "config/scope.yaml",
             profile: str | None = None) -> "Scope":
        data = yaml.safe_load(Path(path).read_text())
        profile = profile or data["active"]
        prof = data["profiles"][profile]
        return cls(profile, prof["cidrs"])

    def contains(self, target: str) -> bool:
        """True if every host implied by target falls inside authorized CIDRs."""
        try:
            net = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False  # hostnames not resolvable to scope -> reject
        return any(net.subnet_of(n) for n in self.networks)

    def guard(self, target: str) -> None:
        if not self.contains(target):
            raise OutOfScope(
                f"{target!r} fuera del scope {self.profile!r} "
                f"({[str(n) for n in self.networks]})")


if __name__ == "__main__":
    s = Scope("home", ["192.168.1.0/24"])
    assert s.contains("192.168.1.10")
    assert s.contains("192.168.1.0/24")
    assert not s.contains("10.0.0.1")
    assert not s.contains("evil.example.com")  # hostname -> reject
    try:
        s.guard("8.8.8.8")
        assert False
    except OutOfScope:
        pass
    print("ok")

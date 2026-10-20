"""The offline harness must reject inadequate isolation and misleading verdicts."""

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location(
    "agent_offline", Path(__file__).resolve().parents[1] / "tools/check_agent_record_offline.py",
)
assert SPEC and SPEC.loader
offline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(offline)


def test_rejects_external_interface(monkeypatch):
    monkeypatch.setattr(offline.socket, "if_nameindex", lambda: [(1, "lo"), (2, "eth0")])
    monkeypatch.setattr(offline.Path, "read_text", lambda _: "Iface\tDestination\n")
    with pytest.raises(RuntimeError, match="loopback"):
        offline.network_control()


def test_rejects_external_route(monkeypatch):
    monkeypatch.setattr(offline.socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(offline.Path, "read_text", lambda _: "Iface\tDestination\nlo\t00000000\n")
    with pytest.raises(RuntimeError, match="IPv4 routes"):
        offline.network_control()


@pytest.mark.parametrize("exit_code,ok,signature,asset,canonical", [
    (2, True, True, True, None),  # Usage error is not successful verification.
    (0, False, True, True, None),
    (0, True, False, True, None),
    (0, True, True, False, None),
    (0, True, True, True, True),  # Local input must not claim canonical retrieval.
])
def test_rejects_inconsistent_original_verdict(
    monkeypatch, exit_code, ok, signature, asset, canonical,
):
    monkeypatch.setattr(offline, "network_control", lambda: {"test": "mocked"})
    monkeypatch.setattr(offline.platform, "system", lambda: "Linux")
    monkeypatch.setattr(offline.platform, "machine", lambda: "x86_64")

    def fake_run(command, **kwargs):
        if "verify" in command:
            return SimpleNamespace(returncode=exit_code, stderr="", stdout=json.dumps({
                "ok": ok, "checks": {
                    "signature": signature, "asset": asset, "canonical": canonical,
                },
            }))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(offline, "run", fake_run)
    with pytest.raises(RuntimeError, match="original: unexpected result"):
        offline.verify_inside()

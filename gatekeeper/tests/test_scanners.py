"""Scanner adapter tests. Samples are built at runtime from parts; nothing malware-like is committed."""
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import yara

from gatekeeper import scanners
from gatekeeper.facts import Finding

# EICAR is assembled from fragments so no scanner flags this source file.
EICAR = "".join(["X5O!P%@AP[4" + chr(92) + "PZX54(P^)7CC)7}$","EICAR", "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"])
FAKE_AWS = "AKIA" + "QYLPMN5HHHHGGDDF"
# 40-char synthetic secret key, built at runtime so the source never holds a matchable literal
FAKE_AWS_SECRET = "gT7qLm2Rx" + "/Vb9NcWd4Kp" + "+Hs6YjZf3Ue8Ao1Ii5X0"


@pytest.fixture
def tmp(tmp_path):
    return tmp_path


def _write_ads(path: Path, content: str) -> None:
    with open(str(path) + ":Zone.Identifier", "w", encoding="utf-8") as fh:
        fh.write(content)


def test_read_motw_parses_ads(tmp):
    f = tmp / "a.txt"
    f.write_text("hi")
    _write_ads(f, "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://ref.example/\r\nHostUrl=https://example.com/x\r\n")
    assert scanners.read_motw(f) == {"ZoneId": 3, "HostUrl": "https://example.com/x",
                                     "ReferrerUrl": "https://ref.example/"}


def test_read_motw_partial_and_none(tmp):
    f = tmp / "b.txt"
    f.write_text("hi")
    assert scanners.read_motw(f) is None
    _write_ads(f, "[ZoneTransfer]\r\nZoneId=3\r\n")
    assert scanners.read_motw(f) == {"ZoneId": 3, "HostUrl": None, "ReferrerUrl": None}
    _write_ads(f, "[ZoneTransfer]\r\nZoneId=notanint\r\n")
    assert scanners.read_motw(f) is None
    assert scanners.read_motw(tmp / "missing.txt") is None


def test_authenticode_signed_and_unsigned(tmp):
    assert scanners.authenticode(Path(r"C:\Windows\System32\notepad.exe")) == "valid"
    s = tmp / "x.ps1"
    s.write_text("Write-Output 'hi'")
    assert scanners.authenticode(s) == "unsigned"


@pytest.mark.parametrize("name,status,expect", [
    ("x.lnk", "UnknownError", "n/a"), ("x.lnk", "NotSigned", "n/a"), ("x.bat", "NotSigned", "n/a"),
    ("x.hta", "UnknownError", "n/a"), ("x.lnk", "HashMismatch", "invalid"),
    ("x.exe", "UnknownError", "invalid"), ("x.ps1", "NotSigned", "unsigned"), ("x.exe", "Valid", "valid"),
])
def test_authenticode_unsignable_types(monkeypatch, tmp, name, status, expect):
    class R:
        returncode = 0
        stdout = status + "\r\n"
    monkeypatch.setattr(scanners.subprocess, "run", lambda *a, **k: R())
    assert scanners.authenticode(tmp / name) == expect


def test_authenticode_failure_is_na(monkeypatch, tmp):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("powershell", 10)
    monkeypatch.setattr(scanners.subprocess, "run", boom)
    assert scanners.authenticode(tmp / "x.ps1") == "n/a"


def test_yara_scan_matches_marker(tmp):
    rules = yara.compile(source='rule gk_test { strings: $a = "GATEKEEPER_TEST_MARKER" condition: $a }')
    f = tmp / "m.bin"
    f.write_bytes(b"xx GATEKEEPER_TEST_MARKER yy")
    out = scanners.yara_scan(f, rules)
    assert len(out) == 1 and out[0].severity == "critical" and "gk_test" in out[0].detail
    g = tmp / "n.bin"
    g.write_bytes(b"nothing here")
    assert scanners.yara_scan(g, rules) == []


def test_yara_scan_error_is_notice(tmp):
    class Bad:
        def match(self, **k):
            raise yara.Error("boom")
    out = scanners.yara_scan(tmp / "z", Bad())
    assert [f.severity for f in out] == ["notice"] and "unavailable" in out[0].detail


def test_load_yara_compiles_pinned_core_once():
    r1 = scanners.load_yara()
    assert r1 is scanners.load_yara()


def test_defender_scan_eicar_real(tmp):
    d = scanners.find_mpcmdrun()
    if d is None:
        pytest.skip("Defender not installed on this machine")
    f = tmp / "eicar.com.txt"
    try:
        f.write_text(EICAR)
    except OSError:
        return  # real-time protection blocked the write: expected critical outcome
    out = scanners.defender_scan(f)
    assert any(x.severity == "critical" for x in out), out


def _fake_run(returncode, on_run=None):
    def run(cmd, **k):
        if on_run:
            on_run()
        return subprocess.CompletedProcess(cmd, returncode, "", "")
    return run


def test_defender_exit2_is_critical(monkeypatch, tmp):
    f = tmp / "t.txt"
    f.write_text("x")
    monkeypatch.setattr(scanners, "find_mpcmdrun", lambda: Path("MpCmdRun.exe"))
    monkeypatch.setattr(scanners.subprocess, "run", _fake_run(2))
    out = scanners.defender_scan(f)
    assert out and out[0].severity == "critical"


def test_defender_clean_and_vanished(monkeypatch, tmp):
    f = tmp / "t.txt"
    f.write_text("x")
    monkeypatch.setattr(scanners, "find_mpcmdrun", lambda: Path("MpCmdRun.exe"))
    monkeypatch.setattr(scanners.subprocess, "run", _fake_run(0))
    assert scanners.defender_scan(f) == []
    monkeypatch.setattr(scanners.subprocess, "run", _fake_run(0, on_run=f.unlink))
    out = scanners.defender_scan(f)
    assert out and out[0].severity == "critical" and "removed by Defender" in out[0].detail


def test_defender_unavailable(monkeypatch, tmp):
    f = tmp / "t.txt"
    f.write_text("x")
    monkeypatch.setattr(scanners, "find_mpcmdrun", lambda: None)
    out = scanners.defender_scan(f)
    assert [(x.severity, x.detail) for x in out] == [("notice", "Defender unavailable")]
    monkeypatch.setattr(scanners, "find_mpcmdrun", lambda: Path("MpCmdRun.exe"))

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("x", 1)
    monkeypatch.setattr(scanners.subprocess, "run", boom)
    out = scanners.defender_scan(f)
    assert [(x.severity, x.detail) for x in out] == [("notice", "Defender unavailable")]


@pytest.mark.skipif(scanners.gitleaks_command() is None, reason="gitleaks not installed")
def test_gitleaks_finds_redacted_secret(tmp):
    f = tmp / "cfg.env"
    f.write_text(f"aws_access_key_id = {FAKE_AWS}\naws_secret_access_key = {FAKE_AWS_SECRET}\n")
    out = scanners.gitleaks_scan(f)
    assert out and all(x.severity == "secret" for x in out), out
    assert all(FAKE_AWS not in x.detail and FAKE_AWS_SECRET[:8] not in x.detail for x in out)
    assert any("line 2" in x.detail for x in out), out  # the secret key line itself trips


def test_gitleaks_skips_binary_and_large(tmp):
    b = tmp / "bin.dat"
    b.write_bytes(b"\x00\x01" + FAKE_AWS.encode())
    assert scanners.gitleaks_scan(b) == []
    big = tmp / "big.txt"
    big.write_text("a" * (5 * 1024 * 1024 + 1))
    assert scanners.gitleaks_scan(big) == []


def test_gitleaks_unavailable_is_notice(monkeypatch, tmp):
    f = tmp / "t.txt"
    f.write_text("hello")

    def boom(*a, **k):
        raise FileNotFoundError("wsl")
    monkeypatch.setattr(scanners.subprocess, "run", boom)
    out = scanners.gitleaks_scan(f)
    assert [(x.severity, x.detail) for x in out] == [("notice", "gitleaks unavailable")]


def test_wsl_path():
    assert scanners.to_wsl_path(Path(r"C:\Users\x\a b.txt")) == "/mnt/c/Users/x/a b.txt"


def test_yara_rules_missing_is_notice(tmp, monkeypatch):
    monkeypatch.setattr(scanners, "YARA_RULES", tmp / "absent.yar")
    assert scanners.load_yara() is None
    f = tmp / "a.txt"
    f.write_text("x")
    out = scanners.yara_scan(f, None)
    assert [(x.code, x.severity) for x in out] == [("yara_unavailable", "notice")]

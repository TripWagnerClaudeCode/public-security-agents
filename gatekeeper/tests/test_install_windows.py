from gatekeeper.config import Config
import types
import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from gatekeeper import install_windows as iw
from gatekeeper import serve

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def test_task_xml():
    xml = iw.task_xml(Path(r"C:\venv\Scripts\pythonw.exe"), Path(r"C:\Users\me\.gatekeeper\service"), r"PC\me")
    root = ET.fromstring(xml)
    assert root.find("t:Triggers/t:LogonTrigger/t:UserId", NS).text == r"PC\me"
    p = root.find("t:Principals/t:Principal", NS)
    assert p.find("t:LogonType", NS).text == "InteractiveToken"
    assert p.find("t:RunLevel", NS).text == "LeastPrivilege"
    s = root.find("t:Settings", NS)
    assert s.find("t:Hidden", NS).text == "true"
    assert s.find("t:ExecutionTimeLimit", NS).text == "PT0S"
    assert s.find("t:MultipleInstancesPolicy", NS).text == "IgnoreNew"
    assert s.find("t:RestartOnFailure/t:Interval", NS).text == "PT1M"
    assert int(s.find("t:RestartOnFailure/t:Count", NS).text) >= 3
    assert s.find("t:DisallowStartIfOnBatteries", NS).text == "false"
    ex = root.find("t:Actions/t:Exec", NS)
    assert ex.find("t:Command", NS).text == r"C:\venv\Scripts\pythonw.exe"
    assert ex.find("t:Arguments", NS).text == "-m gatekeeper serve"
    assert ex.find("t:WorkingDirectory", NS).text == r"C:\Users\me\.gatekeeper\service"


def test_task_xml_escapes():
    xml = iw.task_xml(Path(r"C:\a&b\pythonw.exe"), Path(r"C:\w"), "PC\\me")
    assert ET.fromstring(xml).find("t:Actions/t:Exec/t:Command", NS).text == r"C:\a&b\pythonw.exe"










def test_single_instance_lock(tmp_path):
    a = serve.acquire_lock(tmp_path / "serve.lock")
    assert a is not None
    assert serve.acquire_lock(tmp_path / "serve.lock") is None
    a.close()
    b = serve.acquire_lock(tmp_path / "serve.lock")
    assert b is not None
    b.close()


def test_main_module_dispatches(monkeypatch):
    import gatekeeper.__main__ as m
    got = []
    monkeypatch.setattr(serve, "main", lambda argv=None: got.append(argv) or 0)
    assert m.main(["serve"]) == 0
    assert got == [[]]
    assert m.main(["bogus"]) == 2


def test_install_registers_and_starts_task(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(iw, "load_or_create_key", lambda cfg: "k")
    monkeypatch.setattr(iw, "archive_head", lambda repo: b"tar")
    monkeypatch.setattr(iw, "extract_snapshot", lambda b, app: app)
    monkeypatch.setattr(iw, "register_task", lambda py, wd, user: calls.append(("register", wd)))

    def fake_schtasks(*args, check=True):
        calls.append(("schtasks",) + args[:1])
        return types.SimpleNamespace(returncode=1, stdout="", stderr="")
    monkeypatch.setattr(iw, "_schtasks", fake_schtasks)
    py = tmp_path / "pythonw.exe"
    py.write_text("")
    src = tmp_path / "ntfy-src.json"
    src.write_text('{"url": "https://ntfy.example/", "topic": "t", "token": "x", "extra": 1}')
    cfg = Config(home=tmp_path / "gk")
    out = iw.install(cfg, repo=tmp_path, pythonw=py, ntfy_config=src)
    assert calls[-1] == ("schtasks", "/Run") and ("register", cfg.home / "service") in calls
    assert out["ntfy"].endswith("ntfy.json")
    import json
    assert json.loads((cfg.home / "ntfy.json").read_text()) == {"url": "https://ntfy.example/", "topic": "t", "token": "x"}


def test_install_without_ntfy_says_pushes_off(tmp_path, monkeypatch):
    monkeypatch.setattr(iw, "load_or_create_key", lambda cfg: "k")
    monkeypatch.setattr(iw, "archive_head", lambda repo: b"tar")
    monkeypatch.setattr(iw, "extract_snapshot", lambda b, app: app)
    monkeypatch.setattr(iw, "register_task", lambda *a: None)
    monkeypatch.setattr(iw, "_schtasks", lambda *a, check=True: types.SimpleNamespace(returncode=1, stdout="", stderr=""))
    py = tmp_path / "pythonw.exe"
    py.write_text("")
    out = iw.install(Config(home=tmp_path / "gk"), repo=tmp_path, pythonw=py)
    assert out["ntfy"].startswith("not configured")


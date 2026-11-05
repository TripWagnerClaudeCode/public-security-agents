import hashlib
import json
import socket
import threading
import time
import urllib.request

import pytest

from gatekeeper import backfill, endpoint, notify
from gatekeeper.config import Config
from gatekeeper.facts import Finding
from gatekeeper.state import State
from gatekeeper.watcher import Scanners


class Calls:
    def __init__(self):
        self.defender = []


def make_scanners(calls):
    def yara(p):
        return [Finding("yara_match", "YARA rule matched: TEST_RULE", "critical")] if p.name == "bad.pdf" and b"harmless" not in p.read_bytes() else []

    def gitleaks(p):
        if p.name == "creds.env":
            return [Finding("secret_in_file", "aws-access-token at line 1 (redacted)", "secret")]
        return []

    def defender(p):
        calls.defender.append(p.name)
        return []

    return Scanners(motw=lambda p: None, signature=lambda p: "unsigned", defender=defender,
                    yara=yara, gitleaks=gitleaks)


@pytest.fixture
def env(tmp_path):
    dl = tmp_path / "Downloads"
    hub = tmp_path / "Documents" / "Synced"
    dl.mkdir(parents=True)
    hub.mkdir(parents=True)
    cfg = Config(home=tmp_path / "gk", watch_roots=[dl, hub], code_tree_roots=[hub / "projects"],
                 endpoint_binds=["127.0.0.1"])
    files = {"bad": dl / "bad.pdf", "secret": hub / "creds.env"}
    files["bad"].write_bytes(b"%PDF-1.4\n%%EOF\n")
    files["secret"].write_text("x=1\n", encoding="utf-8")
    for i in range(10):
        (dl / f"clean{i}.txt").write_text(f"hello {i}", encoding="utf-8")
    (dl / "node_modules").mkdir()
    (dl / "node_modules" / "skip.pdf").write_bytes(b"%PDF-1.4\n%%EOF\n")  # excluded dir: not scanned
    st = State(tmp_path / "s.db")
    yield cfg, st, dl, files, tmp_path
    st.close()


def run(env, pushes, calls=None, report=None):
    cfg, st, dl, files, tp = env
    calls = calls or Calls()

    def push(title, body, severity, actions, cfg_, now):
        pushes.append({"title": title, "body": body, "severity": severity, "actions": actions})
        return True

    return backfill.run_backfill(cfg, st, make_scanners(calls), report or tp / "report.md",
                                 notifier=push, rate_per_s=0)


def test_report_only_records_and_one_push(env):
    cfg, st, dl, files, tp = env
    before = sorted(p for p in tp.rglob("*") if p.is_file())
    pushes = []
    res = run(env, pushes)
    assert res == {"scanned": 12, "risky": 1, "secret": 1}
    assert all(p.exists() for p in before)  # nothing moved, quarantined or deleted
    assert files["bad"].exists() and files["secret"].exists()
    assert not (cfg.home / "quarantine").exists()
    rows = [st.get_backfill(backfill.backfill_id(files[k], __import__("hashlib").sha256(files[k].read_bytes())
                                                 .hexdigest())) for k in files]
    assert all(r is not None and r["quarantined_id"] is None for r in rows)
    report = (tp / "report.md").read_text(encoding="utf-8")
    for r in rows:
        assert r["id"] in report and r["path"] in report
    assert "TEST_RULE" in report and "aws-access-token" in report
    assert "skip.pdf" not in report
    assert len(pushes) == 1 and "1 risky" in pushes[0]["body"] and pushes[0]["actions"] is None


def test_second_run_skips_cached_clean_hashes(env):
    pushes = []
    c1 = Calls()
    run(env, pushes, c1)
    assert len(c1.defender) == 12
    c2 = Calls()
    res = run(env, pushes, c2)
    assert res == {"scanned": 12, "risky": 1, "secret": 1}
    assert sorted(c2.defender) == ["bad.pdf", "creds.env"]  # the 10 clean files were cached
    assert len(pushes) == 2  # one summary per run


def test_throttled(env):
    cfg, st, dl, files, tp = env
    slept = []
    backfill.run_backfill(cfg, st, make_scanners(Calls()), tp / "r.md", notifier=lambda *a: True,
                          rate_per_s=20, sleep=slept.append, clock=lambda: 100.0)  # frozen clock
    assert slept == [pytest.approx(0.05)] * 12


def test_stale_row_dropped_when_file_turns_clean(env):
    cfg, st, dl, files, tp = env
    run(env, [])
    old = backfill.backfill_id(files["bad"], hashlib.sha256(files["bad"].read_bytes()).hexdigest())
    assert st.get_backfill(old) is not None
    files["bad"].write_bytes(b"%PDF-1.4 now harmless\n%%EOF\n")  # same path, new content, clean
    res = run(env, [])
    assert res["risky"] == 0 and st.get_backfill(old) is None
    sec = backfill.backfill_id(files["secret"], hashlib.sha256(files["secret"].read_bytes()).hexdigest())
    assert st.get_backfill(sec) is not None  # still-flagged row kept


def test_main_lowers_priority(env, monkeypatch):
    cfg, st, dl, files, tp = env
    calls = []
    monkeypatch.setattr("gatekeeper.serve.lower_process_priority", lambda: calls.append(1))
    monkeypatch.setattr("gatekeeper.config.load_config", lambda *a: cfg)
    monkeypatch.setattr("gatekeeper.watcher.default_scanners", lambda: make_scanners(Calls()))
    assert backfill.main(["--no-push"]) == 0
    assert calls == [1]


def test_quarantine_endpoint_acts_on_backfill_id(env):
    cfg, st, dl, files, tp = env
    run(env, [])
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    cfg.endpoint_port = s.getsockname()[1]
    s.close()
    key = notify.load_or_create_key(cfg)
    stop = threading.Event()
    t = threading.Thread(target=endpoint.serve_endpoint, args=(cfg, st, stop), daemon=True)
    t.start()
    base = f"http://127.0.0.1:{cfg.endpoint_port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.05)
    try:
        bid = next(l.split("|")[1].strip() for l in (tp / "report.md").read_text(encoding="utf-8").splitlines()
                   if "bad.pdf" in l)
        req = urllib.request.Request(f"{base}/q/{bid}/quarantine", data=b"", method="POST")
        req.add_header("X-Gatekeeper-Key", key)
        with urllib.request.urlopen(req, timeout=5) as r:
            qid = json.loads(r.read())["id"]
    finally:
        stop.set()
        t.join(5)
    assert not files["bad"].exists() and files["secret"].exists()
    assert st.get_backfill(bid)["quarantined_id"] == qid


def test_backfill_help_exits_without_running(monkeypatch, capsys):
    def boom(*a, **k):
        raise AssertionError("backfill must not run for --help")
    monkeypatch.setattr(backfill, "run_backfill", boom)
    with pytest.raises(SystemExit) as e:
        backfill.main(["--help"])
    assert e.value.code == 0
    out = capsys.readouterr().out
    assert "--no-push" in out


def test_backfill_rejects_unknown_option(monkeypatch, capsys):
    monkeypatch.setattr(backfill, "run_backfill", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    with pytest.raises(SystemExit) as e:
        backfill.main(["--bogus"])
    assert e.value.code == 2

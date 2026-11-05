import json
import threading
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from zoneinfo import ZoneInfo

import pytest

from gatekeeper import notify
from gatekeeper.config import Config

NY = ZoneInfo("America/New_York")


class Fake:
    def __init__(self, status=200):
        self.reqs = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", 0))
                outer.reqs.append((self.headers, json.loads(self.rfile.read(n))))
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.srv.server_port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def env(tmp_path):
    fake = Fake()
    cfg = Config(home=tmp_path, tz="America/New_York")
    (tmp_path / "ntfy.json").write_text(json.dumps(
        {"url": fake.url, "topic": "t-topic", "token": "tk_secret"}))
    yield cfg, fake
    fake.close()


def test_push_shape_and_bearer(env):
    cfg, fake = env
    acts = [{"action": "view", "label": "x", "url": "http://a"}]
    assert notify.push("T", "B", "warn", acts, cfg, datetime(2026, 11, 3, 14, 0, tzinfo=NY)) is True
    h, body = fake.reqs[0]
    assert h["Authorization"] == "Bearer tk_secret"
    assert h["Content-Type"].startswith("application/json")
    assert body["topic"] == "t-topic" and body["title"] == "T" and body["message"] == "B"
    assert body["actions"] == acts and "delay" not in body
    assert body["priority"] == 3


def test_quiet_hours_delay_2330(env):
    cfg, fake = env
    notify.push("T", "B", "warn", None, cfg, datetime(2026, 11, 3, 23, 30, tzinfo=NY))
    d = int(fake.reqs[0][1]["delay"])
    assert datetime.fromtimestamp(d, NY) == datetime(2026, 11, 4, 8, 0, tzinfo=NY)


def test_quiet_hours_dst_night(env):
    cfg, fake = env
    # 2026-11-01 01:30 EDT; DST ends at 02:00 -> 01:00 EST, so 08:00 is EST (UTC-5)
    now = datetime(2026, 11, 1, 5, 30, tzinfo=ZoneInfo("UTC"))
    notify.push("T", "B", "warn", None, cfg, now)
    d = int(fake.reqs[0][1]["delay"])
    t = datetime.fromtimestamp(d, NY)
    assert (t.hour, t.minute, t.day) == (8, 0, 1)
    assert t.utcoffset().total_seconds() == -5 * 3600


def test_naive_now_is_local(env):
    cfg, fake = env
    notify.push("T", "B", "warn", None, cfg, datetime(2026, 11, 3, 2, 0))
    d = int(fake.reqs[0][1]["delay"])
    assert datetime.fromtimestamp(d, NY) == datetime(2026, 11, 3, 8, 0, tzinfo=NY)


def test_critical_bypasses_quiet(env):
    cfg, fake = env
    notify.push("T", "B", "critical", None, cfg, datetime(2026, 11, 3, 2, 0, tzinfo=NY))
    h, body = fake.reqs[0]
    assert "delay" not in body and body["priority"] == 5


def test_never_raises(tmp_path):
    cfg = Config(home=tmp_path)  # no ntfy.json
    now = datetime(2026, 11, 3, 14, 0, tzinfo=NY)
    assert notify.push("T", "B", "warn", None, cfg, now) is False
    (tmp_path / "ntfy.json").write_text(json.dumps({"url": "http://127.0.0.1:1", "topic": "t"}))
    assert notify.push("T", "B", "warn", None, cfg, now) is False
    (tmp_path / "ntfy.json").write_text("not json")
    assert notify.push("T", "B", "warn", None, cfg, now) is False


def test_http_error_false(tmp_path):
    fake = Fake(status=500)
    cfg = Config(home=tmp_path)
    (tmp_path / "ntfy.json").write_text(json.dumps({"url": fake.url, "topic": "t"}))
    try:
        assert notify.push("T", "B", "warn", None, cfg, datetime(2026, 11, 3, 14, 0, tzinfo=NY)) is False
    finally:
        fake.close()


def test_action_buttons(tmp_path):
    from gatekeeper.state import State
    cfg = Config(home=tmp_path, endpoint_binds=["127.0.0.1", "100.64.0.10"])
    key = notify.load_or_create_key(cfg)
    st = State(tmp_path / "s.db")
    acts = notify.action_buttons("abc123", cfg, st)
    assert [a["label"] for a in acts] == ["Release", "Keep blocked"]
    assert acts[0]["url"] == "http://100.64.0.10:8766/q/abc123/release"
    assert acts[1]["url"] == "http://100.64.0.10:8766/q/abc123/keep"
    tok = acts[0]["headers"]["X-Gatekeeper-Token"]
    for a in acts:
        assert a["action"] == "http" and a["method"] == "POST"
        assert a["headers"] == {"X-Gatekeeper-Token": tok}  # one token per file, shared by both buttons
        assert key not in str(a)                              # the master key never goes into a push
    assert len(tok) >= 40
    # only the hash is stored
    row = st._conn.execute("select * from action_tokens").fetchone()
    assert row["qid"] == "abc123" and row["token_sha256"] == notify.token_digest(tok) and tok not in tuple(row)
    st.close()


def test_action_buttons_fresh_token_each_time(tmp_path):
    from gatekeeper.state import State
    st = State(tmp_path / "s.db")
    a = notify.action_buttons("q1", Config(home=tmp_path, endpoint_binds=["127.0.0.1", "100.64.0.10"]), st)[0]["headers"]["X-Gatekeeper-Token"]
    b = notify.action_buttons("q1", Config(home=tmp_path, endpoint_binds=["127.0.0.1", "100.64.0.10"]), st)[0]["headers"]["X-Gatekeeper-Token"]
    assert a != b
    st.close()


def test_key_created_once(tmp_path):
    cfg = Config(home=tmp_path / "gk", tz="America/New_York")
    k = notify.load_or_create_key(cfg)
    assert len(k) == 64 and int(k, 16) >= 0
    assert notify.load_or_create_key(cfg) == k


def test_install_ntfy_config(tmp_path):
    src = tmp_path / "src.json"
    src.write_text(json.dumps({"url": "u", "topic": "t", "token": "x", "public": "p"}))
    cfg = Config(home=tmp_path / "gk", tz="America/New_York")
    notify.install_ntfy_config(cfg, src)
    assert json.loads((cfg.home / "ntfy.json").read_text()) == {"url": "u", "topic": "t", "token": "x"}


def test_push_outcome_is_unknown_when_the_reply_times_out(tmp_path, monkeypatch):
    import time

    class Slow(Fake):
        pass
    fake = Fake()
    orig = fake.srv.RequestHandlerClass.do_POST

    def slow_post(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        time.sleep(1.0)  # accepted, but the reply is late
    fake.srv.RequestHandlerClass.do_POST = slow_post
    try:
        (tmp_path / "ntfy.json").write_text(json.dumps({"url": fake.url, "topic": "t"}))
        monkeypatch.setattr(notify, "TIMEOUT", 0.3)
        cfg = Config(home=tmp_path)
        now = datetime(2026, 11, 3, 14, 0, tzinfo=NY)
        assert notify.push_outcome("T", "B", "notice", None, cfg, now) is None
        assert notify.push("T", "B", "notice", None, cfg, now) is False  # push() itself is unchanged
    finally:
        fake.srv.RequestHandlerClass.do_POST = orig
        fake.close()


def test_push_outcome_false_when_unreachable(tmp_path):
    (tmp_path / "ntfy.json").write_text(json.dumps({"url": "http://127.0.0.1:9", "topic": "t"}))
    now = datetime(2026, 11, 3, 14, 0, tzinfo=NY)
    assert notify.push_outcome("T", "B", "notice", None, Config(home=tmp_path), now) is False

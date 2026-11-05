import hashlib
import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest

from gatekeeper import endpoint, notify
from gatekeeper.config import Config
from gatekeeper.quarantine import quarantine
from gatekeeper.state import State


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start(cfg, st):
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
    return stop, t, base


@pytest.fixture
def env(tmp_path):
    cfg = Config(home=tmp_path / "gk", endpoint_binds=["127.0.0.1"], endpoint_port=free_port())
    key = notify.load_or_create_key(cfg)
    st = State(tmp_path / "s.db")
    stop, t, base = start(cfg, st)
    yield cfg, st, key, base, tmp_path
    stop.set()
    t.join(5)
    st.close()


def call(base, path, method="POST", key=None, body=b""):
    req = urllib.request.Request(base + path, data=body if method == "POST" else None, method=method)
    if key is not None:
        req.add_header("X-Gatekeeper-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def make_q(st, tmp_path, cfg, data=b"abc"):
    f = tmp_path / "dl" / "x.bin"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(data)
    return f, quarantine(f, hashlib.sha256(data).hexdigest(), ["r"], st, cfg.home / "quarantine")


def test_health_no_key(env):
    cfg, st, key, base, tp = env
    s, b = call(base, "/health", "GET")
    assert s == 200 and json.loads(b) == {"ok": True}


def test_401(env):
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    assert call(base, f"/q/{qid}/release")[0] == 401
    assert call(base, f"/q/{qid}/release", key="wrong")[0] == 401
    assert not f.exists()


def test_release(env):
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    assert call(base, f"/q/{qid}/release", key=key)[0] == 200
    assert f.read_bytes() == b"abc"
    assert st.get_quarantine(qid)["status"] == "released"


def test_keep(env):
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    assert call(base, f"/q/{qid}/keep", key=key)[0] == 200
    assert st.get_quarantine(qid)["status"] == "kept" and not f.exists()


def test_already_handled_409(env):
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    call(base, f"/q/{qid}/keep", key=key)
    assert call(base, f"/q/{qid}/release", key=key)[0] == 409


def call_tok(base, path, token):
    req = urllib.request.Request(base + path, data=b"", method="POST")
    req.add_header("X-Gatekeeper-Token", token)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_token_release_works_once(env):
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    tok = notify.action_buttons(qid, cfg, st)[0]["headers"]["X-Gatekeeper-Token"]
    assert call_tok(base, f"/q/{qid}/release", tok) == 200
    assert f.read_bytes() == b"abc"
    f2, qid2 = make_q(st, tp, cfg, b"zzz")
    assert call_tok(base, f"/q/{qid}/keep", tok) == 401      # replay
    assert call_tok(base, f"/q/{qid2}/release", tok) == 401  # other file
    assert st.get_quarantine(qid2)["status"] == "held"


def test_token_wrong_file_and_garbage_rejected(env):
    cfg, st, key, base, tp = env
    f1, q1 = make_q(st, tp, cfg)
    f2, q2 = make_q(st, tp, cfg, b"other")
    tok1 = notify.action_buttons(q1, cfg, st)[0]["headers"]["X-Gatekeeper-Token"]
    assert call_tok(base, f"/q/{q2}/release", tok1) == 401
    assert call_tok(base, f"/q/{q2}/release", "x" * 43) == 401
    assert call_tok(base, f"/q/{q2}/release", "x" * 500) == 401
    assert st.get_quarantine(q2)["status"] == "held"
    assert call_tok(base, f"/q/{q1}/keep", tok1) == 200     # still valid for its own file


def test_token_expired_rejected(env, monkeypatch):
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    monkeypatch.setattr(notify, "ACTION_TOKEN_TTL_S", -1)
    tok = notify.action_buttons(qid, cfg, st)[0]["headers"]["X-Gatekeeper-Token"]
    assert call_tok(base, f"/q/{qid}/release", tok) == 401
    assert st.get_quarantine(qid)["status"] == "held"


def test_token_cannot_drive_backfill_quarantine(env):
    cfg, st, key, base, tp = env
    tok = notify.action_buttons("bf1", cfg, st)[0]["headers"]["X-Gatekeeper-Token"]
    assert call_tok(base, "/q/bf1/quarantine", tok) == 401


def test_token_returned_after_server_error(env, monkeypatch):
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    tok = notify.action_buttons(qid, cfg, st)[0]["headers"]["X-Gatekeeper-Token"]
    from gatekeeper import quarantine as qmod

    def boom(*a, **k):
        raise qmod.QuarantineError("disk on fire")
    monkeypatch.setattr(endpoint, "release", boom)
    assert call_tok(base, f"/q/{qid}/release", tok) == 500
    monkeypatch.undo()
    assert call_tok(base, f"/q/{qid}/release", tok) == 200  # retry allowed


def test_unknown_404(env):
    cfg, st, key, base, tp = env
    assert call(base, "/q/deadbeef0000/release", key=key)[0] == 404
    assert call(base, "/nope", key=key)[0] == 404
    assert call(base, "/q/abc/bogus", key=key)[0] == 404


def test_quarantine_backfill_only(env):
    cfg, st, key, base, tp = env
    f = tp / "dl" / "old.exe"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(b"zz")
    st.add_backfill("bf1", str(f), hashlib.sha256(b"zz").hexdigest(), ["unsigned"])
    assert call(base, "/q/notbackfill/quarantine", key=key)[0] == 403
    assert f.exists()
    s, b = call(base, "/q/bf1/quarantine", key=key)
    assert s == 200 and not f.exists()
    qid = json.loads(b)["id"]
    assert st.get_quarantine(qid)["status"] == "held"
    assert st.get_backfill("bf1")["quarantined_id"] == qid
    assert call(base, "/q/bf1/quarantine", key=key)[0] == 409


def test_get_405(env):
    cfg, st, key, base, tp = env
    assert call(base, "/q/abc/release", "GET", key=key)[0] == 405
    assert call(base, "/", "GET")[0] == 405


def test_body_too_large_413(env):
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    assert call(base, f"/q/{qid}/release", key=key, body=b"x" * 2000)[0] == 413
    assert not f.exists()


def test_refuses_wildcard_bind(tmp_path):
    cfg = Config(home=tmp_path, endpoint_binds=["0.0.0.0"])
    st = State(tmp_path / "s.db")
    stop = threading.Event()
    stop.set()  # the address check must refuse before serving, not loop
    with pytest.raises(ValueError):
        endpoint.serve_endpoint(cfg, st, stop)
    st.close()


def test_unbindable_address_does_not_block_others(tmp_path):
    # 100.64.0.1 (allowed tailnet range) is not a local address here, so binding it fails and is retried.
    cfg = Config(home=tmp_path / "gk", endpoint_binds=["100.64.0.1", "127.0.0.1"],
                 endpoint_port=free_port())
    st = State(tmp_path / "s.db")
    stop, t, base = start(cfg, st)
    try:
        assert call(base, "/health", "GET")[0] == 200
    finally:
        stop.set()
        t.join(5)
        st.close()
    assert not t.is_alive()


def test_bind_failure_logged_once_then_success(tmp_path, caplog, monkeypatch):
    import logging
    monkeypatch.setattr(endpoint, "RETRY_S", 0.1)
    port = free_port()
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", port))
    blocker.listen()
    cfg = Config(home=tmp_path / "gk", endpoint_binds=["127.0.0.1"], endpoint_port=port)
    key = notify.load_or_create_key(cfg)
    st = State(tmp_path / "s.db")
    stop = threading.Event()
    with caplog.at_level(logging.WARNING, logger="gatekeeper.endpoint"):
        t = threading.Thread(target=endpoint.serve_endpoint, args=(cfg, st, stop), daemon=True)
        t.start()
        time.sleep(0.5)  # several retries
        fails = [r for r in caplog.records if "cannot bind" in r.getMessage()]
        assert len(fails) == 1 and "127.0.0.1" in fails[0].getMessage()
        blocker.close()
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/health", timeout=1)
                break
            except Exception:
                time.sleep(0.05)
        stop.set()
        t.join(5)
    st.close()
    assert sum("bound" in r.getMessage() for r in caplog.records) == 1
    assert key not in caplog.text


def test_slot_released_when_thread_fails_to_start(tmp_path, monkeypatch):
    import http.server
    cfg = Config(home=tmp_path)
    st = State(tmp_path / "s.db")
    srv = endpoint._Server(("127.0.0.1", 0), endpoint._Handler, cfg, st, "k")
    try:
        def boom(self, *a, **k):
            raise RuntimeError("can't start thread")
        monkeypatch.setattr(http.server.ThreadingHTTPServer, "process_request", boom)
        for _ in range(endpoint.MAX_CONNECTIONS + 2):
            s = socket.socket()
            with pytest.raises(RuntimeError):
                srv.process_request(s, ("127.0.0.1", 1))
            s.close()
    finally:
        srv.server_close()
        st.close()


def test_add_backfill_preserves_quarantined_id(tmp_path):
    st = State(tmp_path / "s.db")
    st.add_backfill("b", "p", "h", ["r"])
    st.set_backfill_quarantined("b", "qq")
    st.add_backfill("b", "p2", "h", ["r2"])
    row = st.get_backfill("b")
    assert row["quarantined_id"] == "qq" and row["path"] == "p2"
    st.close()


def test_quarantine_backfill_file_changed_409(env):
    # Final review I1(a): a new document saved under the backfilled name must not be moved.
    cfg, st, key, base, tp = env
    f = tp / "dl" / "report.docx"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(b"old scanned bytes")
    st.add_backfill("bf2", str(f), hashlib.sha256(b"old scanned bytes").hexdigest(), ["macro"])
    f.write_bytes(b"owner's new document")
    s, b = call(base, "/q/bf2/quarantine", key=key)
    assert s == 409 and json.loads(b) == {"ok": False, "reason": "file changed"}
    assert f.read_bytes() == b"owner's new document"
    assert st.get_backfill("bf2")["quarantined_id"] in (None, "")
    assert not (cfg.home / "quarantine").exists() or not any((cfg.home / "quarantine").rglob("*.quarantined"))


@pytest.mark.parametrize("addr", ["192.168.1.20", "10.0.0.5", "8.8.8.8", "fe80::1", "not-an-ip"])
def test_refuses_non_loopback_non_tailnet_bind(tmp_path, addr):
    # Final review M14: binds are an allowlist (loopback + tailnet CGNAT), not a wildcard denylist.
    cfg = Config(home=tmp_path / "gk", endpoint_binds=["127.0.0.1", addr], endpoint_port=free_port())
    st = State(tmp_path / "s.db")
    stop = threading.Event()
    stop.set()  # the address check must refuse before serving, not loop
    with pytest.raises(ValueError):
        endpoint.serve_endpoint(cfg, st, stop)
    st.close()


def test_release_and_keep_are_serialised(env, monkeypatch):
    # Final review M4: a double tap must give 200 + 409, never a 500 or a kept-after-release status.
    cfg, st, key, base, tp = env
    f, qid = make_q(st, tp, cfg)
    import gatekeeper.quarantine as qmod
    real_move = qmod._move

    def slow_move(a, b):
        time.sleep(0.3)
        return real_move(a, b)
    monkeypatch.setattr(qmod, "_move", slow_move)
    codes = []
    ts = [threading.Thread(target=lambda a=a: codes.append(call(base, f"/q/{qid}/{a}", key=key)[0]))
          for a in ("release", "release", "keep")]
    for t in ts:
        t.start()
    for t in ts:
        t.join(10)
    assert sorted(codes) == [200, 409, 409], codes
    # either request may win the lock; what matters is that the outcome is consistent
    status = st.get_quarantine(qid)["status"]
    assert status in ("released", "kept"), status
    if status == "released":
        assert f.read_bytes() == b"abc"
    else:
        assert not f.exists()  # kept: the file stays in quarantine

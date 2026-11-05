import errno
import hashlib
import json
import os
import pathlib
import stat

import pytest

import gatekeeper.quarantine as qmod
from gatekeeper.quarantine import QuarantineError, keep, quarantine, release
from gatekeeper.state import State


def H(b):
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def env(tmp_path):
    st = State(tmp_path / "s.db")
    root = tmp_path / "q"
    src = tmp_path / "dl"
    src.mkdir()
    yield st, root, src
    st.close()


def count(p):
    return sum(1 for f in p.rglob("*") if f.is_file())


def test_round_trip(env):
    st, root, src = env
    f = src / "report.pdf"
    f.write_bytes(b"abc")
    qid = quarantine(f, H(b"abc"), ["unsigned"], st, root)
    assert len(qid) == 12 and qid == qid.lower() and int(qid, 16) >= 0
    assert not f.exists()
    rec = st.get_quarantine(qid)
    assert rec["status"] == "held" and rec["reasons"] == ["unsigned"]
    stored = pathlib.Path(rec["stored_path"])
    assert stored.name == "report.pdf.quarantined" and stored.read_bytes() == b"abc"
    meta = json.loads((stored.parent / "meta.json").read_text())
    assert meta["id"] == qid and meta["sha256"] == H(b"abc") and meta["original_path"] == str(f)
    assert {"reasons", "at", "origin"} <= set(meta)
    assert release(qid, st) == f
    assert f.read_bytes() == b"abc"
    assert st.get_quarantine(qid)["status"] == "released"
    assert st.get_verdict(H(b"abc")) == "clean"


def test_release_occupied(env):
    st, root, src = env
    f = src / "report.pdf"
    f.write_bytes(b"old")
    qid = quarantine(f, H(b"old"), [], st, root)
    f.write_bytes(b"new")
    out = release(qid, st)
    assert out.name == "report (restored).pdf"
    assert out.read_bytes() == b"old" and f.read_bytes() == b"new"


def test_release_twice_and_keep_after_release(env):
    st, root, src = env
    f = src / "a.exe"
    f.write_bytes(b"x")
    qid = quarantine(f, H(b"x"), [], st, root)
    release(qid, st)
    with pytest.raises(QuarantineError):
        release(qid, st)
    with pytest.raises(QuarantineError):
        keep(qid, st)
    with pytest.raises(QuarantineError):
        release("nope", st)


def test_vanished_file(env):
    st, root, src = env
    with pytest.raises(QuarantineError):
        quarantine(src / "gone.txt", "h", [], st, root)
    assert not root.exists() or count(root) == 0


def test_release_missing_stored_file(env):
    st, root, src = env
    f = src / "a.txt"
    f.write_bytes(b"x")
    qid = quarantine(f, H(b"x"), [], st, root)
    pathlib.Path(st.get_quarantine(qid)["stored_path"]).unlink()
    with pytest.raises(QuarantineError):
        release(qid, st)
    assert st.get_quarantine(qid)["status"] == "held"


def test_keep(env):
    st, root, src = env
    f = src / "a.txt"
    f.write_bytes(b"x")
    qid = quarantine(f, H(b"x"), [], st, root)
    keep(qid, st)
    assert st.get_quarantine(qid)["status"] == "kept"
    assert st.get_verdict(H(b"x")) is None
    assert not f.exists()


def test_nothing_deleted(env):
    st, root, src = env
    f = src / "a.txt"
    f.write_bytes(b"x")
    qid = quarantine(f, H(b"x"), [], st, root)
    assert count(src) + count(root) == 2  # file + meta.json
    keep(qid, st)
    assert count(src) + count(root) == 2
    f2 = src / "b.txt"
    f2.write_bytes(b"y")
    q2 = quarantine(f2, H(b"y"), [], st, root)
    release(q2, st)
    assert f2.read_bytes() == b"y"
    assert count(src) + count(root) == 4  # a, b + two meta.json


def _exdev(real):
    def fake(a, b, *args, **kw):
        if str(a).endswith(".part"):
            return real(a, b, *args, **kw)
        raise OSError(errno.EXDEV, "cross-device")
    return fake


def _force_cross_volume(monkeypatch):
    monkeypatch.setattr(os, "rename", _exdev(os.rename))
    if hasattr(os, "link"):
        monkeypatch.setattr(os, "link", _exdev(os.link))


def test_cross_volume_fallback(env, monkeypatch):
    st, root, src = env
    _force_cross_volume(monkeypatch)
    f = src / "a.txt"
    f.write_bytes(b"data")
    qid = quarantine(f, H(b"data"), [], st, root)
    assert not f.exists()
    stored = pathlib.Path(st.get_quarantine(qid)["stored_path"])
    assert stored.read_bytes() == b"data" and not list(root.rglob("*.part"))
    assert release(qid, st) == f and f.read_bytes() == b"data"


def test_cross_volume_readonly_source(env, monkeypatch):
    st, root, src = env
    _force_cross_volume(monkeypatch)
    f = src / "ro.txt"
    f.write_bytes(b"data")
    os.chmod(f, stat.S_IREAD)
    qid = quarantine(f, H(b"data"), [], st, root)
    assert not f.exists() and st.get_quarantine(qid)["status"] == "held"
    stored = pathlib.Path(st.get_quarantine(qid)["stored_path"])
    os.chmod(stored, stat.S_IWRITE)


def test_disk_full_during_copy(env, monkeypatch):
    st, root, src = env
    _force_cross_volume(monkeypatch)

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "disk full")
    monkeypatch.setattr(qmod.shutil, "copyfileobj", boom)
    f = src / "a.txt"
    f.write_bytes(b"data")
    with pytest.raises(QuarantineError):
        quarantine(f, H(b"data"), [], st, root)
    assert f.read_bytes() == b"data" and count(root) == 0


def test_file_in_use_leaves_source(env, monkeypatch):
    st, root, src = env

    def locked(*a, **k):
        raise PermissionError(13, "in use")
    monkeypatch.setattr(os, "rename", locked)
    if hasattr(os, "link"):
        monkeypatch.setattr(os, "link", locked)
    f = src / "a.txt"
    f.write_bytes(b"data")
    with pytest.raises(QuarantineError):
        quarantine(f, H(b"data"), [], st, root)
    assert f.read_bytes() == b"data" and count(root) == 0


def test_release_race_keeps_both(env, monkeypatch):
    st, root, src = env
    f = src / "r.txt"
    f.write_bytes(b"orig")
    qid = quarantine(f, H(b"orig"), [], st, root)
    real = qmod._rename_noclobber

    def racing(a, b):
        if b == f and not f.exists():
            f.write_bytes(b"intruder")
        return real(a, b)
    monkeypatch.setattr(qmod, "_rename_noclobber", racing)
    out = release(qid, st)
    assert f.read_bytes() == b"intruder"
    assert out.name == "r (restored).txt" and out.read_bytes() == b"orig"


def test_bookkeeping_failure_rolls_back(env, monkeypatch):
    st, root, src = env
    f = src / "a.txt"
    f.write_bytes(b"data")

    def bad(*a, **k):
        raise RuntimeError("db down")
    monkeypatch.setattr(st, "add_quarantine", bad)
    with pytest.raises(QuarantineError):
        quarantine(f, H(b"data"), [], st, root)
    assert f.read_bytes() == b"data" and count(root) == 0


def test_rollback_failure_names_stored_path(env, monkeypatch):
    st, root, src = env
    f = src / "a.txt"
    f.write_bytes(b"data")

    def bad(*a, **k):
        raise RuntimeError("db down")
    monkeypatch.setattr(st, "add_quarantine", bad)
    real = qmod._move
    calls = []

    def move(a, b):
        calls.append(1)
        if len(calls) > 1:
            raise OSError("nope")
        return real(a, b)
    monkeypatch.setattr(qmod, "_move", move)
    with pytest.raises(QuarantineError, match=r"\.quarantined"):
        quarantine(f, H(b"data"), [], st, root)


def test_release_hash_mismatch(env):
    st, root, src = env
    f = src / "a.txt"
    f.write_bytes(b"data")
    qid = quarantine(f, H(b"data"), [], st, root)
    pathlib.Path(st.get_quarantine(qid)["stored_path"]).write_bytes(b"tampered")
    with pytest.raises(QuarantineError):
        release(qid, st)
    assert st.get_verdict(H(b"data")) is None and st.get_quarantine(qid)["status"] == "held"


def test_preexisting_part_survives_success(env, monkeypatch):
    st, root, src = env
    _force_cross_volume(monkeypatch)
    g = src / "b.exe"
    g.write_bytes(b"more")
    real = qmod._move
    dst_holder = {}

    def move(a, b):
        part = b.with_name(b.name + ".part")
        b.parent.mkdir(parents=True, exist_ok=True)
        part.write_bytes(b"browser")
        dst_holder["part"] = part
        return real(a, b)
    monkeypatch.setattr(qmod, "_move", move)
    quarantine(g, H(b"more"), [], st, root)
    assert dst_holder["part"].read_bytes() == b"browser"
    assert not g.exists() and count(root) == 3  # stored + meta + browser .part


def test_preexisting_part_survives_failure(env, monkeypatch):
    st, root, src = env
    _force_cross_volume(monkeypatch)

    def boom(*a, **k):
        raise OSError(errno.ENOSPC, "disk full")
    monkeypatch.setattr(qmod.shutil, "copyfileobj", boom)
    g = src / "b.exe"
    g.write_bytes(b"more")
    real = qmod._move
    holder = {}

    def move(a, b):
        part = b.with_name(b.name + ".part")
        b.parent.mkdir(parents=True, exist_ok=True)
        part.write_bytes(b"browser")
        holder["part"] = part
        return real(a, b)
    monkeypatch.setattr(qmod, "_move", move)
    with pytest.raises(QuarantineError):
        quarantine(g, H(b"more"), [], st, root)
    assert holder["part"].read_bytes() == b"browser" and g.read_bytes() == b"more"
    assert [p.name for p in root.rglob("*.part")] == [holder["part"].name]


def test_records_digest_of_stored_file_not_caller_sha(env):
    # Final review I1(b): file changed between scan and quarantine -> release must still work.
    st, root, src = env
    f = src / "doc.ps1"
    f.write_bytes(b"edited after scan")
    qid = quarantine(f, H(b"scanned bytes"), ["unsigned"], st, root)
    rec = st.get_quarantine(qid)
    assert rec["sha256"] == H(b"edited after scan")
    meta = json.loads((pathlib.Path(rec["stored_path"]).parent / "meta.json").read_text())
    assert meta["sha256"] == H(b"edited after scan")
    assert any("content changed" in r for r in rec["reasons"])
    assert release(qid, st) == f
    assert f.read_bytes() == b"edited after scan"
    assert st.get_quarantine(qid)["status"] == "released"


def test_release_still_refuses_tampered_store(env):
    st, root, src = env
    f = src / "a.bin"
    f.write_bytes(b"orig")
    qid = quarantine(f, H(b"orig"), [], st, root)
    pathlib.Path(st.get_quarantine(qid)["stored_path"]).write_bytes(b"tampered")
    with pytest.raises(QuarantineError, match="does not match"):
        release(qid, st)


def test_cross_volume_readonly_part_cleaned_on_failure(env, monkeypatch):
    # Final review M15: a read-only .part (copystat) must still be removed and the real error kept.
    st, root, src = env
    _force_cross_volume(monkeypatch)

    def bad_verify(p):
        raise OSError(errno.EIO, "verify read failed")
    f = src / "ro.txt"
    f.write_bytes(b"data")
    os.chmod(f, stat.S_IREAD)
    real_digest = qmod._digest
    monkeypatch.setattr(qmod, "_digest", lambda p: bad_verify(p) if str(p).endswith(".part") else real_digest(p))
    try:
        with pytest.raises(QuarantineError, match="verify read failed"):
            quarantine(f, H(b"data"), [], st, root)
        assert f.read_bytes() == b"data"
        assert not list(root.rglob("*.part"))
    finally:
        os.chmod(f, stat.S_IWRITE)

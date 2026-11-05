import time

from gatekeeper.state import State


def test_state_roundtrip_verdict(tmp_path):
    s = State(tmp_path / "s.db")
    assert s.get_verdict("abc") is None
    s.put_verdict("abc", "risky")
    assert s.get_verdict("abc") == "risky"
    s.put_verdict("abc", "clean")
    assert s.get_verdict("abc") == "clean"


def test_cache_expires_after_max_age(tmp_path):
    s = State(tmp_path / "s.db")
    s.cache_put("npm", "left-pad", "1.0.0", {"a": 1}, at=time.time() - 8 * 86400)
    assert s.cache_get("npm", "left-pad", "1.0.0", max_age_days=7) is None
    s.cache_put("npm", "left-pad", "1.0.0", {"a": 2})
    assert s.cache_get("npm", "left-pad", "1.0.0", max_age_days=7) == {"a": 2}


def test_log_event_and_tables(tmp_path):
    s = State(tmp_path / "s.db")
    s.log_event("download", "C:/x", "sha", "clean", ["r1"])
    rows = s.list_events()
    assert len(rows) == 1 and rows[0]["kind"] == "download" and rows[0]["reasons"] == ["r1"]
    names = {r[0] for r in s._conn.execute("select name from sqlite_master where type='table'")}
    assert {"verdicts", "pkgcache", "events", "quarantine", "backfill"} <= names
    assert s._conn.execute("pragma journal_mode").fetchone()[0] == "wal"

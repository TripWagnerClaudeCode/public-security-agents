"""SQLite state: verdict cache, package-risk cache, event log, quarantine and backfill tables."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
create table if not exists verdicts(sha256 text primary key, verdict text not null, at real not null);
create table if not exists pkgcache(
    eco text not null, name text not null, version text not null, payload text not null, at real not null,
    primary key(eco, name, version));
create table if not exists events(
    id integer primary key autoincrement, at real not null, kind text not null, path text,
    sha256 text, verdict text, reasons_json text not null default '[]');
create table if not exists quarantine(
    id text primary key, at real not null, original_path text not null, stored_path text not null,
    sha256 text, reasons_json text not null default '[]', status text not null);
create table if not exists backfill(
    id text primary key, at real not null, path text not null, sha256 text,
    reasons_json text not null default '[]', quarantined_id text);
create table if not exists guard_files(
    path text primary key, sha256 text not null, text text not null, at real not null);
create table if not exists action_tokens(
    token_sha256 text primary key, qid text not null, created real not null, expires real not null,
    used real);
"""


class State:
    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("pragma journal_mode=wal")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def get_verdict(self, sha256: str) -> str | None:
        with self._lock:
            row = self._conn.execute("select verdict from verdicts where sha256=?", (sha256,)).fetchone()
        return row["verdict"] if row else None

    def put_verdict(self, sha256: str, verdict: str) -> None:
        with self._lock:
            self._conn.execute(
                "insert or replace into verdicts(sha256, verdict, at) values(?,?,?)",
                (sha256, verdict, time.time()),
            )
            self._conn.commit()

    def cache_get(self, eco: str, name: str, version: str, max_age_days: float) -> dict | None:
        cutoff = time.time() - max_age_days * 86400
        with self._lock:
            row = self._conn.execute(
                "select payload from pkgcache where eco=? and name=? and version=? and at>=?",
                (eco, name, version, cutoff),
            ).fetchone()
        return json.loads(row["payload"]) if row else None

    def cache_put(self, eco: str, name: str, version: str, payload: dict, at: float | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "insert or replace into pkgcache(eco,name,version,payload,at) values(?,?,?,?,?)",
                (eco, name, version, json.dumps(payload), time.time() if at is None else at),
            )
            self._conn.commit()

    def log_event(self, kind: str, path: str | None = None, sha256: str | None = None,
                  verdict: str | None = None, reasons: list[str] | None = None) -> None:
        with self._lock:
            self._conn.execute(
                "insert into events(at,kind,path,sha256,verdict,reasons_json) values(?,?,?,?,?,?)",
                (time.time(), kind, path, sha256, verdict, json.dumps(reasons or [])),
            )
            self._conn.commit()

    def list_events(self) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("select * from events order by id").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d.pop("reasons_json"))
            out.append(d)
        return out

    def add_quarantine(self, id: str, original_path: str, stored_path: str, sha256: str | None,
                       reasons: list[str], status: str = "held") -> None:
        with self._lock:
            self._conn.execute(
                "insert into quarantine(id,at,original_path,stored_path,sha256,reasons_json,status) "
                "values(?,?,?,?,?,?,?)",
                (id, time.time(), original_path, stored_path, sha256, json.dumps(reasons), status),
            )
            self._conn.commit()

    def get_quarantine(self, id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("select * from quarantine where id=?", (id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["reasons"] = json.loads(d.pop("reasons_json"))
        return d

    def set_quarantine_status(self, id: str, status: str) -> None:
        with self._lock:
            self._conn.execute("update quarantine set status=? where id=?", (status, id))
            self._conn.commit()

    def add_backfill(self, id: str, path: str, sha256: str | None, reasons: list[str]) -> None:
        with self._lock:
            self._conn.execute(
                "insert into backfill(id,at,path,sha256,reasons_json) values(?,?,?,?,?) "
                "on conflict(id) do update set at=excluded.at, path=excluded.path, "
                "sha256=excluded.sha256, reasons_json=excluded.reasons_json",
                (id, time.time(), path, sha256, json.dumps(reasons)),
            )
            self._conn.commit()

    def drop_stale_backfill(self, path: str, keep_id: str | None) -> None:
        """Remove un-actioned backfill rows for `path` other than `keep_id` (file now clean or changed)."""
        with self._lock:
            self._conn.execute(
                "delete from backfill where path=? and id is not ? and quarantined_id is null",
                (path, keep_id),
            )
            self._conn.commit()

    def get_backfill(self, id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("select * from backfill where id=?", (id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["reasons"] = json.loads(d.pop("reasons_json"))
        return d

    # -- guarded security files (last-seen copy, for change alerts)
    def get_guard(self, path: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("select * from guard_files where path=?", (path,)).fetchone()
        return dict(row) if row else None

    def put_guard(self, path: str, sha256: str, text: str) -> None:
        with self._lock:
            self._conn.execute(
                "insert or replace into guard_files(path,sha256,text,at) values(?,?,?,?)",
                (path, sha256, text, time.time()),
            )
            self._conn.commit()

    # -- phone action tokens (Release / Keep blocked buttons)
    def add_action_token(self, qid: str, token_sha256: str, expires: float) -> None:
        with self._lock:
            self._conn.execute(
                "insert into action_tokens(token_sha256,qid,created,expires) values(?,?,?,?)",
                (token_sha256, qid, time.time(), expires),
            )
            self._conn.commit()

    def consume_action_token(self, qid: str, token_sha256: str, now: float | None = None) -> bool:
        """Atomically mark the token used. True only if it exists for this qid, is unused and unexpired."""
        now = time.time() if now is None else now
        with self._lock:
            cur = self._conn.execute(
                "update action_tokens set used=? where token_sha256=? and qid=? and used is null and expires>?",
                (now, token_sha256, qid, now),
            )
            self._conn.commit()
        return cur.rowcount == 1

    def unconsume_action_token(self, token_sha256: str) -> None:
        """Give a token back after the action itself failed (so the owner can retry from the phone)."""
        with self._lock:
            self._conn.execute("update action_tokens set used=null where token_sha256=?", (token_sha256,))
            self._conn.commit()

    def purge_action_tokens(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        with self._lock:
            self._conn.execute("delete from action_tokens where expires<=? or used is not null", (now - 86400,))
            self._conn.commit()

    def set_backfill_quarantined(self, id: str, quarantined_id: str) -> None:
        with self._lock:
            self._conn.execute("update backfill set quarantined_id=? where id=?", (quarantined_id, id))
            self._conn.commit()

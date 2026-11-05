"""Quarantine store: risky files are moved (never deleted) and can be released back."""
from __future__ import annotations

import errno
import hashlib
import json
import os
import secrets
import shutil
import stat
import time
from datetime import datetime
from pathlib import Path

from .config import Config
from .state import State


class QuarantineError(Exception):
    pass


def default_root(cfg: Config) -> Path:
    return cfg.home / "quarantine"


def _is_exdev(e: OSError) -> bool:
    return e.errno == errno.EXDEV or getattr(e, "winerror", None) == 17


def _rename_noclobber(src: Path, dst: Path) -> None:
    """Rename that raises FileExistsError instead of overwriting dst."""
    if os.name == "nt":
        os.rename(src, dst)  # raises FileExistsError if dst exists
    else:
        os.link(src, dst)  # raises FileExistsError if dst exists
        os.unlink(src)


def _move(src: Path, dst: Path) -> None:
    """Move src to dst without ever overwriting dst (FileExistsError if it exists).

    Same volume: atomic no-clobber rename. Only a cross-device error falls back to
    copy to <dst>.part, verify SHA-256, rename into place, then unlink the source.
    On any failure the .part is removed and the source is left untouched.
    """
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        _rename_noclobber(src, dst)
        return
    except OSError as e:
        if isinstance(e, FileExistsError) or not _is_exdev(e):
            raise
    part = dst.with_name(dst.name + ".part")
    if part.exists():  # not ours (e.g. a browser's in-progress file): never touch it
        part = dst.with_name(f"{dst.name}.{secrets.token_hex(3)}.part")
    created = False
    placed = False
    try:
        if dst.exists():
            raise FileExistsError(str(dst))
        with open(src, "rb") as fi, open(part, "xb") as fo:
            created = True
            shutil.copyfileobj(fi, fo, 1 << 20)
        shutil.copystat(src, part)
        if _digest(src) != _digest(part):
            raise QuarantineError(f"copy verification failed for {src}")
        _rename_noclobber(part, dst)
        placed = True
        try:
            os.chmod(src, stat.S_IWRITE)
        except OSError:
            pass
        src.unlink()
    except BaseException:
        if placed:
            dst.unlink(missing_ok=True)
        if created:
            try:  # copystat may have made the .part read-only; never let cleanup mask the real error
                os.chmod(part, stat.S_IWRITE)
                part.unlink(missing_ok=True)
            except OSError:
                pass
        raise


def _digest(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_meta(path: Path, meta: dict) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def quarantine(path: Path, sha256: str, reasons: list[str], state: State, root: Path,
               origin: str = "") -> str:
    path = Path(path)
    if not path.is_file():
        raise QuarantineError(f"file not found: {path}")
    now = time.time()
    qid = secrets.token_hex(6)
    folder = Path(root) / datetime.fromtimestamp(now).strftime("%Y-%m-%d") / qid
    stored = folder / (path.name + ".quarantined")
    try:
        _move(path, stored)
    except FileNotFoundError as e:
        raise QuarantineError(f"file vanished: {path}") from e
    except (OSError, QuarantineError) as e:
        raise QuarantineError(f"cannot quarantine {path}: {e}") from e
    reasons = list(reasons)
    try:
        # Record what is actually stored, so release() never locks out a file that
        # changed between the scan and the move (the caller's sha is only advisory).
        actual = _digest(stored)
        if sha256 and actual != sha256:
            reasons.append("content changed after scan")
        _write_meta(folder / "meta.json", {
            "id": qid, "original_path": str(path), "sha256": actual,
            "reasons": reasons, "at": now, "origin": origin,
        })
        state.add_quarantine(qid, str(path), str(stored), actual, reasons, "held")
    except Exception as e:
        try:
            _move(stored, path)
        except Exception as e2:
            raise QuarantineError(
                f"bookkeeping failed ({e}) and move-back failed ({e2}); file is at {stored}") from e
        for leftover in (folder / "meta.json", folder / "meta.json.tmp"):
            leftover.unlink(missing_ok=True)
        try:
            folder.rmdir()
        except OSError:
            pass
        raise QuarantineError(f"bookkeeping failed, file restored to {path}: {e}") from e
    return qid


def _held(qid: str, state: State) -> dict:
    rec = state.get_quarantine(qid)
    if rec is None:
        raise QuarantineError(f"unknown quarantine id: {qid}")
    if rec["status"] != "held":
        raise QuarantineError(f"{qid} is already {rec['status']}")
    return rec


def release(qid: str, state: State) -> Path:
    rec = _held(qid, state)
    stored = Path(rec["stored_path"])
    if not stored.is_file():
        raise QuarantineError(f"stored file missing for {qid}: {stored}")
    if rec["sha256"] and _digest(stored) != rec["sha256"]:
        raise QuarantineError(f"stored file for {qid} does not match recorded sha256")
    orig = Path(rec["original_path"])
    n = 0
    while True:
        if n == 0:
            dest = orig
        else:
            tag = " (restored)" if n == 1 else f" (restored {n})"
            dest = orig.with_name(f"{orig.stem}{tag}{orig.suffix}")
        if not dest.exists():
            try:
                _move(stored, dest)
                break
            except FileExistsError:
                pass
            except (OSError, QuarantineError) as e:
                raise QuarantineError(f"cannot release {qid}: {e}") from e
        n += 1
    if rec["sha256"]:
        state.put_verdict(rec["sha256"], "clean")
    state.set_quarantine_status(qid, "released")
    return dest


def keep(qid: str, state: State) -> None:
    _held(qid, state)
    state.set_quarantine_status(qid, "kept")

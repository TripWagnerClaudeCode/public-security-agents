"""Guardrail-file alert: push to the phone whenever an owner-only security file changes.

Watches cfg.guarded_files (by default the security agents' scope.yaml and AGENT_RULES.md, and
GATEKEEPER_RULES.md) every cfg.guard_interval_s seconds. Any change, from anyone (an agent, the owner,
a sync), sends one `critical` push (never held for quiet hours) with the file name and how many lines
were added/removed. The push never contains file content: ntfy may be readable by other tailnet devices.

The last-seen copy of each file is kept in state.db, so a change made while Gatekeeper was stopped still
alerts at the next start. A file seen for the first time is recorded silently (that is the baseline).
If a push is not delivered, the baseline is left alone and the next check tries again.
"""
from __future__ import annotations

import difflib
import hashlib
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from . import notify
from .config import Config
from .state import State

log = logging.getLogger("gatekeeper.guard")
MISSING = "missing"


def _read(p: Path) -> tuple[str, str]:
    """(sha256 or MISSING, text). Unreadable counts as missing."""
    try:
        data = Path(p).read_bytes()
    except OSError:
        return MISSING, ""
    return hashlib.sha256(data).hexdigest(), data.decode("utf-8", errors="replace")


def _counts(old: str, new: str) -> tuple[int, int]:
    added = removed = 0
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


def check_once(cfg: Config, state: State, notifier: Callable = notify.push_outcome,
               now: datetime | None = None) -> list[str]:
    """Check every guarded file once. Returns the names of files an alert was sent for."""
    now = now or datetime.now(timezone.utc)
    alerted = []
    for p in cfg.guarded_files:
        key = str(Path(p))
        sha, text = _read(Path(p))
        prev = state.get_guard(key)
        if prev is None:
            state.put_guard(key, sha, text)
            log.info("guard baseline recorded for %s", Path(p).name)
            continue
        if prev["sha256"] == sha:
            continue
        name = Path(p).name
        if sha == MISSING:
            title, body = f"Security file DELETED: {name}", f"{key} was deleted or became unreadable."
        elif prev["sha256"] == MISSING:
            title, body = f"Security file restored: {name}", f"{key} exists again."
        else:
            a, r = _counts(prev["text"], text)
            title, body = f"Security file changed: {name}", f"+{a} / -{r} lines in {key}."
        body += " If you did not make this change, review it (git diff in the security-agent repo)."
        outcome = notifier(title, body, "critical", None, cfg, now)
        state.log_event("guard_change", key, None if sha == MISSING else sha, None, [title])
        if outcome is False:  # not delivered: keep the old baseline so the next check alerts again
            log.warning("guard alert for %s not delivered; will retry", name)
            continue
        state.put_guard(key, sha, text)
        alerted.append(name)
    return alerted


def guard_loop(cfg: Config, state: State, stop: threading.Event, notifier: Callable = notify.push_outcome) -> None:
    while not stop.is_set():
        try:
            check_once(cfg, state, notifier)
        except Exception:  # the guard must never take Gatekeeper down
            log.exception("guard check failed")
        stop.wait(max(5.0, float(cfg.guard_interval_s)))

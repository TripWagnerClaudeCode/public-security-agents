"""`python -m gatekeeper serve`: the watcher plus the control endpoint, in one hidden per-user process.

Logs go to <home>/logs/gatekeeper.log (stdout/stderr are redirected there too, since pythonw has none).
A lock file keeps a second copy from running. If the watcher dies it is restarted after 30 s.
"""
from __future__ import annotations

import logging
import logging.handlers
import os
import signal
import sys
import threading
from pathlib import Path

from .config import Config, load_config
from .endpoint import serve_endpoint
from .guard import guard_loop
from .state import State
from .watcher import Pipeline, Watcher, default_scanners

log = logging.getLogger("gatekeeper.serve")
RESTART_S = 30
SORT_TICK_S = 60



class _LogStream:
    """File-like object that sends print() output to the log."""

    def __init__(self, logger: logging.Logger, level: int):
        self.logger, self.level, self._buf = logger, level, ""

    def write(self, s: str) -> int:
        self._buf += s
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                self.logger.log(self.level, line)
        return len(s)

    def flush(self) -> None:
        pass


def setup_logging(home: Path) -> None:
    logs = home / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    h = logging.handlers.RotatingFileHandler(logs / "gatekeeper.log", maxBytes=2_000_000, backupCount=3,
                                             encoding="utf-8")
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(h)
    root.setLevel(logging.INFO)
    sys.stdout = _LogStream(logging.getLogger("stdout"), logging.INFO)
    sys.stderr = _LogStream(logging.getLogger("stderr"), logging.WARNING)


def acquire_lock(path: Path):
    """Open and lock `path`; None if another process holds it. Keep the returned file open."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.close()
        return None
    return fh


def lower_process_priority() -> None:
    if os.name != "nt":
        try:
            os.nice(10)
        except OSError:
            pass
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetPriorityClass(k32.GetCurrentProcess(), 0x4000)  # BELOW_NORMAL; scanner children inherit it
    except Exception:
        pass


def main(argv: list[str] | None = None) -> int:
    try:
        cfg, cfg_error = load_config(), None
    except Exception as e:  # a malformed config.toml must not kill Layer 1 silently
        cfg, cfg_error = Config(), e
    setup_logging(cfg.home)
    if cfg_error is not None:
        log.error("cannot load config (%s: %s); using defaults", type(cfg_error).__name__, str(cfg_error)[:200])
    lock = acquire_lock(cfg.home / "serve.lock")
    if lock is None:
        log.info("another gatekeeper serve is running; exiting")
        return 0
    lower_process_priority()
    stop = threading.Event()
    for sig in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, sig):
            signal.signal(getattr(signal, sig), lambda *_: stop.set())
    state = State(cfg.home / "state.db")
    log.info("gatekeeper serve starting (pid %s)", os.getpid())
    ep = threading.Thread(target=serve_endpoint, args=(cfg, state, stop), name="gatekeeper-endpoint", daemon=True)
    ep.start()
    gd = threading.Thread(target=guard_loop, args=(cfg, state, stop), name="gatekeeper-guard", daemon=True)
    gd.start()
    pipeline = Pipeline(cfg, state, default_scanners())
    try:
        while not stop.is_set():
            try:
                Watcher(cfg, pipeline, stop).run()
            except Exception:
                log.exception("watcher crashed; restarting in %ss", RESTART_S)
                stop.wait(RESTART_S)
    finally:
        stop.set()
        ep.join(10)
        gd.join(10)
        state.close()
        lock.close()
        log.info("gatekeeper serve stopped")
    return 0

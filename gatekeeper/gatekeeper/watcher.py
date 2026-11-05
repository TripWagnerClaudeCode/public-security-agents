"""Layer 1 watcher: watchdog observers on the watch roots feed a stability wait and one low-priority worker.

Pipeline.handle(path, doorway) runs one file through facts -> scanners -> classify, then quarantines and
pushes (risky), pushes (secret), or just logs (clean/notice). Nothing in here deletes a file.
"""
from __future__ import annotations

import dataclasses
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from . import facts as facts_mod
from . import notify, scanners
from .config import Config
from .facts import FileFacts, Finding, is_signable
from .lnk import lnk_findings
from .packages import redact_urls
from .quarantine import QuarantineError, default_root, quarantine
from .state import State
from .verdict import classify

log = logging.getLogger("gatekeeper.watcher")

# Directories never scanned, wherever they are under a watch root (in addition to cfg.exclude_dirs).
EXTRA_EXCLUDE_DIRS = {"venv", ".stversions", ".stfolder"}
# Build output: only excluded inside a code tree, so a tool unpacked into Downloads\x\bin is still scanned.
BUILD_DIRS = {"bin", "obj"}
EXCLUDED_SUBPATHS: list[tuple[str, ...]] = []   # e.g. ("projects", "my-tool", "work"): scratch dirs never scanned
TEMP_SUFFIXES = (".crdownload", ".part")
DOWNLOAD_ROOT_NAMES = {"downloads", "desktop"}
_TEXT_KINDS = {"text", "script"}
# Returned by Pipeline.handle(final=False) when the file could not be read yet (locked, sharing violation).
RETRY = "retry"
# Seconds to wait before each re-read of a file that raised OSError; after the last one it is a notice.
RETRY_DELAYS = (2.0, 5.0, 15.0, 60.0)


# ---------------------------------------------------------------- path rules

def is_temp_name(name: str) -> bool:
    n = name.lower()
    if n.endswith(TEMP_SUFFIXES):
        return True
    return n.endswith(".tmp") and (n.startswith("~syncthing~") or n.startswith(".syncthing."))


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _abs(p: Path) -> Path:
    return Path(os.path.normcase(os.path.abspath(p)))


def _root_of(path: Path, cfg: Config) -> Path | None:
    p = _abs(path)
    best = None
    for r in cfg.watch_roots:
        ra = _abs(r)
        if _under(p, ra) and (best is None or len(ra.parts) > len(best.parts)):
            best = ra
    return best


def _code_tree(path: Path, root: Path, cfg: Config) -> bool:
    p = _abs(path)
    if any(_under(p, _abs(c)) for c in cfg.code_tree_roots):
        return True
    cur = p.parent
    while _under(cur, root):
        if (cur / ".git").exists():
            return True
        if cur == root:
            break
        cur = cur.parent
    return False


def is_excluded(path: Path, cfg: Config) -> bool:
    p = _abs(path)
    if _under(p, _abs(cfg.home)) or _under(p, _abs(default_root(cfg))):
        return True
    root = _root_of(p, cfg)
    if root is None:
        return True
    dirs = [s.lower() for s in p.relative_to(root).parts[:-1]]
    skip = {d.lower() for d in cfg.exclude_dirs} | EXTRA_EXCLUDE_DIRS
    if any(d in skip for d in dirs):
        return True
    for sub in EXCLUDED_SUBPATHS:
        n = len(sub)
        if any(tuple(dirs[i:i + n]) == sub for i in range(len(dirs) - n + 1)):
            return True
    if any(d in BUILD_DIRS for d in dirs) and _code_tree(p, root, cfg):
        return True
    return False


def doorway_for(path: Path, cfg: Config) -> str:
    """Downloads/Desktop -> download; everything else (e.g. a synced folder) -> sync (the writer is unknown)."""
    root = _root_of(path, cfg)
    return "download" if root is not None and root.name.lower() in DOWNLOAD_ROOT_NAMES else "sync"


# ---------------------------------------------------------------- pipeline

@dataclass
class Scanners:
    motw: Callable[[Path], dict | None]
    signature: Callable[[Path], str]
    defender: Callable[[Path], list[Finding]]
    yara: Callable[[Path], list[Finding]]
    gitleaks: Callable[[Path], list[Finding]]


def default_scanners() -> Scanners:
    return Scanners(
        motw=scanners.read_motw,
        signature=scanners.authenticode,
        defender=scanners.defender_scan,
        yara=lambda p: scanners.yara_scan(p, scanners.load_yara()),
        gitleaks=scanners.gitleaks_scan,
    )


_DETECTORS: dict[str, Callable[[Path], list[Finding]]] = {
    "office": facts_mod.office_findings,
    "pdf": facts_mod.pdf_findings,
    "archive": facts_mod.archive_findings,
}


def _reasons(f: FileFacts, findings: list[Finding]) -> list[str]:
    out = [x.detail for x in findings]
    if f.origin == "internet" and f.kind in ("pe", "msi", "script") and f.signed != "valid":
        out.append(f"{'unsigned' if f.signed == 'n/a' else f.signed} {f.kind} from the internet")
    if f.ext_mismatch:
        out.append(f"content ({f.kind}) does not match the extension")
    return out


class Pipeline:
    def __init__(self, cfg: Config, state: State, scanners: Scanners,
                 notifier: Callable[..., bool] = notify.push):
        self.cfg, self.state, self.scanners, self.notifier = cfg, state, scanners, notifier
        # Called as cb(path, facts, verdict) after a clean/notice verdict (e.g. a later downloads sorter).
        self.on_clean: list[Callable[[Path, FileFacts, str], None]] = []
        # Called as cb(path, facts, verdict, findings) for EVERY verdict, before quarantine/push (the sorter
        # uses it to drop a file queued on an earlier clean verdict and to see scanner errors).
        self.on_verdict: list[Callable[[Path, FileFacts, str, list[Finding]], None]] = []
        self._key: str | None = None
        self.last_retry_error = ""

    def _call(self, name: str, fn, path: Path, default):
        try:
            return fn(path), None
        except Exception as e:
            log.warning("%s failed on %s: %s", name, path.name, type(e).__name__)
            return default, Finding(f"{name}_error", f"{name} failed: {type(e).__name__}", "notice")

    def handle(self, path: Path, doorway: str, final: bool = True) -> str:
        """Judge one file. With final=False a transient OSError (locked file) returns RETRY and logs no
        event, so the caller can try again later; a vanished file or any other error is a notice."""
        path = Path(path)
        try:
            return self._handle(path, doorway)
        except OSError as e:
            if not final and not isinstance(e, FileNotFoundError):
                log.info("cannot read %s yet (%s); will retry", path.name, type(e).__name__)
                self.last_retry_error = f"{type(e).__name__}: {str(e)[:200]}"
                return RETRY
            return self._error(path, e)
        except Exception as e:  # a bug: log, never crash the worker
            return self._error(path, e)

    def _error(self, path: Path, e: Exception) -> str:
        msg = f"{type(e).__name__}: {str(e)[:200]}"
        log.warning("cannot handle %s: %s", path, msg)
        self.state.log_event("error", str(path), None, "notice", [msg])
        return "notice"

    def give_up(self, path: Path, attempts: int) -> None:
        """Record that a file stayed unreadable through every retry (a notice, never a silent pass)."""
        last = self.last_retry_error
        log.warning("giving up on %s after %d attempts: %s", path, attempts, last)
        self.state.log_event("error", str(path), None, "notice",
                             [f"unreadable after {attempts} attempts; not scanned ({last})"])

    def analyze(self, path: Path, doorway: str):
        """Facts -> scanners -> classify; no side effects beyond reading the file.

        Returns (verdict, facts, findings, reasons, motw, cached); cached=True means the hash was already
        known clean and no scanner ran.
        """
        errors: list[Finding] = []
        motw, err = self._call("motw", self.scanners.motw, path, None)
        errors += [err] if err else []
        facts = facts_mod.gather_facts(path, self.cfg, doorway, motw, "n/a")  # type: ignore[arg-type]

        if self.state.get_verdict(facts.sha256) == "clean":
            return "clean", facts, [], ["cached"], motw, True

        if is_signable(facts.kind, path):
            signed, err = self._call("signature", self.scanners.signature, path, "n/a")
            errors += [err] if err else []
            facts = dataclasses.replace(facts, signed="unsigned" if signed == "n/a" else signed)

        findings: list[Finding] = []
        steps = [("defender", self.scanners.defender), ("yara", self.scanners.yara)]
        if facts.kind == "lnk":  # judged by its target; Downloads/%APPDATA% targets depend on origin
            origin = facts.origin
            steps.append(("lnk", lambda p: lnk_findings(p, origin)))
        elif facts.kind in _DETECTORS:
            steps.append((facts.kind, _DETECTORS[facts.kind]))
        if facts.kind in _TEXT_KINDS:
            steps.append(("gitleaks", self.scanners.gitleaks))
        for name, fn in steps:
            got, err = self._call(name, fn, path, [])
            findings += got
            errors += [err] if err else []
        findings += errors

        verdict = classify(facts, findings)
        return verdict, facts, findings, _reasons(facts, findings), motw, False

    def _handle(self, path: Path, doorway: str) -> str:
        verdict, facts, findings, reasons, motw, cached = self.analyze(path, doorway)
        self._after_verdict(path, facts, verdict, findings)
        if cached:
            self.state.log_event("file", str(path), facts.sha256, "clean", ["cached"])
            self._after_clean(path, facts, "clean")
            return "clean"
        if verdict == "risky":
            self._risky(path, facts, findings, reasons, motw)
        elif verdict == "secret":
            self.state.log_event("file", str(path), facts.sha256, verdict, reasons)
            self._push(f"Secret found: {path.name}", "; ".join(reasons) + f"\n{path}", "secret", None)
        else:
            self.state.log_event("file", str(path), facts.sha256, verdict, reasons)
            if verdict == "clean":
                self.state.put_verdict(facts.sha256, "clean")
            self._after_clean(path, facts, verdict)
        return verdict

    def _risky(self, path: Path, facts: FileFacts, findings: list[Finding], reasons: list[str],
               motw: dict | None) -> None:
        severity = "critical" if any(f.severity == "critical" for f in findings) else "risky"
        source = (motw or {}).get("HostUrl") or (motw or {}).get("ReferrerUrl")
        source = redact_urls(str(source)) if source else source  # no pre-signed query strings
        origin = f"{facts.origin} via {source}" if source else facts.origin
        body = "; ".join(reasons)[:500] + f"\nFrom: {origin}\n{path}"
        try:
            qid = quarantine(path, facts.sha256, reasons, self.state, default_root(self.cfg), origin=origin)
        except QuarantineError as e:
            self.state.log_event("quarantine_failed", str(path), facts.sha256, "risky",
                                 reasons + [str(e)[:200]])
            self._push(f"Risky, NOT quarantined: {path.name}", body, severity, None)
            return
        self.state.log_event("file", str(path), facts.sha256, "risky", reasons + [f"quarantined {qid}"])
        try:
            actions = notify.action_buttons(qid, self.cfg, self.state)
        except Exception as e:  # no buttons is better than no push
            log.warning("action token failed: %s", type(e).__name__)
            actions = None
        self._push(f"Quarantined: {path.name}", body, severity, actions)

    def _push(self, title: str, body: str, severity: str, actions) -> None:
        try:
            self.notifier(title, body, severity, actions, self.cfg, datetime.now(timezone.utc))
        except Exception as e:
            log.warning("push failed: %s", type(e).__name__)

    def _after_verdict(self, path: Path, facts: FileFacts, verdict: str, findings: list[Finding]) -> None:
        for cb in list(self.on_verdict):
            try:
                cb(path, facts, verdict, list(findings))
            except Exception as e:
                log.warning("on_verdict callback failed for %s: %s", path.name, type(e).__name__)

    def _after_clean(self, path: Path, facts: FileFacts, verdict: str) -> None:
        for cb in list(self.on_clean):
            try:
                cb(path, facts, verdict)
            except Exception as e:
                log.warning("on_clean callback failed for %s: %s", path.name, type(e).__name__)


# ---------------------------------------------------------------- watcher

def _lower_thread_priority() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.SetThreadPriority(k32.GetCurrentThread(), -2)  # THREAD_PRIORITY_LOWEST
    except Exception:
        pass


@dataclass
class _Pending:
    path: Path
    sig: tuple[int, int] | None = None
    since: float = field(default_factory=time.monotonic)
    attempt: int = 0  # reads already tried that hit a transient OSError
    not_before: float = 0.0  # monotonic time before which a retry is not queued


class _Events(FileSystemEventHandler):
    def __init__(self, watcher: "Watcher"):
        self.w = watcher

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        if event.event_type == "deleted":
            self.w.forget(Path(os.fsdecode(event.src_path)))
        elif event.event_type == "moved":
            self.w.forget(Path(os.fsdecode(event.src_path)))
            self.w.notify(Path(os.fsdecode(event.dest_path)))
        elif event.event_type in ("created", "modified", "closed"):
            self.w.notify(Path(os.fsdecode(event.src_path)))


class Watcher:
    """Observers on cfg.watch_roots -> stability wait -> bounded queue -> one low-priority worker."""

    DONE_MAX = 20_000

    def __init__(self, cfg: Config, pipeline, stop: threading.Event, stable_s: float = 2.0,
                 poll_s: float = 0.5, queue_max: int = 256,
                 retry_delays: tuple[float, ...] = RETRY_DELAYS):
        self.cfg, self.pipeline, self.stop = cfg, pipeline, stop
        self.stable_s, self.poll_s = stable_s, poll_s
        self.retry_delays = tuple(retry_delays)
        self.queue: queue.Queue = queue.Queue(maxsize=queue_max)
        self.ready = threading.Event()
        self._lock = threading.Lock()
        self._pending: dict[str, _Pending] = {}
        self._inflight: set[str] = set()
        self._done: dict[str, tuple[int, int]] = {}

    @staticmethod
    def _key(path: Path) -> str:
        return os.path.normcase(os.path.abspath(path))

    def notify(self, path: Path) -> None:
        path = Path(path)
        if is_temp_name(path.name) or is_excluded(path, self.cfg):
            return
        with self._lock:
            self._pending[self._key(path)] = _Pending(path)

    def forget(self, path: Path) -> None:
        with self._lock:
            self._pending.pop(self._key(path), None)

    def _tick(self) -> None:
        now = time.monotonic()
        with self._lock:
            items = list(self._pending.items())
        for key, p in items:
            if now < p.not_before:
                continue
            try:
                st = os.stat(p.path)
            except FileNotFoundError:
                self.forget(p.path)
                continue
            except OSError:
                continue  # locked for now; try again next tick
            if not os.path.isfile(p.path):
                self.forget(p.path)
                continue
            sig = (st.st_size, st.st_mtime_ns)
            with self._lock:
                cur = self._pending.get(key)
                if cur is not p:
                    continue  # re-notified meanwhile; its own entry restarts the wait
                if sig != p.sig:
                    p.sig, p.since = sig, now
                    continue
                if now - p.since < self.stable_s or key in self._inflight:
                    continue
                if self._done.get(key) == sig:
                    del self._pending[key]
                    continue
                try:
                    self.queue.put_nowait((key, p.path, sig, p.attempt))
                except queue.Full:
                    continue  # stays pending; retried next tick
                self._inflight.add(key)
                del self._pending[key]

    def _worker(self) -> None:
        _lower_thread_priority()
        while not self.stop.is_set():
            try:
                key, path, sig, attempt = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue
            verdict = None
            try:
                verdict = self.pipeline.handle(path, doorway_for(path, self.cfg), final=False)
                if verdict == RETRY:
                    attempt += 1
                    if attempt <= len(self.retry_delays):
                        self._schedule_retry(key, path, attempt)
                    else:
                        self.pipeline.give_up(path, attempt)
                    verdict = None  # no judgement: never mark done
            except Exception as e:
                log.exception("pipeline crashed on %s: %s", path, type(e).__name__)
            finally:
                with self._lock:
                    self._inflight.discard(key)
                    if verdict is not None:
                        self._done.pop(key, None)
                        self._done[key] = sig
                        while len(self._done) > self.DONE_MAX:
                            self._done.pop(next(iter(self._done)))

    def _schedule_retry(self, key: str, path: Path, attempt: int) -> None:
        delay = self.retry_delays[attempt - 1]
        with self._lock:
            if key in self._pending:  # a fresh event arrived meanwhile; it starts its own wait
                return
            self._pending[key] = _Pending(path, attempt=attempt, not_before=time.monotonic() + delay)

    def run(self) -> None:
        observer = Observer()
        handler = _Events(self)
        for root in self.cfg.watch_roots:
            if Path(root).is_dir():
                observer.schedule(handler, str(root), recursive=True)
                log.info("watching %s", root)
            else:
                log.warning("watch root missing, skipped: %s", root)
        observer.start()
        worker = threading.Thread(target=self._worker, name="gatekeeper-worker", daemon=True)
        worker.start()
        self.ready.set()
        try:
            while not self.stop.is_set():
                self._tick()
                self.stop.wait(self.poll_s)
        finally:
            observer.stop()
            observer.join(10)
            worker.join(10)

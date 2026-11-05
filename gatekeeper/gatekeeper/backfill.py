"""Report-only backfill: one scan of files already under the watch roots.

Never moves, quarantines or deletes anything. Risky and secret findings are recorded as backfill rows
(so the phone's "quarantine this id" button can act on them later) and listed in a Markdown report; one
summary push is sent at the end. Clean hashes are cached, so a re-run skips them and resumes cheaply.
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from . import notify
from .config import Config
from .state import State
from .watcher import Pipeline, Scanners, doorway_for, is_excluded, is_temp_name

log = logging.getLogger("gatekeeper.backfill")
RATE_PER_S = 20.0


def backfill_id(path: Path, sha256: str) -> str:
    key = f"{os.path.normcase(os.path.abspath(path))}|{sha256}"
    return "b" + hashlib.sha256(key.encode()).hexdigest()[:20]


def iter_files(cfg: Config) -> Iterator[Path]:
    """Every file under the watch roots that the live watcher would also scan."""
    seen: set[str] = set()
    for root in cfg.watch_roots:
        if not Path(root).is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if not is_excluded(Path(dirpath) / d / "_", cfg)]
            for name in filenames:
                p = Path(dirpath) / name
                key = os.path.normcase(os.path.abspath(p))
                if key in seen or is_temp_name(name) or is_excluded(p, cfg):
                    continue
                seen.add(key)
                yield p


def run_backfill(cfg: Config, state: State, scanners: Scanners, report_path: Path,
                 notifier: Callable[..., bool] = notify.push, rate_per_s: float = RATE_PER_S,
                 sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic) -> dict:
    pipe = Pipeline(cfg, state, scanners, notifier)
    scanned = 0
    found: list[tuple[str, str, str, list[str]]] = []  # (verdict, id, path, reasons)
    delay = 1.0 / rate_per_s if rate_per_s > 0 else 0.0
    for path in iter_files(cfg):
        started = clock()
        try:
            verdict, facts, _f, reasons, _m, cached = pipe.analyze(path, doorway_for(path, cfg))
        except Exception as e:  # unreadable/vanished file: skip, keep going
            log.warning("backfill cannot scan %s: %s", path, type(e).__name__)
            continue
        scanned += 1
        if verdict == "clean" and not cached:
            state.put_verdict(facts.sha256, "clean")
        bid = backfill_id(path, facts.sha256) if verdict in ("risky", "secret") else None
        state.drop_stale_backfill(str(path), bid)  # no longer flagged (or content changed)
        if bid:
            state.add_backfill(bid, str(path), facts.sha256, reasons)
            found.append((verdict, bid, str(path), reasons))
        if not cached and delay:
            left = delay - (clock() - started)
            if left > 0:
                sleep(left)
    risky = sum(1 for v, *_ in found if v == "risky")
    secret = sum(1 for v, *_ in found if v == "secret")
    _write_report(report_path, scanned, risky, secret, found)
    body = f"Scanned {scanned} files: {risky} risky, {secret} secret. Nothing was moved. Report: {report_path}"
    try:
        notifier("Gatekeeper backfill finished", body, "info", None, cfg, datetime.now(timezone.utc))
    except Exception as e:
        log.warning("backfill summary push failed: %s", type(e).__name__)
    return {"scanned": scanned, "risky": risky, "secret": secret}


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _write_report(report_path: Path, scanned: int, risky: int, secret: int, found: list) -> None:
    lines = [
        f"# Gatekeeper backfill report ({datetime.now().strftime('%Y-%m-%d %H:%M')})",
        "",
        f"Scanned {scanned} files: {risky} risky, {secret} secret. Report-only: nothing was moved or deleted.",
        "",
        "| id | verdict | path | reasons |",
        "|---|---|---|---|",
    ]
    for verdict, bid, path, reasons in found:
        lines.append(f"| {bid} | {verdict} | {_cell(path)} | {_cell('; '.join(reasons))} |")
    if not found:
        lines.append("| - | - | nothing found | - |")
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m gatekeeper backfill",
                                 description="Report-only scan of existing files; one summary push.")
    ap.add_argument("--no-push", action="store_true", help="do not send the summary push")
    args = ap.parse_args(argv or [])
    from .config import load_config
    from .serve import lower_process_priority
    from .watcher import default_scanners
    lower_process_priority()  # BELOW_NORMAL; the scanner children inherit it
    cfg = load_config()
    no_push = args.no_push
    state = State(cfg.home / "state.db")
    report = cfg.home / f"backfill-{datetime.now().strftime('%Y-%m-%d')}.md"
    try:
        res = run_backfill(cfg, state, default_scanners(), report,
                           notifier=(lambda *a, **k: False) if no_push else notify.push)
    finally:
        state.close()
    print(f"scanned={res['scanned']} risky={res['risky']} secret={res['secret']} report={report}")
    return 0

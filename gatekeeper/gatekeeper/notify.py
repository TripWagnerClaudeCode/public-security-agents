"""Phone pushes via an ntfy server (ntfy.sh or self-hosted), plus the action buttons for quarantine pushes.

Publishes like the hub's own notifier: JSON POST to the base URL with topic/title/message/priority and
`Authorization: Bearer <token>`. During quiet hours the message carries ntfy's `delay` (unix time of the
next 08:00 local) so ntfy itself holds it; severity `critical` is never held. Never raises, never logs
the token.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .config import Config

TIMEOUT = 5.0
PRIORITY = {"critical": 5, "risky": 4}
DEFAULT_PRIORITY = 3


def _log(msg: str) -> None:
    try:
        print(f"gatekeeper.notify: {msg}", file=sys.stderr)
    except Exception:
        pass


# ---------------------------------------------------------------- key + config files

def _restrict_acl(path: Path) -> None:
    """Best effort: only the current user may read the file."""
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        return
    try:
        user = os.environ.get("USERNAME") or os.getlogin()
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:F"],
                       capture_output=True, timeout=10, check=False)
    except Exception:
        pass


def load_or_create_key(cfg: Config) -> str:
    path = cfg.home / "key"
    try:
        key = path.read_text(encoding="utf-8").strip()
        if key:
            return key
    except OSError:
        pass
    cfg.home.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32)
    path.write_text(key, encoding="utf-8")
    _restrict_acl(path)
    return key


def install_ntfy_config(cfg: Config, source: Path) -> None:
    """Copy {url, topic, token} from a local JSON file to <home>/ntfy.json, owner-only (installer only)."""
    data = json.loads(Path(source).read_text(encoding="utf-8"))
    out = {k: data[k] for k in ("url", "topic", "token") if k in data}
    if "url" not in out or "topic" not in out:
        raise ValueError("ntfy config needs url and topic")
    cfg.home.mkdir(parents=True, exist_ok=True)
    dst = cfg.home / "ntfy.json"
    dst.write_text(json.dumps(out), encoding="utf-8")
    _restrict_acl(dst)


def _load_ntfy(cfg: Config) -> dict | None:
    try:
        d = json.loads((cfg.home / "ntfy.json").read_text(encoding="utf-8"))
    except Exception:
        return None
    if isinstance(d, dict) and isinstance(d.get("url"), str) and isinstance(d.get("topic"), str) \
            and d["url"].lower().startswith(("http://", "https://")):
        return d
    return None


# ---------------------------------------------------------------- quiet hours

def quiet_until(now: datetime, cfg: Config) -> datetime | None:
    """Next end-of-quiet-hours wall time (in cfg.tz) if `now` is inside quiet hours, else None.

    Naive `now` is taken as wall time in cfg.tz. The target is built as a wall time in the zone, so it
    carries that day's UTC offset (DST-safe)."""
    zone = ZoneInfo(cfg.tz)
    local = now.replace(tzinfo=zone) if now.tzinfo is None else now.astimezone(zone)
    start, end = cfg.quiet_hours
    if start > end:
        quiet = local.hour >= start or local.hour < end
    else:
        quiet = start <= local.hour < end
    if not quiet:
        return None
    day = local.date()
    if start > end and local.hour >= start:
        day += timedelta(days=1)
    return datetime(day.year, day.month, day.day, end, tzinfo=zone)


# ---------------------------------------------------------------- push

def push(title: str, body: str, severity: str, actions: list[dict] | None,
         cfg: Config, now: datetime) -> bool:
    return push_outcome(title, body, severity, actions, cfg, now) is True


def push_outcome(title: str, body: str, severity: str, actions: list[dict] | None,
                 cfg: Config, now: datetime) -> bool | None:
    """True: accepted. False: not delivered. None: the request went out but the reply timed out,
    so ntfy may well have accepted it (callers that must not send twice treat that as sent)."""
    try:
        conf = _load_ntfy(cfg)
        if not conf:
            _log("push skipped: no usable ntfy.json")
            return False
        msg: dict = {
            "topic": conf["topic"],
            "title": (title or "Gatekeeper")[:200],
            "message": (body or "")[:3000],
            "priority": PRIORITY.get(severity, DEFAULT_PRIORITY),
            "tags": ["shield"],
        }
        if actions:
            msg["actions"] = actions
        if severity != "critical":
            hold = quiet_until(now, cfg)
            if hold is not None:
                msg["delay"] = str(int(hold.timestamp()))
        headers = {"Content-Type": "application/json"}
        if conf.get("token"):
            headers["Authorization"] = f"Bearer {conf['token']}"
        req = urllib.request.Request(conf["url"], data=json.dumps(msg).encode(), headers=headers,
                                     method="POST")
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return 200 <= r.status < 300
    except TimeoutError as e:  # a read timeout: the connect timeout arrives wrapped in URLError
        _log(f"push outcome unknown: {type(e).__name__}")
        return None
    except Exception as e:  # never raise; never include the token
        _log(f"push failed: {type(e).__name__}: {str(e)[:200]}")
        return False


# ---------------------------------------------------------------- buttons

def _tailnet_host(cfg: Config) -> str:
    for b in cfg.endpoint_binds:
        if not b.startswith("127."):
            return b
    return cfg.endpoint_binds[0]


ACTION_TOKEN_TTL_S = 7 * 86400
TOKEN_HEADER = "X-Gatekeeper-Token"


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def action_buttons(qid: str, cfg: Config, state) -> list[dict]:
    """Release / Keep blocked buttons for one quarantined file.

    The buttons carry a fresh random token that works only for this qid, only once, and only for
    ACTION_TOKEN_TTL_S. Only its SHA-256 is stored. The endpoint's master key never goes into a push:
    ntfy caches messages and may let other tailnet devices read the topic."""
    token = secrets.token_urlsafe(32)
    state.add_action_token(qid, token_digest(token), time.time() + ACTION_TOKEN_TTL_S)
    base = f"http://{_tailnet_host(cfg)}:{cfg.endpoint_port}/q/{qid}"
    hdr = {TOKEN_HEADER: token}
    return [
        {"action": "http", "label": "Release", "url": f"{base}/release", "method": "POST",
         "headers": hdr, "clear": True},
        {"action": "http", "label": "Keep blocked", "url": f"{base}/keep", "method": "POST",
         "headers": hdr, "clear": True},
    ]

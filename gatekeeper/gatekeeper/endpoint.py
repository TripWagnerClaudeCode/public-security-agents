"""Keyed control endpoint for the phone's Release / Keep blocked buttons.

POST /q/<id>/release | keep      (any quarantine id)
     auth: X-Gatekeeper-Token (the per-file, single-use token from that file's push buttons)
           or X-Gatekeeper-Key (master key; never sent in pushes, local/admin use only)
POST /q/<id>/quarantine          (backfill finding ids only; master key only)
GET  /health                     (no key, no paths)
Everything else GET -> 405. Binds only the addresses in cfg.endpoint_binds (never a wildcard).
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import logging
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .config import Config
from .notify import TOKEN_HEADER, load_or_create_key, token_digest
from .quarantine import QuarantineError, _digest, default_root, keep, quarantine, release
from .state import State

MAX_BODY = 1024
MAX_CONNECTIONS = 16
RETRY_S = 30
TIMEOUT_S = 10
log = logging.getLogger("gatekeeper.endpoint")
_WILDCARDS = {"", "0.0.0.0", "::", "0:0:0:0:0:0:0:0"}
# Only loopback and the tailnet (CGNAT range Tailscale uses) may be bound.
_ALLOWED_NETS = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128", "100.64.0.0/10")]
# One release/keep/quarantine at a time across every bind's server (double taps, ntfy retries).
_ACTION_LOCK = threading.Lock()


def _allowed_bind(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip())
    except ValueError:
        return False
    return any(ip in n for n in _ALLOWED_NETS)
_ROUTE = re.compile(r"^/q/([0-9A-Za-z_-]{1,64})/(release|keep|quarantine)$")


class _Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, handler, cfg: Config, state: State, key: str):
        self.cfg, self.state, self.key = cfg, state, key
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)  # over the connection limit
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()  # thread failed to start; process_request_thread will never run
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


class _Handler(BaseHTTPRequestHandler):
    timeout = TIMEOUT_S
    server_version = "gatekeeper"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _send(self, code: int, obj: dict | None = None) -> None:
        data = json.dumps(obj if obj is not None else {"ok": code < 400}).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": True})
        else:
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()

    do_PUT = do_DELETE = do_PATCH = do_HEAD = do_GET

    def do_POST(self):
        try:
            self._post()
        except Exception as e:
            print(f"gatekeeper.endpoint: {type(e).__name__}: {str(e)[:200]}", file=sys.stderr)
            self._send(500, {"ok": False})

    def _post(self):
        supplied = self.headers.get("X-Gatekeeper-Key", "")
        master = bool(supplied) and hmac.compare_digest(supplied.encode(), self.server.key.encode())
        token = self.headers.get(TOKEN_HEADER, "").strip()
        if not master and not (token and len(token) <= 128):
            return self._send(401, {"ok": False})
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._send(400, {"ok": False})
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            return self._send(413, {"ok": False})
        if length:
            self.rfile.read(length)
        m = _ROUTE.match(self.path)
        if not m:
            return self._send(404, {"ok": False})
        qid, action = m.groups()
        with _ACTION_LOCK:
            return self._act(qid, action, master, token)

    def _act(self, qid: str, action: str, master: bool, token: str):
        state: State = self.server.state
        if action == "quarantine":
            if not master:  # backfill quarantine is never driven by a push button
                return self._send(401, {"ok": False})
            return self._quarantine_backfill(qid, state)
        digest = None
        if not master:
            digest = token_digest(token)
            if not state.consume_action_token(qid, digest):  # wrong file, used, expired or unknown
                return self._send(401, {"ok": False})
        if state.get_quarantine(qid) is None:
            return self._send(404, {"ok": False})
        try:
            if action == "release":
                release(qid, state)
            else:
                keep(qid, state)
        except QuarantineError as e:
            already = "already" in str(e)
            if digest and not already:
                state.unconsume_action_token(digest)  # let the owner retry after a transient failure
            return self._send(409 if already else 500, {"ok": False})
        self._send(200, {"ok": True})

    def _quarantine_backfill(self, bid: str, state: State):
        row = state.get_backfill(bid)
        if row is None:
            return self._send(403, {"ok": False})
        if row.get("quarantined_id"):
            return self._send(409, {"ok": False})
        if row.get("sha256"):
            try:
                live = _digest(Path(row["path"]))
            except OSError:
                return self._send(404, {"ok": False})
            if live != row["sha256"]:
                return self._send(409, {"ok": False, "reason": "file changed"})
        try:
            qid = quarantine(Path(row["path"]), row.get("sha256") or "", row["reasons"], state,
                             default_root(self.server.cfg), origin=f"backfill:{bid}")
        except QuarantineError:
            return self._send(404, {"ok": False})
        state.set_backfill_quarantined(bid, qid)
        self._send(200, {"ok": True, "id": qid})


def serve_endpoint(cfg: Config, state: State, stop: threading.Event) -> None:
    """Serve until `stop` is set: one server per bind address; failed binds retried every 30 s."""
    for b in cfg.endpoint_binds:
        if b.strip() in _WILDCARDS:
            raise ValueError(f"refusing to bind wildcard address {b!r}")
        if not _allowed_bind(b):
            raise ValueError(f"refusing to bind {b!r}: only loopback and tailnet (100.64.0.0/10) addresses")
    key = load_or_create_key(cfg)
    try:
        state.purge_action_tokens()
    except Exception:
        pass
    servers: dict[str, _Server] = {}
    failed: set[str] = set()
    threads: list[threading.Thread] = []
    try:
        while not stop.is_set():
            for b in cfg.endpoint_binds:
                if b in servers:
                    continue
                try:
                    srv = _Server((b, cfg.endpoint_port), _Handler, cfg, state, key)
                except OSError as e:
                    if b not in failed:
                        failed.add(b)
                        log.warning("cannot bind %s:%s (%s); retrying every %ss",
                                    b, cfg.endpoint_port, type(e).__name__, RETRY_S)
                    continue
                if b in failed:
                    log.warning("bound %s:%s after earlier failure", b, cfg.endpoint_port)
                servers[b] = srv
                t = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
                t.start()
                threads.append(t)
            stop.wait(RETRY_S if len(servers) < len(cfg.endpoint_binds) else 3600)
    finally:
        for srv in servers.values():
            srv.shutdown()
            srv.server_close()
        for t in threads:
            t.join(5)

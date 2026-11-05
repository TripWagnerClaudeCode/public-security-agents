"""Gatekeeper configuration: defaults overridden by an optional TOML file."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

USER = Path.home()
DEFAULT_HOME = USER / ".gatekeeper"


def _default_watch_roots() -> list[Path]:
    return [USER / "Downloads", USER / "Desktop"]   # add synced folders in config.toml


def _default_guarded_files() -> list[Path]:
    sa = USER / "security-agents"   # where this repo is cloned (override guarded_files in config.toml)
    return [sa / "config" / "scope.yaml", sa / "config" / "AGENT_RULES.md", sa / "gatekeeper" / "GATEKEEPER_RULES.md"]


def _default_code_roots() -> list[Path]:
    return []   # folders holding your code repos (set in config.toml)


@dataclass
class Config:
    home: Path = DEFAULT_HOME
    watch_roots: list[Path] = field(default_factory=_default_watch_roots)
    code_tree_roots: list[Path] = field(default_factory=_default_code_roots)
    exclude_dirs: set[str] = field(
        default_factory=lambda: {".git", "node_modules", ".venv", "__pycache__", ".gatekeeper"}
    )
    quiet_hours: tuple[int, int] = (23, 8)
    tz: str = "UTC"   # IANA zone for quiet hours, e.g. "Europe/Berlin" (set in config.toml)
    endpoint_binds: list[str] = field(default_factory=lambda: ["127.0.0.1"])   # add your tailnet IP for phone buttons
    endpoint_port: int = 8766
    hook_timeout_s: float = 3.0
    pkg_cache_days: int = 7
    guarded_files: list[Path] = field(default_factory=_default_guarded_files)  # change -> critical push
    guard_interval_s: float = 30.0


def load_config(path: Path | None = None) -> Config:
    path = Path(path) if path is not None else DEFAULT_HOME / "config.toml"
    cfg = Config()
    if not path.is_file():
        return cfg
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    for key in ("home",):
        if key in data:
            setattr(cfg, key, Path(data[key]))
    for key in ("watch_roots", "code_tree_roots", "guarded_files"):
        if key in data:
            setattr(cfg, key, [Path(p) for p in data[key]])
    if "exclude_dirs" in data:
        cfg.exclude_dirs = set(data["exclude_dirs"])
    if "quiet_hours" in data:
        start, end = data["quiet_hours"]
        cfg.quiet_hours = (int(start), int(end))
    if "tz" in data:
        cfg.tz = str(data["tz"])
    if "endpoint_binds" in data:
        cfg.endpoint_binds = [str(b) for b in data["endpoint_binds"]]
    if "endpoint_port" in data:
        cfg.endpoint_port = int(data["endpoint_port"])
    if "hook_timeout_s" in data:
        cfg.hook_timeout_s = float(data["hook_timeout_s"])
    if "pkg_cache_days" in data:
        cfg.pkg_cache_days = int(data["pkg_cache_days"])
    if "guard_interval_s" in data:
        cfg.guard_interval_s = float(data["guard_interval_s"])
    return cfg

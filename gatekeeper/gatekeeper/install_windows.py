r"""Install the Windows watcher service (no admin):

    python -m gatekeeper.install_windows [--ntfy-config PATH]   # from the gatekeeper folder, with its venv

1. creates the endpoint key (kept if it exists); with --ntfy-config, copies {url, topic, token} from that
   JSON file to <home>/ntfy.json (owner-only). Without it, an existing <home>/ntfy.json is kept, or pushes stay off;
2. stops the `Gatekeeper` task, snapshots `git archive HEAD gatekeeper` into <home>/service;
3. registers the per-user Scheduled Task `Gatekeeper` (at logon, hidden, restart on failure) that runs
   `<venv>\Scripts\pythonw.exe -m gatekeeper serve` in <home>/service, and starts it.
The previous task definition goes to <home>/install-backup-<timestamp>.json.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape

from .config import Config, load_config
from .install_hooks import archive_head, extract_snapshot
from .notify import install_ntfy_config, load_or_create_key

TASK_NAME = "Gatekeeper"
_NOFLASH = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def task_xml(pythonw: Path, workdir: Path, user: str) -> str:
    u, cmd, wd = escape(user), escape(str(pythonw)), escape(str(workdir))
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Gatekeeper download watcher + control endpoint (python -m gatekeeper serve).</Description>
  </RegistrationInfo>
  <Principals>
    <Principal id="Author">
      <UserId>{u}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <Hidden>true</Hidden>
    <Priority>7</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
  </Settings>
  <Triggers>
    <LogonTrigger>
      <UserId>{u}</UserId>
    </LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>{cmd}</Command>
      <Arguments>-m gatekeeper serve</Arguments>
      <WorkingDirectory>{wd}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def _schtasks(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    r = subprocess.run(["schtasks", *args], capture_output=True, text=True, timeout=60, creationflags=_NOFLASH)
    if check and r.returncode != 0:
        raise RuntimeError(f"schtasks {args[0]} failed: {(r.stdout + r.stderr).strip()[:300]}")
    return r


def register_task(pythonw: Path, workdir: Path, user: str) -> None:
    fd, tmp = tempfile.mkstemp(suffix=".xml", prefix="gk-task-")
    os.close(fd)
    try:
        Path(tmp).write_text(task_xml(pythonw, workdir, user), encoding="utf-16")
        _schtasks("/Create", "/TN", TASK_NAME, "/XML", tmp, "/F")
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------- install

def default_pythonw() -> Path:
    return Path(sys.executable).with_name("pythonw.exe")


def install(cfg: Config | None = None, repo: Path | None = None, pythonw: Path | None = None,
            ntfy_config: Path | None = None) -> dict:
    cfg = cfg or load_config()
    repo = Path(repo) if repo is not None else Path(__file__).resolve().parents[2]
    pythonw = Path(pythonw) if pythonw is not None else default_pythonw()
    if not pythonw.is_file():
        raise FileNotFoundError(f"pythonw not found: {pythonw}")
    user = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".lstrip("\\")
    result: dict = {}

    load_or_create_key(cfg)
    result["key"] = str(cfg.home / "key")
    if ntfy_config is not None:
        install_ntfy_config(cfg, ntfy_config)
    result["ntfy"] = str(cfg.home / "ntfy.json") if (cfg.home / "ntfy.json").is_file() else         "not configured (pushes off; rerun with --ntfy-config PATH)"

    backup: dict = {"at": datetime.now().isoformat(timespec="seconds")}
    bak = cfg.home / f"install-backup-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}.json"

    def save() -> None:  # after every step, so a later failure still leaves the earlier values
        bak.write_text(json.dumps(backup, indent=2), encoding="utf-8")

    prev = _schtasks("/Query", "/TN", TASK_NAME, "/XML", check=False)
    if prev.returncode == 0:
        backup["task_xml"] = prev.stdout
        save()
        _schtasks("/End", "/TN", TASK_NAME, check=False)  # releases the service dir (its cwd)
    service = extract_snapshot(archive_head(repo), cfg.home / "service")
    register_task(pythonw, service, user)
    result["task"] = f"{TASK_NAME}: {pythonw} -m gatekeeper serve (in {service})"

    _schtasks("/Run", "/TN", TASK_NAME)
    result["backup"] = str(bak)
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="python -m gatekeeper.install_windows")
    ap.add_argument("--ntfy-config", type=Path, default=None,
                    help='JSON file {"url": ..., "topic": ..., "token": ...} for phone pushes')
    a = ap.parse_args(argv)
    for k, v in install(ntfy_config=a.ntfy_config).items():
        print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

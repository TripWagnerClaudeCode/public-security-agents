"""Install / deploy the gatekeeper Claude Code hooks.

    python -m gatekeeper.install_hooks deploy [--wsl-distro NAME]   # from the repo: snapshot HEAD, set up this machine (+ a WSL distro)
    python -m gatekeeper.install_hooks setup <app> <venv> <settings.json>   # on one machine, app already extracted
    python -m gatekeeper.install_hooks install <settings.json> <python> [--shim <path>]

The live hook never runs from the dev tree: `deploy` extracts `git archive HEAD gatekeeper` into
`~/.gatekeeper/app`, makes a stdlib-only venv at `~/.gatekeeper/venv` (no pip), links it with a `.pth`,
and points settings.json at `gatekeeper_hook_shim.py` in the snapshot. `install` only adds or updates
the gatekeeper's own PreToolUse/PostToolUse entries; every other key and hook is left as it was, and the
file is backed up before any change.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime
from pathlib import Path

PRE_MATCHER = "Bash|PowerShell|Write|Edit|NotebookEdit|WebFetch|mcp__.*"
POST_MATCHER = "WebFetch|mcp__.*|Read"
HOOK_TIMEOUT_S = 10  # outer bound; the hook itself answers `ask` after hook_timeout_s (3 s)
SHIM_NAME = "gatekeeper_hook_shim.py"
_OUR_MARKS = ("-m gatekeeper.hook ", SHIM_NAME + '" ', SHIM_NAME + " ")


def hook_command(python: Path, mode: str, shim: Path | None = None) -> str:
    # -I: ignore cwd/PYTHON* env so a repo's own `gatekeeper/` folder can't shadow the hook.
    if shim is not None:
        return f'"{python}" -I "{shim}" {mode}'
    return f'"{python}" -I -m gatekeeper.hook {mode}'


def _is_ours(h: dict, mode: str) -> bool:
    cmd = h.get("command") if isinstance(h, dict) else None
    if not isinstance(cmd, str):
        return False
    cmd = cmd.rstrip()
    return any(cmd.endswith(mark + mode) for mark in _OUR_MARKS)


def _merge(entries: list, matcher: str, command: str, mode: str) -> list:
    want = {"matcher": matcher, "hooks": [{"type": "command", "command": command, "timeout": HOOK_TIMEOUT_S}]}
    out: list = []
    placed = False
    for e in entries:
        hooks = e.get("hooks") if isinstance(e, dict) else None
        if not isinstance(hooks, list) or not any(_is_ours(h, mode) for h in hooks):
            out.append(e)
            continue
        rest = [h for h in hooks if not _is_ours(h, mode)]
        if rest:  # someone put other hooks in our entry: keep them under their matcher
            out.append({**e, "hooks": rest})
        if not placed:
            out.append(want)
            placed = True
    if not placed:
        out.append(want)
    return out


def _backup(path: Path) -> Path:
    stamp = datetime.now().strftime("%Y-%m-%d")
    bak = path.with_name(f"{path.name}.bak-{stamp}")
    if bak.exists():
        bak = path.with_name(f"{path.name}.bak-{stamp}-{datetime.now().strftime('%H%M%S%f')}")
    bak.write_bytes(path.read_bytes())
    return bak


def install(settings_path: Path, python: Path, shim: Path | None = None) -> bool:
    """Add/update the gatekeeper hooks. Returns True if the file changed."""
    settings_path = Path(settings_path)
    text = settings_path.read_text(encoding="utf-8") if settings_path.is_file() else ""
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError as e:
        raise ValueError(f"{settings_path} is not valid JSON; not touching it") from e
    if not isinstance(data, dict):
        raise ValueError(f"{settings_path} is not a JSON object; not touching it")
    before = json.dumps(data, sort_keys=True)

    hooks = data.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("settings 'hooks' is not an object; not touching it")
    for event, matcher, mode in (("PreToolUse", PRE_MATCHER, "pre"), ("PostToolUse", POST_MATCHER, "post")):
        entries = hooks.get(event, [])
        if not isinstance(entries, list):
            raise ValueError(f"settings hooks.{event} is not a list; not touching it")
        hooks[event] = _merge(entries, matcher, hook_command(python, mode, shim), mode)

    if json.dumps(data, sort_keys=True) == before:
        return False  # already installed exactly like this
    settings_path.parent.mkdir(parents=True, exist_ok=True)
    if settings_path.is_file():
        _backup(settings_path)
    tmp = settings_path.with_name(settings_path.name + ".gatekeeper-tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, settings_path)
    return True


# --------------------------------------------------------------------------
# Snapshot + venv
# --------------------------------------------------------------------------

def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def link_package(python: Path, src: Path) -> Path:
    """Write <venv site-packages>/gatekeeper.pth pointing at `src` (the dir that contains gatekeeper/)."""
    purelib = subprocess.run([str(python), "-I", "-c", "import sysconfig; print(sysconfig.get_paths()['purelib'])"],
                             capture_output=True, text=True, check=True, timeout=60).stdout.strip()
    pth = Path(purelib) / "gatekeeper.pth"
    pth.write_text(str(Path(src).resolve()) + "\n", encoding="utf-8")
    return pth


def archive_head(repo: Path) -> bytes:
    """`git archive HEAD gatekeeper` as tar bytes."""
    return subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", "HEAD", "gatekeeper"],
                          capture_output=True, check=True, timeout=120).stdout


def _retry(fn, attempts: int = 10) -> None:
    for i in range(attempts):
        try:
            fn()
            return
        except OSError:  # Windows: a hook process may briefly hold a file in the tree
            if i == attempts - 1:
                raise
            time.sleep(0.5)


def extract_snapshot(tar_bytes: bytes, app: Path) -> Path:
    """Extract the archive's `gatekeeper/` folder as `app` (swap via app.new / app.prev)."""
    app = Path(app)
    new, prev = app.with_name(app.name + ".new"), app.with_name(app.name + ".prev")
    stage = app.with_name(app.name + ".stage")
    for d in (new, stage):
        if d.exists():
            shutil.rmtree(d)
    stage.mkdir(parents=True)
    with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tf:
        tf.extractall(stage, filter="data")
    os.replace(stage / "gatekeeper", new)
    shutil.rmtree(stage)
    if not (new / SHIM_NAME).is_file() or not (new / "gatekeeper" / "hook.py").is_file():
        raise RuntimeError("snapshot lacks the hook shim or package")
    if app.exists():
        if prev.exists():
            _retry(lambda: shutil.rmtree(prev))
        _retry(lambda: os.replace(app, prev))
    _retry(lambda: os.replace(new, app))
    return app


def setup(app: Path, venv: Path, settings: Path) -> Path:
    """Make the stdlib-only venv (if missing), link it to `app`, point settings.json at the shim."""
    app, venv = Path(app).resolve(), Path(venv)
    py = venv_python(venv)
    if not py.is_file():
        base = getattr(sys, "_base_executable", None) or sys.executable
        subprocess.run([base, "-m", "venv", "--without-pip", str(venv)], check=True, timeout=300)
    link_package(py, app)
    install(settings, py.absolute(), shim=app / SHIM_NAME)
    return py


def _wsl_path(p: Path) -> str:
    s = str(Path(p).resolve())
    return f"/mnt/{s[0].lower()}{s[2:].replace(chr(92), '/')}"


def deploy_hub(tar_bytes: bytes, staging: Path, distro: str) -> str:
    staging.mkdir(parents=True, exist_ok=True)
    tar_path = staging / "gatekeeper-hub.tar"
    tar_path.write_bytes(tar_bytes)
    t = shlex.quote(_wsl_path(tar_path))
    script = f"""set -e
A="$HOME/.gatekeeper/app"
rm -rf "$A.new" && mkdir -p "$A.new"
tar -xf {t} --strip-components=1 -C "$A.new"
test -f "$A.new/{SHIM_NAME}"
if [ -d "$A" ]; then rm -rf "$A.prev"; mv "$A" "$A.prev"; fi
mv "$A.new" "$A"
cd "$A"
python3 -m gatekeeper.install_hooks setup "$A" "$HOME/.gatekeeper/venv" "$HOME/.claude/settings.json"
"""
    p = subprocess.run(["wsl.exe", "-d", distro, "--", "bash", "-s"], input=script.encode(),
                       capture_output=True, timeout=600)
    out = (p.stdout + p.stderr).decode("utf-8", "replace").strip()
    if p.returncode != 0:
        raise RuntimeError(f"hub deploy failed ({p.returncode}): {out[-500:]}")
    return out


def deploy(repo: Path, home: Path | None = None, wsl_distro: str | None = None) -> list[str]:
    home = Path(home) if home is not None else Path.home()
    gk = home / ".gatekeeper"
    tar_bytes = archive_head(repo)
    notes = []
    app = extract_snapshot(tar_bytes, gk / "app")
    py = setup(app, gk / "venv", home / ".claude" / "settings.json")
    notes.append(f"local: {app} via {py}")
    if wsl_distro:  # also install the hooks for Claude Code inside this WSL distro
        notes.append(f"wsl {wsl_distro}: " + deploy_hub(tar_bytes, gk / "deploy", wsl_distro))
    return notes


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m gatekeeper.install_hooks")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("deploy")
    d.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    d.add_argument("--wsl-distro", default=None, help="also set up Claude Code hooks inside this WSL distro")
    s = sub.add_parser("setup")
    s.add_argument("app", type=Path)
    s.add_argument("venv", type=Path)
    s.add_argument("settings", type=Path)
    i = sub.add_parser("install")
    i.add_argument("settings", type=Path)
    i.add_argument("python", type=Path)
    i.add_argument("--shim", type=Path)
    a = ap.parse_args(argv)
    if a.cmd == "deploy":
        for line in deploy(a.repo, wsl_distro=a.wsl_distro):
            print(line)
    elif a.cmd == "setup":
        print(f"set up {a.app} with {setup(a.app, a.venv, a.settings)}; hooks in {a.settings}")
    else:
        changed = install(a.settings, a.python, a.shim)
        print(("hooks installed in " if changed else "hooks already current in ") + str(a.settings))
    return 0


if __name__ == "__main__":
    sys.exit(main())

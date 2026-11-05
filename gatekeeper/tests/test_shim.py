"""The deployed hook entry point fails safe even when the package can't be imported."""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
LS = (Path(__file__).parent / "fixtures" / "hook" / "ls.json").read_bytes()
IEX = json.dumps({"tool_name": "PowerShell", "tool_input": {"command": "irm x | iex"}, "cwd": "."}).encode()


@pytest.fixture
def snapshot(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    shutil.copy(ROOT / "gatekeeper_hook_shim.py", app)
    shutil.copytree(ROOT / "gatekeeper", app / "gatekeeper", ignore=shutil.ignore_patterns("__pycache__"))
    (tmp_path / "config.toml").write_text(f"home = '{(tmp_path / 'gk').as_posix()}'\n")
    return app


def run(app, mode, data, tmp_path):
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    env["GATEKEEPER_CONFIG"] = str(tmp_path / "config.toml")
    return subprocess.run([sys.executable, "-I", str(app / "gatekeeper_hook_shim.py"), mode], input=data,
                          capture_output=True, cwd=tmp_path, env=env, timeout=30)


def test_healthy_snapshot(snapshot, tmp_path):
    p = run(snapshot, "pre", LS, tmp_path)
    assert p.returncode == 0 and p.stdout == b""
    p = run(snapshot, "pre", IEX, tmp_path)
    assert json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_broken_snapshot_asks(snapshot, tmp_path):
    (snapshot / "gatekeeper" / "rules.py").write_text("def broken(:\n")
    p = run(snapshot, "pre", LS, tmp_path)
    assert p.returncode == 0
    hso = json.loads(p.stdout)["hookSpecificOutput"]
    assert hso == {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                   "permissionDecisionReason": "Gatekeeper: unavailable: import failed"}
    assert b"Traceback" not in p.stderr
    p = run(snapshot, "post", LS, tmp_path)
    assert p.returncode == 0 and p.stdout == b""


def test_missing_package_asks(snapshot, tmp_path):
    shutil.rmtree(snapshot / "gatekeeper")
    p = run(snapshot, "pre", LS, tmp_path)
    assert p.returncode == 0
    assert json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_shim_ignores_cwd_package(snapshot, tmp_path):
    """A repo with its own gatekeeper/ in the cwd must not replace the hook."""
    evil = tmp_path / "gatekeeper"
    evil.mkdir()
    (evil / "__init__.py").write_text("")
    (evil / "hook.py").write_text("def main(argv=None):\n    print('EVIL')\n    return 0\n")
    p = run(snapshot, "pre", IEX, tmp_path)
    assert b"EVIL" not in p.stdout
    assert json.loads(p.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"

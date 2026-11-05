import json
from pathlib import Path

import pytest

from gatekeeper.install_hooks import POST_MATCHER, PRE_MATCHER, hook_command, install

PY = Path(r"C:\Users\user\security-agent\gatekeeper\.venv\Scripts\python.exe")


def ours(data, event):
    return [e for e in data["hooks"][event] if any("gatekeeper.hook" in h["command"] for h in e["hooks"])]


def test_matchers_exact():
    assert PRE_MATCHER == "Bash|PowerShell|Write|Edit|NotebookEdit|WebFetch|mcp__.*"
    assert POST_MATCHER == "WebFetch|mcp__.*|Read"


def test_creates_missing_file(tmp_path):
    s = tmp_path / ".claude" / "settings.json"
    install(s, PY)
    data = json.loads(s.read_text())
    (pre,) = ours(data, "PreToolUse")
    (post,) = ours(data, "PostToolUse")
    assert pre["matcher"] == PRE_MATCHER and post["matcher"] == POST_MATCHER
    assert pre["hooks"][0] == {"type": "command", "command": hook_command(PY, "pre"), "timeout": 10}
    assert post["hooks"][0]["command"] == hook_command(PY, "post")
    assert not list(s.parent.glob("*.bak-*"))  # nothing to back up


def test_command_line():
    assert hook_command(PY, "pre") == f'"{PY}" -I -m gatekeeper.hook pre'


def test_preserves_other_keys_and_hooks_and_backs_up(tmp_path):
    s = tmp_path / "settings.json"
    original = {"model": "opus", "permissions": {"allow": ["Bash(ls:*)"]},
                "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other.sh"}]}],
                          "Stop": [{"hooks": [{"type": "command", "command": "notify.sh"}]}]}}
    s.write_text(json.dumps(original, indent=2))
    install(s, PY)
    data = json.loads(s.read_text())
    assert data["model"] == "opus" and data["permissions"] == original["permissions"]
    assert data["hooks"]["Stop"] == original["hooks"]["Stop"]
    assert data["hooks"]["PreToolUse"][0] == original["hooks"]["PreToolUse"][0]
    assert len(ours(data, "PreToolUse")) == 1
    (bak,) = s.parent.glob("settings.json.bak-*")
    assert json.loads(bak.read_text()) == original


def test_idempotent(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text("{}")
    install(s, PY)
    first = s.read_text()
    install(s, PY)
    install(s, PY)
    assert s.read_text() == first
    assert len(list(tmp_path.glob("settings.json.bak-*"))) == 1
    data = json.loads(first)
    assert len(ours(data, "PreToolUse")) == 1 and len(ours(data, "PostToolUse")) == 1


def test_updates_stale_entry_in_place(tmp_path):
    s = tmp_path / "settings.json"
    old_py = Path(r"C:\old\python.exe")
    install(s, old_py)
    install(s, PY)
    data = json.loads(s.read_text())
    (pre,) = ours(data, "PreToolUse")
    assert pre["hooks"][0]["command"] == hook_command(PY, "pre")
    # the first install had no file to back up; the second backed it up once
    assert len(list(tmp_path.glob("settings.json.bak-*"))) == 1


def test_second_backup_same_day_never_overwrites(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text('{"a": 1}')
    install(s, Path(r"C:\one\python.exe"))
    install(s, Path(r"C:\two\python.exe"))
    baks = sorted(tmp_path.glob("settings.json.bak-*"))
    assert len(baks) == 2
    assert json.loads(baks[0].read_text()) == {"a": 1} or json.loads(baks[1].read_text()) == {"a": 1}


def test_invalid_json_refused_untouched(tmp_path):
    s = tmp_path / "settings.json"
    s.write_text("{broken")
    with pytest.raises(ValueError):
        install(s, PY)
    assert s.read_text() == "{broken"


# ---------------------------------------------------------------- fix round 1: snapshot + shim

import subprocess  # noqa: E402
import sys  # noqa: E402

from gatekeeper import install_hooks as ih  # noqa: E402

REPO = Path(__file__).resolve().parents[2]


def test_shim_command_line():
    shim = Path(r"C:\Users\user\.gatekeeper\app\gatekeeper_hook_shim.py")
    assert ih.hook_command(PY, "pre", shim) == f'"{PY}" -I "{shim}" pre'


def test_legacy_module_entry_replaced_by_shim(tmp_path):
    s = tmp_path / "settings.json"
    install(s, PY)
    shim = tmp_path / "app" / "gatekeeper_hook_shim.py"
    assert install(s, PY, shim=shim) is True
    data = json.loads(s.read_text())
    (pre,) = ours_any(data, "PreToolUse")
    assert pre["hooks"][0]["command"] == ih.hook_command(PY, "pre", shim)
    assert install(s, PY, shim=shim) is False


def ours_any(data, event):
    return [e for e in data["hooks"][event]
            if any("gatekeeper" in h["command"] for h in e["hooks"])]


def worktree_tar() -> bytes:
    """Same layout as `git archive HEAD gatekeeper`, but from the working tree (tests run before commit)."""
    import io
    import tarfile
    buf = io.BytesIO()
    src = REPO / "gatekeeper"
    with tarfile.open(fileobj=buf, mode="w") as tf:
        tf.add(src / "gatekeeper_hook_shim.py", "gatekeeper/gatekeeper_hook_shim.py")
        tf.add(src / "gatekeeper", "gatekeeper/gatekeeper",
               filter=lambda ti: None if "__pycache__" in ti.name else ti)
    return buf.getvalue()


def test_archive_head_has_package():
    import io
    import tarfile
    names = tarfile.open(fileobj=io.BytesIO(ih.archive_head(REPO))).getnames()
    assert "gatekeeper/gatekeeper/hook.py" in names and all(n.startswith("gatekeeper") for n in names)


def test_snapshot_from_head_and_swap(tmp_path):
    tar = worktree_tar()
    app = ih.extract_snapshot(tar, tmp_path / "app")
    assert (app / "gatekeeper_hook_shim.py").is_file() and (app / "gatekeeper" / "hook.py").is_file()
    (app / "marker").write_text("old")
    ih.extract_snapshot(tar, tmp_path / "app")
    assert not (app / "marker").exists()
    assert (tmp_path / "app.prev" / "marker").exists()  # previous snapshot kept until the next deploy
    assert not (tmp_path / "app.new").exists() and not (tmp_path / "app.stage").exists()


def test_setup_makes_stdlib_venv_and_working_hook(tmp_path):
    tar = worktree_tar()
    app = ih.extract_snapshot(tar, tmp_path / "app")
    settings = tmp_path / ".claude" / "settings.json"
    py = ih.setup(app, tmp_path / "venv", settings)
    data = json.loads(settings.read_text())
    (pre,) = ours_any(data, "PreToolUse")
    cmd = pre["hooks"][0]["command"]
    assert cmd == ih.hook_command(py.absolute(), "pre", app.resolve() / "gatekeeper_hook_shim.py")
    probe = subprocess.run([str(py), "-I", "-c", "import gatekeeper.hook, sys; print(gatekeeper.hook.__file__)"],
                           capture_output=True, text=True, cwd=tmp_path, timeout=60)
    assert Path(probe.stdout.strip()).resolve().is_relative_to(app.resolve())
    pip = subprocess.run([str(py), "-I", "-c", "import pip"], capture_output=True, cwd=tmp_path, timeout=60)
    assert pip.returncode != 0  # stdlib only: no pip in the hook venv
    ev = json.dumps({"tool_name": "PowerShell", "tool_input": {"command": "irm x | iex"}, "cwd": str(tmp_path)})
    out = subprocess.run([str(py), "-I", str(app / "gatekeeper_hook_shim.py"), "pre"], input=ev.encode(),
                         capture_output=True, cwd=tmp_path, timeout=60)
    assert json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_wsl_path():
    assert ih._wsl_path(Path(r"C:\Users\user\.gatekeeper\deploy\x.tar")) == "/mnt/c/Users/user/.gatekeeper/deploy/x.tar"

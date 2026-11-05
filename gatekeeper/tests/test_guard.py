"""Guardrail-file change alerts."""
from datetime import datetime, timezone

from gatekeeper import guard
from gatekeeper.config import Config
from gatekeeper.state import State

NOW = datetime(2026, 11, 5, 3, 0, tzinfo=timezone.utc)


def env(tmp_path, outcome=True):
    f = tmp_path / "scope.yaml"
    f.write_text("repos:\n  - a\n  - b\n", encoding="utf-8")
    cfg = Config(home=tmp_path / "gk", guarded_files=[f])
    st = State(tmp_path / "s.db")
    pushes = []

    def notifier(title, body, severity, actions, cfg_, now):
        pushes.append({"title": title, "body": body, "severity": severity, "actions": actions})
        return outcome
    return f, cfg, st, pushes, notifier


def test_first_sight_is_silent_baseline(tmp_path):
    f, cfg, st, pushes, n = env(tmp_path)
    assert guard.check_once(cfg, st, n, NOW) == [] and pushes == []
    assert st.get_guard(str(f))["sha256"] != guard.MISSING


def test_unchanged_no_alert(tmp_path):
    f, cfg, st, pushes, n = env(tmp_path)
    guard.check_once(cfg, st, n, NOW)
    guard.check_once(cfg, st, n, NOW)
    assert pushes == []


def test_change_alerts_once_with_counts_and_no_content(tmp_path):
    f, cfg, st, pushes, n = env(tmp_path)
    guard.check_once(cfg, st, n, NOW)
    f.write_text("repos:\n  - a\n  - SECRETPATH\n  - c\n", encoding="utf-8")
    assert guard.check_once(cfg, st, n, NOW) == ["scope.yaml"]
    p = pushes[0]
    assert p["title"] == "Security file changed: scope.yaml" and p["severity"] == "critical"
    assert "+2 / -1 lines" in p["body"] and "SECRETPATH" not in p["body"] and p["actions"] is None
    guard.check_once(cfg, st, n, NOW)
    assert len(pushes) == 1  # new baseline: no repeat
    assert any(e["kind"] == "guard_change" for e in st.list_events())


def test_undelivered_push_retries(tmp_path):
    f, cfg, st, pushes, n = env(tmp_path, outcome=False)
    guard.check_once(cfg, st, n, NOW)
    f.write_text("changed\n", encoding="utf-8")
    guard.check_once(cfg, st, n, NOW)
    guard.check_once(cfg, st, n, NOW)
    assert len(pushes) == 2  # still alerting until one is delivered


def test_timed_out_push_counts_as_sent(tmp_path):
    f, cfg, st, pushes, n = env(tmp_path, outcome=None)
    guard.check_once(cfg, st, n, NOW)
    f.write_text("changed\n", encoding="utf-8")
    guard.check_once(cfg, st, n, NOW)
    guard.check_once(cfg, st, n, NOW)
    assert len(pushes) == 1


def test_delete_and_restore(tmp_path):
    f, cfg, st, pushes, n = env(tmp_path)
    guard.check_once(cfg, st, n, NOW)
    f.unlink()
    guard.check_once(cfg, st, n, NOW)
    f.write_text("back\n", encoding="utf-8")
    guard.check_once(cfg, st, n, NOW)
    assert [p["title"] for p in pushes] == ["Security file DELETED: scope.yaml", "Security file restored: scope.yaml"]


def test_change_while_stopped_alerts_on_next_start(tmp_path):
    f, cfg, st, pushes, n = env(tmp_path)
    guard.check_once(cfg, st, n, NOW)
    st.close()
    f.write_text("edited while gatekeeper was down\n", encoding="utf-8")
    st2 = State(tmp_path / "s.db")
    guard.check_once(cfg, st2, n, NOW)
    assert len(pushes) == 1
    st2.close()


def test_default_guarded_files_cover_scope_and_rules():
    names = [p.name for p in Config().guarded_files]
    assert names == ["scope.yaml", "AGENT_RULES.md", "GATEKEEPER_RULES.md"]


def test_config_toml_override(tmp_path):
    from gatekeeper.config import load_config
    t = tmp_path / "c.toml"
    t.write_text('guarded_files = ["C:/x/a.yaml"]\nguard_interval_s = 10\n', encoding="utf-8")
    c = load_config(t)
    assert [str(p).replace("\\", "/") for p in c.guarded_files] == ["C:/x/a.yaml"] and c.guard_interval_s == 10.0

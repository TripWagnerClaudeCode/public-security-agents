from pathlib import Path

from gatekeeper.config import load_config


def test_config_defaults_when_file_missing(tmp_path):
    cfg = load_config(tmp_path / "nope.toml")
    assert cfg.endpoint_port == 8766
    assert cfg.quiet_hours == (23, 8)
    assert cfg.tz == "UTC"
    assert cfg.endpoint_binds == ["127.0.0.1"]
    assert cfg.hook_timeout_s == 3.0
    assert cfg.pkg_cache_days == 7
    assert any(p.name == "Downloads" for p in cfg.watch_roots)


def test_config_overrides_from_file(tmp_path):
    f = tmp_path / "config.toml"
    f.write_text(
        'home = "%s"\nendpoint_port = 9000\nquiet_hours = [22, 7]\nwatch_roots = ["C:/x"]\n'
        % (tmp_path / "h").as_posix()
    )
    cfg = load_config(f)
    assert cfg.endpoint_port == 9000
    assert cfg.quiet_hours == (22, 7)
    assert cfg.watch_roots == [Path("C:/x")]
    assert cfg.home == tmp_path / "h"

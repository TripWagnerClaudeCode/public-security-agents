import logging

from gatekeeper import serve
from gatekeeper.config import Config


def test_malformed_config_logs_and_uses_defaults(tmp_path, monkeypatch, caplog):
    # Final review M9: a bad config.toml must not kill serve before anything is logged.
    def bad():
        raise ValueError("bad config.toml: line 3")
    monkeypatch.setattr(serve, "load_config", bad)
    monkeypatch.setattr(serve, "Config", lambda: Config(home=tmp_path / "gk"))
    seen = {}
    monkeypatch.setattr(serve, "setup_logging", lambda home: seen.setdefault("home", home))
    monkeypatch.setattr(serve, "acquire_lock", lambda path: seen.setdefault("lock", path) and None)
    with caplog.at_level(logging.ERROR, logger="gatekeeper"):
        assert serve.main([]) == 0
    assert seen["home"] == tmp_path / "gk"
    assert "config" in caplog.text and "defaults" in caplog.text

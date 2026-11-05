import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from gatekeeper.commands import PkgRef
from gatekeeper.packages import FetchError, assess, typo_target, urllib_fetcher
from gatekeeper.state import State

FIX = Path(__file__).parent / "fixtures" / "registry"
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)
OSV = "https://api.osv.dev/v1/query"


def fx(name):
    return json.loads((FIX / name).read_text())


class Fake:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def __call__(self, url, json_body=None):
        self.calls.append((url, json_body))
        r = self.routes.get(url)
        if r is None:
            raise FetchError("no route " + url, status=404)
        if isinstance(r, Exception):
            raise r
        return r


def no_fetch(url, json_body=None):
    raise AssertionError("no fetch expected")


@pytest.fixture
def state(tmp_path):
    s = State(tmp_path / "s.db")
    yield s
    s.close()


def pypi(name="requests", version=None):
    return PkgRef("pypi", name, version, "registry")


def test_popular_old_package_not_risky(state):
    f = Fake({"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"), OSV: fx("osv_none.json")})
    assert assess(pypi(), f, state, NOW) == []


def test_new_package_risky(state):
    f = Fake({"https://pypi.org/pypi/brandnewthing/json": fx("pypi_newpkg.json"), OSV: fx("osv_none.json")})
    r = assess(pypi("brandnewthing"), f, state, NOW)
    assert any("first published 20 days ago" in x for x in r)


def test_recent_latest_version_risky(state):
    f = Fake({"https://pypi.org/pypi/zq-oldlib/json": fx("pypi_recent_latest.json"), OSV: fx("osv_none.json")})
    r = assess(pypi("zq-oldlib"), f, state, NOW)
    assert any("published 10 days ago" in x for x in r)
    assert not any("first published" in x for x in r)


def test_selected_version_used(state):
    f = Fake({"https://pypi.org/pypi/zq-oldlib/json": fx("pypi_recent_latest.json"), OSV: fx("osv_none.json")})
    assert assess(pypi("zq-oldlib", "1.0.0"), f, state, NOW) == []
    assert f.calls[-1][1]["version"] == "1.0.0"


def test_typosquat(state):
    f = Fake({"https://pypi.org/pypi/reqeusts/json": fx("pypi_requests.json"), OSV: fx("osv_none.json")})
    r = assess(pypi("reqeusts"), f, state, NOW)
    assert any("looks like 'requests'" in x for x in r)


def test_top_package_not_typosquat():
    assert typo_target("request", "pypi") == "requests"
    assert typo_target("requests", "pypi") is None
    assert typo_target("Requests", "pypi") is None
    assert typo_target("reqeusts", "pypi") == "requests"
    assert typo_target("zzqqxxvvwwkk-unrelated", "pypi") is None
    assert typo_target("lodahs", "npm") == "lodash"
    assert typo_target("requests", "crates") is None


def test_not_found(state):
    f = Fake({"https://pypi.org/pypi/nope-nope-nope/json": FetchError("nf", status=404)})
    assert "not found on PyPI" in assess(pypi("nope-nope-nope"), f, state, NOW)


def test_osv_vuln(state):
    f = Fake({"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"), OSV: fx("osv_vuln.json")})
    r = assess(pypi(), f, state, NOW)
    assert any("known vulnerability GHSA-xxxx-yyyy-zzzz" in x for x in r)
    body = [c for c in f.calls if c[0] == OSV][0][1]
    assert body == {"package": {"name": "requests", "ecosystem": "PyPI"}, "version": "2.31.0"}


def test_npm_install_scripts(state):
    f = Fake({"https://registry.npmjs.org/evilthing": fx("npm_postinstall.json"), OSV: fx("osv_none.json")})
    r = assess(PkgRef("npm", "evilthing", None, "registry"), f, state, NOW)
    assert "runs install scripts" in r


def test_npm_no_install_scripts(state):
    f = Fake({"https://registry.npmjs.org/zq-fine": fx("npm_clean.json"), OSV: fx("osv_none.json")})
    assert assess(PkgRef("npm", "zq-fine", None, "registry"), f, state, NOW) == []


def test_crates_and_go(state):
    crate = {"crate": {"created_at": "2026-10-30T00:00:00Z", "max_version": "0.1.0"},
             "versions": [{"num": "0.1.0", "created_at": "2026-10-30T00:00:00Z"}]}
    f = Fake({"https://crates.io/api/v1/crates/shiny": crate, OSV: {}})
    r = assess(PkgRef("crates", "shiny", None, "registry"), f, state, NOW)
    assert any("first published 4 days ago" in x for x in r)
    f = Fake({"https://proxy.golang.org/github.com/!foo/bar/@latest":
              {"Version": "v1.0.0", "Time": "2020-01-01T00:00:00Z"}, OSV: {}})
    assert assess(PkgRef("go", "github.com/Foo/bar", None, "registry"), f, state, NOW) == []


@pytest.mark.parametrize("src", ["url", "git", "path"])
def test_url_git_path_always_risky(state, src):
    assert assess(PkgRef("pypi", "whatever", None, src), no_fetch, state, NOW) == ["installed from a URL/git/path"]


def test_other_ecosystems_no_registry_checks(state):
    assert assess(PkgRef("winget", "Git.Git", None, "registry"), no_fetch, state, NOW) == []


def test_requirements_file_expanded(state, tmp_path):
    (tmp_path / "other.txt").write_text("nope-nope-nope\n")
    (tmp_path / "reqs.txt").write_text(
        "# comment\n--index-url https://x\nrequests==2.31.0\n\nbrandnewthing>=0.1\n-r other.txt\n"
        "-e ./local\nhttps://example.com/p.whl\n")
    f = Fake({
        "https://pypi.org/pypi/requests/json": fx("pypi_requests.json"),
        "https://pypi.org/pypi/brandnewthing/json": fx("pypi_newpkg.json"),
        "https://pypi.org/pypi/nope-nope-nope/json": FetchError("nf", status=404),
        OSV: fx("osv_none.json")})
    r = assess(PkgRef("pypi", "reqs.txt", None, "requirements"), f, state, NOW, cwd=tmp_path)
    assert any("brandnewthing" in x and "first published 20 days ago" in x for x in r)
    assert any("nope-nope-nope" in x and "not found on PyPI" in x for x in r)
    assert any("installed from a URL/git/path" in x for x in r)
    assert not any(x.startswith("requests") for x in r)


def test_requirements_unreadable(state, tmp_path):
    r = assess(PkgRef("pypi", "missing.txt", None, "requirements"), Fake({}), state, NOW, cwd=tmp_path)
    assert any("couldn't read requirements file" in x for x in r)


def test_offline_cached_ok(state):
    url = "https://pypi.org/pypi/requests/json"
    online = Fake({url: fx("pypi_requests.json"), OSV: fx("osv_none.json")})
    first = assess(pypi(), online, state, NOW)
    offline = Fake({url: FetchError("down", status=None), OSV: FetchError("down", status=None)})
    assert assess(pypi(), offline, state, NOW) == first


def test_offline_uncached(state):
    dead = Fake({"https://pypi.org/pypi/requests/json": FetchError("down", status=None)})
    assert assess(pypi(), dead, state, NOW) == ["couldn't check (offline)"]


def test_cache_used_within_7_days(state):
    f = Fake({"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"), OSV: fx("osv_none.json")})
    assess(pypi(), f, state, NOW)
    n = len(f.calls)
    assert n > 0
    assess(pypi(), f, state, NOW)
    assert len(f.calls) == n


def test_urllib_fetcher_factory():
    assert callable(urllib_fetcher(1.0))


# ---------------------------------------------------------------- fix round 1

import http.server
import threading
import time


def npm_doc(created="2020-01-01T00:00:00.000Z"):
    return {"dist-tags": {"latest": "4.17.21", "next": "5.0.0-beta.1"},
            "time": {"created": created, "4.17.21": created, "5.0.0-beta.1": created},
            "versions": {"4.17.21": {}, "5.0.0-beta.1": {}}}


@pytest.mark.parametrize("ver", ["latest", "^4", "~4.17", ">=1,<2", "4.x", "*", "^4 || ^5", "next", "4.17.21"])
def test_npm_tags_and_ranges_not_risky(state, ver):
    f = Fake({"https://registry.npmjs.org/zq-lodash": npm_doc(), OSV: {}})
    assert assess(PkgRef("npm", "zq-lodash", ver, "registry"), f, state, NOW) == []


def test_npm_range_uses_latest_cache_key_and_tag_resolves(state):
    f = Fake({"https://registry.npmjs.org/zq-lodash": npm_doc(), OSV: {}})
    assess(PkgRef("npm", "zq-lodash", "^4", "registry"), f, state, NOW)
    assert state.cache_get("npm", "zq-lodash", "", 7) is not None
    assess(PkgRef("npm", "zq-lodash", "next", "registry"), f, state, NOW)
    assert f.calls[-1][1]["version"] == "5.0.0-beta.1"


@pytest.mark.parametrize("ver", [">=1,<2", "==2.*", "2.*", "~=2.1", "!=1.0"])
def test_pypi_specifiers_use_latest(state, ver):
    f = Fake({"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"), OSV: {}})
    assert assess(pypi("requests", ver), f, state, NOW) == []
    assert f.calls[-1][1]["version"] == "2.31.0"


def test_crates_range_uses_latest(state):
    crate = {"crate": {"created_at": "2020-01-01T00:00:00Z", "max_version": "1.2.3"},
             "versions": [{"num": "1.2.3", "created_at": "2020-01-01T00:00:00Z"}]}
    f = Fake({"https://crates.io/api/v1/crates/zq-crate": crate, OSV: {}})
    assert assess(PkgRef("crates", "zq-crate", "^1.2", "registry"), f, state, NOW) == []


def test_exact_but_missing_version_not_found(state):
    f = Fake({"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"), OSV: {}})
    assert assess(pypi("requests", "9.9.9"), f, state, NOW) == ["version 9.9.9 not found on PyPI"]
    f = Fake({"https://registry.npmjs.org/zq-lodash": npm_doc(), OSV: {}})
    assert assess(PkgRef("npm", "zq-lodash", "9.9.9", "registry"), f, state, NOW) == \
        ["version 9.9.9 not found on npm"]
    assert assess(PkgRef("npm", "zq-lodash", "nosuchtag", "registry"), f, state, NOW) == \
        ["version nosuchtag not found on npm"]


def test_nested_requirements_followed_three_levels(state, tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\n")
    (tmp_path / "b.txt").write_text("-r c.txt\n")
    (tmp_path / "c.txt").write_text("-r d.txt\n")
    (tmp_path / "d.txt").write_text("zq-deep\n-r e.txt\n")
    (tmp_path / "e.txt").write_text("zq-toodeep\n")
    f = Fake({"https://pypi.org/pypi/zq-deep/json": fx("pypi_requests.json"), OSV: {}})
    r = assess(PkgRef("pypi", "a.txt", None, "requirements"), f, state, NOW, cwd=tmp_path)
    assert "nested requirements not followed" in r
    assert any("zq-deep" in c[0] for c in f.calls)
    assert not any("zq-toodeep" in c[0] for c in f.calls)


def test_requirements_cycle_safe(state, tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\n")
    (tmp_path / "b.txt").write_text("-r a.txt\n")
    assert assess(PkgRef("pypi", "a.txt", None, "requirements"), Fake({}), state, NOW, cwd=tmp_path) == []


def test_requirements_line_not_understood(state, tmp_path):
    (tmp_path / "r.txt").write_text("!!!weird-line-that-is-long-enough-to-be-truncated-here\n--hash=sha256:abc\n--pre\n")
    r = assess(PkgRef("pypi", "r.txt", None, "requirements"), Fake({}), state, NOW, cwd=tmp_path)
    assert r == ["requirements line not understood: !!!weird-line-that-is-long-enough-to-be-"]


def test_requirements_index_options_flagged(state, tmp_path):
    (tmp_path / "r.txt").write_text(
        "-i https://evil.example/simple\n--extra-index-url=https://x.example:8080/s\n"
        "--find-links /srv/wheels\n--trusted-host evil.example\n-r sub.txt\n-c cons.txt\n")
    (tmp_path / "sub.txt").write_text("--extra-index-url https://nested.example/simple\n")
    (tmp_path / "cons.txt").write_text("requests==2.0\n--index-url https://cons.example/simple\n-r cons2.txt\n")
    (tmp_path / "cons2.txt").write_text("--find-links https://deep.example/w\nnot-a-package\n")
    f = Fake({})
    r = assess(PkgRef("pypi", "r.txt", None, "requirements"), f, state, NOW, cwd=tmp_path)
    assert r == [
        "custom package index/source: -i evil.example",
        "custom package index/source: --extra-index-url x.example:8080",
        "custom package index/source: --find-links /srv/wheels",
        "custom package index/source: --trusted-host evil.example",
        "custom package index/source: --extra-index-url nested.example",
        "custom package index/source: --index-url cons.example",
        "custom package index/source: --find-links deep.example",
    ]
    assert f.calls == []  # constraints add no packages


def test_requirements_entry_cap(state, tmp_path):
    (tmp_path / "r.txt").write_text("".join(f"zq-pkg-{i}\n" for i in range(55)))
    f = Fake({})
    r = assess(PkgRef("pypi", "r.txt", None, "requirements"), f, state, NOW, cwd=tmp_path)
    assert "requirements file has more than 50 packages; rest not checked" in r
    assert len([c for c in f.calls if c[0].startswith("https://pypi.org")]) == 50


def test_negative_age_clamped(state):
    future = fx("pypi_newpkg.json")
    future["releases"]["0.1.0"][0]["upload_time_iso_8601"] = "2026-12-01T00:00:00Z"
    f = Fake({"https://pypi.org/pypi/zq-future/json": future, OSV: {}})
    r = assess(pypi("zq-future"), f, state, NOW)
    assert "first published 0 days ago" in r
    assert not any("-" in x.split("published")[1] for x in r if "published" in x)


def test_typo_distance_by_length():
    from gatekeeper.packages import _typo_limit
    assert _typo_limit("abcde") == 1 and _typo_limit("abcdef") == 2
    assert typo_target("reqeusts", "pypi") == "requests"
    assert typo_target("requessts", "pypi") == "requests"
    assert typo_target("rqeuests", "pypi") == "requests"


def test_cache_expiry_refetches(state):
    f = Fake({"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"), OSV: {}})
    assess(pypi(), f, state, NOW)
    n = len(f.calls)
    payload = state.cache_get("pypi", "requests", "", 7)
    state.cache_put("pypi", "requests", "", payload, at=time.time() - 8 * 86400)
    assess(pypi(), f, state, NOW)
    assert len(f.calls) > n


def test_404_result_cached(state):
    f = Fake({"https://pypi.org/pypi/zq-gone/json": FetchError("nf", status=404)})
    assert assess(pypi("zq-gone"), f, state, NOW) == ["not found on PyPI"]
    n = len(f.calls)
    assert assess(pypi("zq-gone"), f, state, NOW) == ["not found on PyPI"]
    assert len(f.calls) == n


def test_unexpected_registry_response(state):
    f = Fake({"https://pypi.org/pypi/zq-odd/json": {"releases": [1, 2]}})
    assert assess(pypi("zq-odd"), f, state, NOW) == ["couldn't check (unexpected registry response)"]


@pytest.fixture
def local_server():
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, body=b"{}"):
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/ok":
                self._send(200, b'{"a": 1}')
            elif self.path == "/boom":
                self._send(500)
            elif self.path == "/bad":
                self._send(200, b"not json")
            else:
                self._send(404)

        def do_POST(self):
            n = int(self.headers["Content-Length"])
            self._send(200, self.rfile.read(n))

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_urllib_fetcher_get_post_and_errors(local_server):
    fetch = urllib_fetcher(2.0)
    assert fetch(local_server + "/ok", None) == {"a": 1}
    assert fetch(local_server + "/echo", {"x": [1]}) == {"x": [1]}
    with pytest.raises(FetchError) as e:
        fetch(local_server + "/missing", None)
    assert e.value.status == 404
    with pytest.raises(FetchError) as e:
        fetch(local_server + "/boom", None)
    assert e.value.status == 500
    with pytest.raises(FetchError) as e:
        fetch(local_server + "/bad", None)
    assert e.value.status is None


def test_urllib_fetcher_network_failure_has_no_status():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(FetchError) as e:
        urllib_fetcher(1.0)(f"http://127.0.0.1:{port}/x", None)
    assert e.value.status is None


# ---------------------------------------------------------------- fix round 2

def test_index_option_reason_has_no_credentials(state, tmp_path):
    (tmp_path / "r.txt").write_text(
        "--index-url https://user:s3cr3ttoken@private.example:8443/simple?k=tok2\n"
        "-f https://u:tok3@files.example/w\n--trusted-host u:tok4@h.example\n")
    r = assess(PkgRef("pypi", "r.txt", None, "requirements"), Fake({}), state, NOW, cwd=tmp_path)
    assert r == ["custom package index/source: --index-url private.example:8443",
                 "custom package index/source: -f files.example",
                 "custom package index/source: --trusted-host h.example"]
    joined = " ".join(r)
    for secret in ("s3cr3ttoken", "tok2", "tok3", "tok4", "user", "/simple"):
        assert secret not in joined


@pytest.mark.parametrize("ver", ["4", "4.17"])
def test_npm_partial_version_is_range(state, ver):
    f = Fake({"https://registry.npmjs.org/zq-lodash": npm_doc(), OSV: {}})
    assert assess(PkgRef("npm", "zq-lodash", ver, "registry"), f, state, NOW) == []
    assert state.cache_get("npm", "zq-lodash", "", 7) is not None


def test_npm_full_version_still_exact(state):
    f = Fake({"https://registry.npmjs.org/zq-lodash": npm_doc(), OSV: {}})
    assert assess(PkgRef("npm", "zq-lodash", "4.17.21", "registry"), f, state, NOW) == []
    assert state.cache_get("npm", "zq-lodash", "4.17.21", 7) is not None
    assert assess(PkgRef("npm", "zq-lodash", "4.17.20", "registry"), f, state, NOW) == \
        ["version 4.17.20 not found on npm"]


def test_cargo_partial_version_is_range(state):
    crate = {"crate": {"created_at": "2020-01-01T00:00:00Z", "max_version": "1.2.3"},
             "versions": [{"num": "1.2.3", "created_at": "2020-01-01T00:00:00Z"}]}
    f = Fake({"https://crates.io/api/v1/crates/zq-crate": crate, OSV: {}})
    assert assess(PkgRef("crates", "zq-crate", "1.2", "registry"), f, state, NOW) == []


def test_pypi_short_exact_version_stays_literal(state):
    f = Fake({"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"), OSV: {}})
    assert assess(pypi("requests", "2.1"), f, state, NOW) == ["version 2.1 not found on PyPI"]


# ---------------------------------------------------------------- fix round 3

import re as _re

from gatekeeper.packages import redact_urls


def test_redact_urls_unit():
    assert redact_urls("git+https://u:T@g.example/r.git#egg=x&subdirectory=a") == "git+https://g.example/r.git#egg=x"
    assert redact_urls("https://h/x.whl?sig=SECRET#frag") == "https://h/x.whl"
    assert redact_urls("ssh://git@github.com/a/b") == "ssh://github.com/a/b"
    assert redact_urls("git@github.com:a/b.git") == "github.com:a/b.git"
    assert redact_urls("plain text, no urls @scope/pkg") == "plain text, no urls @scope/pkg"


def test_credentials_never_in_reasons(state, tmp_path):
    (tmp_path / "r.txt").write_text(
        "https://u:TOK1@h.example/a.whl?sig=TOK5\n"
        "foo @ git+https://u:TOK2@g.example/r.git\n"
        "-e git+https://u:TOK3@g.example/r.git#egg=x\n"
        "-e git+ssh://git@github.com/a/b\n")
    r = assess(PkgRef("pypi", "r.txt", None, "requirements"), no_fetch, state, NOW, cwd=tmp_path)
    assert len(r) == 4
    blob = " ".join(r)
    for secret in ("TOK1", "TOK2", "TOK3", "TOK5", "u:", "git@"):
        assert secret not in blob
    assert "h.example/a.whl" in blob and "#egg=x" in blob
    npm = assess(PkgRef("npm", "foo@https://u:TOK4@h.example/x.tgz", None, "url"), no_fetch, state, NOW)
    npm += assess(PkgRef("npm", "git+ssh://git@github.com/a/b", None, "git"), no_fetch, state, NOW)
    assert npm == ["installed from a URL/git/path"] * 2


def test_reason_echoing_name_is_redacted(state):
    f = Fake({"https://registry.npmjs.org/foo@https:%2F%2Fu:TOK6@h.example%2Fx.tgz": FetchError("nf", 404)})
    r = assess(PkgRef("npm", "foo@https://u:TOK6@h.example/x.tgz", None, "registry"), f, state, NOW)
    assert "TOK6" not in " ".join(r)


def test_no_userinfo_survives_any_fixture_case(state, tmp_path):
    (tmp_path / "r.txt").write_text(
        "-i https://u:p@x.example/s\nfoo @ https://a:b@c.example/f.whl\n-e git+ssh://git@github.com/a/b\n"
        "requests\nzq-new\n")
    cases = [
        (pypi("requests"), {"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"), OSV: fx("osv_vuln.json")}),
        (pypi("zq-new"), {"https://pypi.org/pypi/zq-new/json": fx("pypi_newpkg.json"), OSV: {}}),
        (pypi("reqeusts"), {"https://pypi.org/pypi/reqeusts/json": fx("pypi_requests.json"), OSV: {}}),
        (PkgRef("npm", "evilthing", None, "registry"),
         {"https://registry.npmjs.org/evilthing": fx("npm_postinstall.json"), OSV: {}}),
        (PkgRef("pypi", "r.txt", None, "requirements"),
         {"https://pypi.org/pypi/requests/json": fx("pypi_requests.json"),
          "https://pypi.org/pypi/zq-new/json": fx("pypi_newpkg.json"), OSV: {}}),
        (PkgRef("npm", "x@https://u:T@h/x.tgz", None, "url"), {}),
        (pypi("zq-gone"), {}),
    ]
    for pkg, routes in cases:
        for reason in assess(pkg, Fake(routes), State(tmp_path / f"{id(pkg)}.db"), NOW, cwd=tmp_path):
            assert not _re.search(r"://[^\s/]*@|\w@[\w.-]+:", reason), reason


@pytest.mark.parametrize("text,host,secrets", [
    ("https://u:p@ss@h/a", "https://h/a", ("p@", "ss", "u:")),
    ("https://h:pw@x@h2/a", "https://h2/a", ("pw", "x@", "h:")),
    ("https://u:p@@h/a", "https://h/a", ("p@", "u:", "@")),
    ("git+https://u:p@ss@g.example/r.git#egg=x", "git+https://g.example/r.git#egg=x", ("p@", "ss")),
    ("ssh://git:p@zz@github.com/a/b", "ssh://github.com/a/b", ("p@", "zz", "git:")),
])
def test_redact_urls_splits_userinfo_at_last_at(text, host, secrets):
    out = redact_urls(text)
    assert out == host
    for s in secrets:
        assert s not in out


def test_redact_urls_schemeless_authority():
    assert redact_urls("see //user:tok@host.example/a.whl now") == "see //host.example/a.whl now"
    assert redact_urls("//u:p@ss@h/a") == "//h/a"
    assert redact_urls("x //plain comment, a//b") == "x //plain comment, a//b"


def test_redact_urls_preserved_behaviour():
    assert redact_urls("https://u:p@[::1]:8080/x") == "https://[::1]:8080/x"
    assert redact_urls("https://u%40x:p%3Aq@h/a") == "https://h/a"
    assert redact_urls('("https://u:p@h/a")') == '("https://h/a")'
    assert redact_urls("'https://u:p@h/a'") == "'https://h/a'"
    assert redact_urls("https://u:p@h/a, next") == "https://h/a, next"
    assert redact_urls("https://h/a?t=SECRET, next") == "https://h/a, next"
    assert redact_urls("mail bob@example.com about @scope/pkg") == "mail bob@example.com about @scope/pkg"
    assert redact_urls("https://h/a@b/c") == "https://h/a@b/c"
    assert redact_urls("git+https://h/r.git#egg=name") == "git+https://h/r.git#egg=name"

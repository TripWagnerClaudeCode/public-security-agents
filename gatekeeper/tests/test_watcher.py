import dataclasses
import os
import threading
import time
from pathlib import Path

import pytest

import gatekeeper.watcher as watcher_mod

from gatekeeper.config import Config
from gatekeeper.facts import Finding
from gatekeeper.quarantine import default_root
from gatekeeper.state import State
from lnk_samples import make_lnk
from gatekeeper import facts as facts_mod
from gatekeeper.watcher import RETRY, Pipeline, Scanners, Watcher, doorway_for, is_excluded, is_temp_name


# ---------------------------------------------------------------- fixtures

@pytest.fixture
def roots(tmp_path):
    dl = tmp_path / "Downloads"
    desk = tmp_path / "Desktop"
    hub = tmp_path / "Documents" / "Synced"
    for d in (dl, desk, hub / "projects"):
        d.mkdir(parents=True)
    cfg = Config(home=tmp_path / "gk", watch_roots=[dl, desk, hub], code_tree_roots=[hub / "projects"])
    return cfg, dl, desk, hub


class FakeScanners:
    """Records every call; per-scanner results or exceptions can be set."""

    def __init__(self):
        self.calls = []
        self.results = {"defender": [], "yara": [], "gitleaks": []}
        self.raise_in = set()

    def _run(self, name, path):
        self.calls.append((name, Path(path).name))
        if name in self.raise_in:
            raise RuntimeError(f"{name} exploded")
        return list(self.results[name])

    def build(self) -> Scanners:
        return Scanners(
            motw=lambda p: self.calls.append(("motw", p.name)) or None,
            signature=lambda p: self.calls.append(("signature", p.name)) or "unsigned",
            defender=lambda p: self._run("defender", p),
            yara=lambda p: self._run("yara", p),
            gitleaks=lambda p: self._run("gitleaks", p),
        )


@pytest.fixture
def pipe(roots, tmp_path):
    cfg, dl, desk, hub = roots
    st = State(tmp_path / "s.db")
    fs = FakeScanners()
    pushes = []

    def fake_push(title, body, severity, actions, cfg_, now):
        pushes.append({"title": title, "body": body, "severity": severity, "actions": actions})
        return True

    p = Pipeline(cfg, st, fs.build(), notifier=fake_push)
    yield p, fs, pushes, st, cfg, dl, hub
    st.close()


class RecordingPipeline:
    def __init__(self, watcher_ref=None, delay=0.0):
        self.handled = []
        self.lock = threading.Lock()
        self.delay = delay
        self.watcher = None
        self.max_q = 0

    def handle(self, path, doorway, final=True):
        if self.watcher is not None:
            self.max_q = max(self.max_q, self.watcher.queue.qsize())
        if self.delay:
            time.sleep(self.delay)
        with self.lock:
            self.handled.append((Path(path), doorway))
        return "clean"

    def names(self):
        with self.lock:
            return [p.name for p, _ in self.handled]


def start_watcher(cfg, pipeline, **kw):
    stop = threading.Event()
    kw.setdefault("stable_s", 0.6)
    kw.setdefault("poll_s", 0.1)
    w = Watcher(cfg, pipeline, stop, **kw)
    pipeline.watcher = w
    t = threading.Thread(target=w.run, daemon=True)
    t.start()
    assert w.ready.wait(10)
    return w, stop, t


def wait_for(cond, timeout=15.0):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


@pytest.fixture
def watching(roots):
    cfg = roots[0]
    rec = RecordingPipeline()
    w, stop, t = start_watcher(cfg, rec)
    yield rec, w, roots
    stop.set()
    t.join(10)
    assert not t.is_alive()


# ---------------------------------------------------------------- pure helpers

@pytest.mark.parametrize("name", ["x.crdownload", "x.part", "~syncthing~x.tmp", ".syncthing.x.tmp",
                                  "X.CRDOWNLOAD", "~syncthing~report.pdf.tmp"])
def test_temp_names_are_ignored(name):
    assert is_temp_name(name)


@pytest.mark.parametrize("name", ["x.exe", "x.tmp", "part.txt", "syncthing.txt", "x.partial.zip"])
def test_final_names_are_not_temp(name):
    assert not is_temp_name(name)


@pytest.mark.parametrize("rel", [
    ".git/config", "proj/.git/HEAD", "proj/.venv/x.py", "proj/venv/x.py", "proj/node_modules/a/b.js",
    "proj/__pycache__/m.pyc", ".stversions/old.docx", ".stfolder/x", "proj/.stversions/y.txt",
])
def test_excluded_dirs(roots, rel):
    cfg, dl, desk, hub = roots
    assert is_excluded(hub / rel, cfg)
    assert is_excluded(dl / rel, cfg)


def test_excluded_build_output_and_scratch_subpath(roots, monkeypatch):
    monkeypatch.setattr(watcher_mod, "EXCLUDED_SUBPATHS", [("projects", "my-tool", "work")])
    cfg, dl, desk, hub = roots
    proj = hub / "projects" / "app"
    assert is_excluded(proj / "bin" / "Debug" / "app.dll", cfg)
    assert is_excluded(proj / "obj" / "x.cache", cfg)
    assert is_excluded(hub / "projects" / "my-tool" / "work" / "clip.mp4", cfg)
    assert is_excluded(hub / "projects" / "My-Tool" / "WORK" / "a" / "b.txt", cfg)
    assert not is_excluded(hub / "projects" / "my-tool" / "notes.md", cfg)
    assert not is_excluded(hub / "projects" / "app" / "src" / "main.py", cfg)


def test_bin_obj_outside_a_code_tree_still_scanned(roots):
    # A downloaded tool unpacked into Downloads\tool\bin is not build output: it must still be scanned.
    cfg, dl, desk, hub = roots
    assert not is_excluded(dl / "tool" / "bin" / "setup.exe", cfg)
    assert not is_excluded(desk / "obj" / "a.ps1", cfg)


def test_bin_inside_git_repo_is_build_output(roots):
    cfg, dl, desk, hub = roots
    repo = dl / "cloned"
    (repo / ".git").mkdir(parents=True)
    assert is_excluded(repo / "bin" / "a.exe", cfg)


def test_quarantine_root_and_home_excluded(roots):
    cfg, dl, desk, hub = roots
    cfg.home = dl / "gkhome"
    assert is_excluded(default_root(cfg) / "2026-11-03" / "abc" / "x.exe.quarantined", cfg)
    assert is_excluded(cfg.home / "state.db", cfg)


def test_outside_watch_roots_excluded(roots, tmp_path):
    cfg = roots[0]
    assert is_excluded(tmp_path / "elsewhere" / "x.exe", cfg)


def test_doorway(roots):
    cfg, dl, desk, hub = roots
    assert doorway_for(dl / "a.zip", cfg) == "download"
    assert doorway_for(desk / "sub" / "a.zip", cfg) == "download"
    assert doorway_for(hub / "projects" / "a.py", cfg) == "sync"
    assert doorway_for(hub / "x.docx", cfg) == "sync"


# ---------------------------------------------------------------- pipeline

def test_clean_no_push_and_cached(pipe):
    p, fs, pushes, st, cfg, dl, hub = pipe
    f = hub / "notes.txt"
    f.write_text("hello", encoding="utf-8")
    assert p.handle(f, "sync") == "clean"
    assert pushes == []
    assert f.exists()
    assert {c[0] for c in fs.calls} >= {"defender", "yara", "gitleaks"}
    ev = [e for e in st.list_events() if e["kind"] == "file"]
    assert ev[-1]["verdict"] == "clean" and ev[-1]["path"] == str(f)

    fs.calls.clear()
    g = dl / "copy.txt"
    g.write_text("hello", encoding="utf-8")
    assert p.handle(g, "download") == "clean"
    assert fs.calls == [("motw", "copy.txt")]  # cached-clean hash: no scanners


def test_released_hash_skips_scanners(pipe):
    p, fs, pushes, st, cfg, dl, hub = pipe
    f = dl / "tool.exe"
    f.write_bytes(b"MZ not really")
    import hashlib
    st.put_verdict(hashlib.sha256(b"MZ not really").hexdigest(), "clean")
    assert p.handle(f, "download") == "clean"
    assert not any(c[0] in ("defender", "yara", "gitleaks", "signature") for c in fs.calls)
    assert pushes == [] and f.exists()


def test_risky_quarantined_with_one_push(pipe):
    p, fs, pushes, st, cfg, dl, hub = pipe
    fs.results["yara"] = [Finding("yara_match", "YARA rule matched: TEST_RULE", "critical")]
    f = dl / "invoice.pdf"
    f.write_bytes(b"%PDF-1.4\n%%EOF\n")
    assert p.handle(f, "download") == "risky"
    assert not f.exists()
    held = list(default_root(cfg).rglob("invoice.pdf.quarantined"))
    assert len(held) == 1 and (held[0].parent / "meta.json").is_file()
    assert len(pushes) == 1
    push = pushes[0]
    assert push["title"] == "Quarantined: invoice.pdf"
    assert "TEST_RULE" in push["body"]
    assert push["severity"] == "critical"
    labels = [a["label"] for a in push["actions"]]
    assert labels == ["Release", "Keep blocked"]
    qid = held[0].parent.name
    assert all(f"/q/{qid}/" in a["url"] for a in push["actions"])
    assert st.get_quarantine(qid)["status"] == "held"
    assert st.get_verdict(st.get_quarantine(qid)["sha256"]) is None  # never cached as clean


def test_risky_by_type_rule_has_reason(pipe):
    # unsigned script from the internet: no scanner finding, the type rule makes it risky
    p, fs, pushes, st, cfg, dl, hub = pipe
    f = dl / "setup.ps1"
    f.write_text("Write-Host hi", encoding="utf-8")
    assert p.handle(f, "download") == "risky"
    assert len(pushes) == 1 and pushes[0]["severity"] == "risky"
    assert "unsigned" in pushes[0]["body"] and "internet" in pushes[0]["body"]
    assert ("signature", "setup.ps1") in fs.calls


def test_secret_pushes_and_file_stays(pipe):
    p, fs, pushes, st, cfg, dl, hub = pipe
    fs.results["gitleaks"] = [Finding("secret_in_file", "aws-access-token at line 3 (redacted)", "secret")]
    f = hub / "creds.env"
    f.write_text("x=1\n", encoding="utf-8")
    assert p.handle(f, "sync") == "secret"
    assert f.exists()
    assert len(pushes) == 1
    assert pushes[0]["actions"] is None
    assert "aws-access-token" in pushes[0]["body"]
    assert not list(default_root(cfg).rglob("*.quarantined"))


def test_scanner_exception_is_notice(pipe):
    p, fs, pushes, st, cfg, dl, hub = pipe
    fs.raise_in = {"defender"}
    f = hub / "report.txt"
    f.write_text("fine", encoding="utf-8")
    assert p.handle(f, "sync") == "notice"
    assert f.exists() and pushes == []
    ev = [e for e in st.list_events() if e["kind"] == "file"][-1]
    assert ev["verdict"] == "notice"
    assert any("defender" in r for r in ev["reasons"])
    assert st.get_verdict(ev["sha256"]) is None  # a failed scan is not a clean judgement


def test_vanished_file_does_not_crash(pipe):
    p, fs, pushes, st, cfg, dl, hub = pipe
    assert p.handle(dl / "gone.zip", "download") == "notice"
    assert pushes == []


def test_on_clean_called_for_clean_and_notice(pipe):
    p, fs, pushes, st, cfg, dl, hub = pipe
    seen = []
    assert p.on_clean == []
    p.on_clean.append(lambda path, facts, verdict: seen.append((path.name, facts.sha256[:4], verdict)))
    p.on_clean.append(lambda path, facts, verdict: 1 / 0)  # a broken hook never breaks the pipeline
    a = hub / "a.txt"
    a.write_text("a", encoding="utf-8")
    b = hub / "b.txt"
    b.write_text("b", encoding="utf-8")
    assert p.handle(a, "sync") == "clean"
    fs.raise_in = {"yara"}
    assert p.handle(b, "sync") == "notice"
    fs.raise_in = set()
    fs.results["yara"] = [Finding("yara_match", "YARA rule matched: X", "critical")]
    c = dl / "c.txt"
    c.write_text("c", encoding="utf-8")
    assert p.handle(c, "download") == "risky"
    assert [s[0] for s in seen] == ["a.txt", "b.txt"]
    assert [s[2] for s in seen] == ["clean", "notice"]


def test_on_verdict_called_for_every_verdict_with_findings(pipe, monkeypatch):
    from gatekeeper import watcher as W
    p, fs, pushes, st, cfg, dl, hub = pipe
    seen = []
    p.on_verdict.append(lambda path, facts, verdict, findings:
                        seen.append((path.name, facts.sha256 is not None, verdict, [f.code for f in findings])))
    p.on_verdict.append(lambda *a: 1 / 0)  # a broken hook never breaks the pipeline
    a = dl / "a.txt"
    a.write_text("a", encoding="utf-8")
    assert p.handle(a, "download") == "clean"
    assert p.handle(a, "download") == "clean"  # cached
    fs.raise_in = {"yara"}
    b = dl / "b.txt"
    b.write_text("b", encoding="utf-8")
    assert p.handle(b, "download") == "notice"
    fs.raise_in = set()
    fs.results["gitleaks"] = [Finding("secret_in_file", "aws key", "secret")]
    c = dl / "c.txt"
    c.write_text("c", encoding="utf-8")
    assert p.handle(c, "download") == "secret"
    fs.results["gitleaks"] = []
    fs.results["yara"] = [Finding("yara_match", "YARA rule matched: X", "critical")]
    d = dl / "d.pdf"
    d.write_bytes(b"%PDF-1.4\n%%EOF\n")
    assert p.handle(d, "download") == "risky"
    e = dl / "e.pdf"
    e.write_bytes(b"%PDF-1.4\n%%EOF\n%e\n")

    def fail(*a, **k):
        raise W.QuarantineError("locked")
    monkeypatch.setattr(W, "quarantine", fail)
    assert p.handle(e, "download") == "risky"
    assert [(s[0], s[2]) for s in seen] == [("a.txt", "clean"), ("a.txt", "clean"), ("b.txt", "notice"),
                                            ("c.txt", "secret"), ("d.pdf", "risky"), ("e.pdf", "risky")]
    assert all(s[1] for s in seen)
    assert "yara_error" in seen[2][3] and seen[3][3] == ["secret_in_file"]
    assert len(pushes) == 3  # secret, quarantined, not quarantined: hooks never replace the pushes


def test_raising_on_clean_hook_does_not_block_quarantine(pipe):
    p, fs, pushes, st, cfg, dl, hub = pipe
    p.on_clean.append(lambda path, facts, verdict: 1 / 0)
    fs.results["yara"] = [Finding("yara_match", "YARA rule matched: TEST_RULE", "critical")]
    f = dl / "invoice.pdf"
    f.write_bytes(b"%PDF-1.4\n%%EOF\n")
    assert p.handle(f, "download") == "risky"
    assert not f.exists() and len(list(default_root(cfg).rglob("invoice.pdf.quarantined"))) == 1
    assert len(pushes) == 1


# ---------------------------------------------------------------- watcher

def test_growing_file_handled_once_after_it_stops(watching):
    rec, w, (cfg, dl, desk, hub) = watching
    f = dl / "big.bin"
    end = time.monotonic() + 3.0
    with open(f, "wb") as fh:
        while time.monotonic() < end:
            fh.write(b"x" * 4096)
            fh.flush()
            os.fsync(fh.fileno())
            assert rec.names() == []
            time.sleep(0.15)
    stopped = time.monotonic()
    assert wait_for(lambda: rec.names() == ["big.bin"])
    assert time.monotonic() - stopped >= 0.5
    time.sleep(1.5)
    assert rec.names() == ["big.bin"]


@pytest.mark.parametrize("temp,final", [
    ("x.crdownload", "x.exe"), ("x.part", "x.zip"), ("~syncthing~x.tmp", "x.docx"), (".syncthing.x.tmp", "x.pdf"),
])
def test_temp_ignored_until_renamed(watching, temp, final):
    rec, w, (cfg, dl, desk, hub) = watching
    folder = hub if "syncthing" in temp else dl
    t = folder / temp
    t.write_bytes(b"data" * 100)
    time.sleep(1.5)
    assert rec.names() == []
    t.rename(folder / final)
    assert wait_for(lambda: rec.names() == [final])
    time.sleep(1.0)
    assert rec.names() == [final]


def test_excluded_paths_never_handled(watching, monkeypatch):
    monkeypatch.setattr(watcher_mod, "EXCLUDED_SUBPATHS", [("projects", "my-tool", "work")])
    rec, w, (cfg, dl, desk, hub) = watching
    proj = hub / "projects" / "app"
    rels = [proj / ".git" / "index", proj / ".venv" / "x.py", proj / "node_modules" / "m.js",
            proj / "__pycache__" / "m.pyc", hub / ".stversions" / "old.txt", hub / ".stfolder" / "marker",
            proj / "bin" / "app.dll", proj / "obj" / "x.cache", hub / "projects" / "my-tool" / "work" / "c.mp4"]
    for r in rels:
        r.parent.mkdir(parents=True, exist_ok=True)
        r.write_bytes(b"z")
    (hub / "ok.txt").write_text("ok", encoding="utf-8")
    assert wait_for(lambda: "ok.txt" in rec.names())
    time.sleep(1.0)
    assert rec.names() == ["ok.txt"]


def test_quarantine_root_never_handled(roots):
    cfg, dl, desk, hub = roots
    cfg.home = dl / ".gk-home-test"
    qdir = default_root(cfg) / "2026-11-03" / "abc"
    rec = RecordingPipeline()
    w, stop, t = start_watcher(cfg, rec)
    try:
        qdir.mkdir(parents=True)
        (qdir / "evil.exe.quarantined").write_bytes(b"MZ")
        (qdir / "meta.json").write_text("{}", encoding="utf-8")
        (dl / "after.txt").write_text("x", encoding="utf-8")
        assert wait_for(lambda: "after.txt" in rec.names())
        time.sleep(0.8)
        assert rec.names() == ["after.txt"]
    finally:
        stop.set()
        t.join(10)


def test_doorway_passed_by_watcher(watching):
    rec, w, (cfg, dl, desk, hub) = watching
    (dl / "a.txt").write_text("1", encoding="utf-8")
    (desk / "b.txt").write_text("2", encoding="utf-8")
    sub = hub / "projects"
    (sub / "c.txt").write_text("3", encoding="utf-8")
    assert wait_for(lambda: len(rec.handled) == 3)
    got = {p.name: d for p, d in rec.handled}
    assert got == {"a.txt": "download", "b.txt": "download", "c.txt": "sync"}


def test_unchanged_file_not_handled_twice(watching):
    rec, w, (cfg, dl, desk, hub) = watching
    f = dl / "once.txt"
    f.write_text("same", encoding="utf-8")
    assert wait_for(lambda: rec.names() == ["once.txt"])
    os.utime(f, ns=(f.stat().st_atime_ns, f.stat().st_mtime_ns))  # touch the event stream, same mtime
    w.notify(f)
    time.sleep(1.2)
    assert rec.names() == ["once.txt"]
    f.write_text("changed content", encoding="utf-8")
    assert wait_for(lambda: rec.names() == ["once.txt", "once.txt"])


def test_burst_of_200_files(roots):
    cfg, dl, desk, hub = roots
    rec = RecordingPipeline(delay=0.005)
    w, stop, t = start_watcher(cfg, rec, queue_max=16)
    try:
        for i in range(200):
            (dl / f"f{i:03d}.txt").write_text(str(i), encoding="utf-8")
        assert wait_for(lambda: len(rec.handled) >= 200, timeout=60)
        time.sleep(1.0)
        names = rec.names()
        assert len(names) == 200 and len(set(names)) == 200
        assert w.queue.maxsize == 16
        assert rec.max_q <= 16
    finally:
        stop.set()
        t.join(10)


def test_pipeline_crash_does_not_stop_worker(roots):
    cfg, dl, desk, hub = roots

    class Boom(RecordingPipeline):
        def handle(self, path, doorway, final=True):
            super().handle(path, doorway, final)
            if Path(path).name == "bad.txt":
                raise RuntimeError("boom")
            return "clean"

    rec = Boom()
    w, stop, t = start_watcher(cfg, rec)
    try:
        (dl / "bad.txt").write_text("b", encoding="utf-8")
        assert wait_for(lambda: "bad.txt" in rec.names())
        (dl / "good.txt").write_text("g", encoding="utf-8")
        assert wait_for(lambda: "good.txt" in rec.names())
    finally:
        stop.set()
        t.join(10)


def test_missing_root_is_skipped(roots, tmp_path):
    cfg, dl, desk, hub = roots
    cfg.watch_roots = cfg.watch_roots + [tmp_path / "nope"]
    rec = RecordingPipeline()
    w, stop, t = start_watcher(cfg, rec)
    try:
        (dl / "x.txt").write_text("x", encoding="utf-8")
        assert wait_for(lambda: rec.names() == ["x.txt"])
    finally:
        stop.set()
        t.join(10)


# ---------------------------------------------------------------- shortcuts (fix round 1)

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


@pytest.fixture
def desk_pipe(pipe, roots):
    return pipe + (roots[2],)


def test_edge_like_desktop_lnk_is_clean(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    f = desk / "Microsoft Edge.lnk"
    f.write_bytes(make_lnk(EDGE, "", idlist=True, icon=EDGE))
    assert p.handle(f, doorway_for(f, cfg)) == "clean"
    assert f.exists() and pushes == []
    assert not any(c[0] == "signature" for c in fs.calls)  # a .lnk is never Authenticode-checked


def test_desktop_lnk_to_powershell_enc_is_risky(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    f = desk / "Invoice.lnk"
    f.write_bytes(make_lnk(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-enc AAAA"))
    assert p.handle(f, doorway_for(f, cfg)) == "risky"
    assert not f.exists()
    assert len(pushes) == 1 and "powershell.exe" in pushes[0]["body"]


def test_motw_internet_lnk_into_temp_is_risky(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    p.scanners.motw = lambda path: {"ZoneId": 3, "HostUrl": "https://example.invalid/a.zip", "ReferrerUrl": None}
    f = dl / "readme.lnk"
    f.write_bytes(make_lnk(os.path.join(os.environ.get("TEMP", r"C:\Temp"), "payload.exe")))
    assert p.handle(f, doorway_for(f, cfg)) == "risky"
    assert not f.exists()
    assert len(pushes) == 1 and pushes[0]["title"] == "Quarantined: readme.lnk"


def test_unparsable_lnk_risky_internet_notice_local(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    broken = b"L\x00\x00\x00" + b"\x01" * 40
    local = desk / "broken.lnk"
    local.write_bytes(broken)
    assert p.handle(local, doorway_for(local, cfg)) == "notice"  # Desktop, no MotW: local
    assert local.exists() and pushes == []
    net = dl / "broken.lnk"
    net.write_bytes(broken + b"\x02")
    assert p.handle(net, doorway_for(net, cfg)) == "risky"       # Downloads: internet
    assert not net.exists() and len(pushes) == 1


def test_probe_benign_linkinfo_env_block_powershell_internet(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    p.scanners.motw = lambda path: {"ZoneId": 3, "HostUrl": None, "ReferrerUrl": None}
    f = desk / "Report.lnk"
    f.write_bytes(make_lnk(r"C:\Program Files\App\app.exe", "-enc AAAA",
                           env_target=r"%windir%\System32\WindowsPowerShell\v1.0\powershell.exe"))
    assert p.handle(f, doorway_for(f, cfg)) == "risky"
    assert not f.exists() and len(pushes) == 1


@pytest.mark.parametrize("kind", ["idlist", "unc"])
def test_probe_idlist_only_or_unc_internet_is_risky(desk_pipe, kind):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    p.scanners.motw = lambda path: {"ZoneId": 3, "HostUrl": None, "ReferrerUrl": None}
    f = dl / f"{kind}.lnk"
    data = (make_lnk(None, "-nop -enc AAAA", idlist=True) if kind == "idlist"
            else make_lnk(None, unc=r"\\evil.example@SSL\DavWWWRoot\invoice.exe"))
    f.write_bytes(data)
    assert p.handle(f, doorway_for(f, cfg)) == "risky"
    assert not f.exists() and len(pushes) == 1


def test_unc_lnk_local_is_notice(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    f = desk / "share.lnk"
    f.write_bytes(make_lnk(None, unc=r"\\nas\media\player.exe"))
    assert p.handle(f, doorway_for(f, cfg)) == "notice"
    assert f.exists() and pushes == []


def test_desktop_unsigned_exe_without_motw_is_local(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    f = desk / "tool.ps1"
    f.write_text("Write-Host hi", encoding="utf-8")
    assert p.handle(f, doorway_for(f, cfg)) == "clean"
    assert f.exists() and pushes == []


ZOOM_LNK = r"%APPDATA%\Zoom\bin\Zoom.exe"


def test_zoom_like_local_desktop_lnk_is_clean(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    f = desk / "Zoom Workplace.lnk"
    f.write_bytes(make_lnk(ZOOM_LNK))
    assert p.handle(f, doorway_for(f, cfg)) == "clean"
    assert f.exists() and pushes == []


def test_zoom_like_lnk_with_motw_internet_is_risky(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    p.scanners.motw = lambda path: {"ZoneId": 3, "HostUrl": None, "ReferrerUrl": None}
    f = desk / "Zoom Workplace.lnk"
    f.write_bytes(make_lnk(ZOOM_LNK))
    assert p.handle(f, doorway_for(f, cfg)) == "risky"
    assert not f.exists() and len(pushes) == 1


def test_local_lnk_into_temp_is_risky(desk_pipe):
    p, fs, pushes, st, cfg, dl, hub, desk = desk_pipe
    f = desk / "x.lnk"
    f.write_bytes(make_lnk(r"%TEMP%\x.exe"))
    assert p.handle(f, doorway_for(f, cfg)) == "risky"
    assert not f.exists() and len(pushes) == 1


# ---------------------------------------------------------------- I3: transient read errors

def _flaky_gather(monkeypatch, fail_times, exc=PermissionError):
    real = facts_mod.gather_facts
    calls = {"n": 0}

    def gather(path, *a, **k):
        calls["n"] += 1
        if calls["n"] <= fail_times:
            raise exc(13, "The process cannot access the file")
        return real(path, *a, **k)

    monkeypatch.setattr(facts_mod, "gather_facts", gather)
    return calls


def test_handle_oserror_not_final_returns_retry_without_event(pipe, monkeypatch):
    p, fs, pushes, st, cfg, dl, hub = pipe
    _flaky_gather(monkeypatch, 1)
    f = dl / "locked.txt"
    f.write_text("x", encoding="utf-8")
    assert p.handle(f, "download", final=False) == RETRY
    assert st.list_events() == []
    assert p.handle(f, "download", final=False) == "clean"


def test_handle_oserror_final_records_notice(pipe, monkeypatch):
    p, fs, pushes, st, cfg, dl, hub = pipe
    _flaky_gather(monkeypatch, 99)
    f = dl / "locked.txt"
    f.write_text("x", encoding="utf-8")
    assert p.handle(f, "download") == "notice"
    ev = st.list_events()[-1]
    assert ev["verdict"] == "notice" and "PermissionError" in ev["reasons"][0]


def test_watcher_retries_locked_file_then_scans(roots, tmp_path, monkeypatch):
    cfg, dl, desk, hub = roots
    st = State(tmp_path / "s.db")
    fs = FakeScanners()
    p = Pipeline(cfg, st, fs.build(), notifier=lambda *a: True)
    calls = _flaky_gather(monkeypatch, 1)
    w, stop, t = start_watcher(cfg, p, retry_delays=(0.2, 0.2, 0.2))
    try:
        f = dl / "busy.txt"
        f.write_text("fine", encoding="utf-8")
        assert wait_for(lambda: any(e["kind"] == "file" for e in st.list_events()))
        evs = st.list_events()
        assert [e["kind"] for e in evs] == ["file"] and evs[0]["verdict"] == "clean"
        assert calls["n"] == 2
    finally:
        stop.set()
        t.join(10)
        st.close()


def test_watcher_exhausted_retries_notice_and_not_done(roots, tmp_path, monkeypatch):
    cfg, dl, desk, hub = roots
    st = State(tmp_path / "s.db")
    fs = FakeScanners()
    p = Pipeline(cfg, st, fs.build(), notifier=lambda *a: True)
    calls = _flaky_gather(monkeypatch, 4)
    w, stop, t = start_watcher(cfg, p, retry_delays=(0.1, 0.1, 0.1))
    try:
        f = dl / "stuck.txt"
        f.write_text("x", encoding="utf-8")
        assert wait_for(lambda: len(st.list_events()) >= 1)
        time.sleep(0.5)
        evs = st.list_events()
        assert len(evs) == 1 and evs[0]["verdict"] == "notice"
        assert "after 4 attempts" in evs[0]["reasons"][0]
        assert calls["n"] == 4
        assert w._key(f) not in w._done  # no verdict -> never marked done
        w.notify(f)  # a later event gets a fresh look and now succeeds
        assert wait_for(lambda: any(e["kind"] == "file" for e in st.list_events()))
    finally:
        stop.set()
        t.join(10)
        st.close()


def test_motw_url_query_not_in_push_or_meta(pipe):
    # Final review M6: pre-signed download URLs must not leak their query string.
    import json as _json
    p, fs, pushes, st, cfg, dl, hub = pipe
    p.scanners = dataclasses.replace(p.scanners, motw=lambda path: {
        "ZoneId": "3", "HostUrl": "https://dl.example.com/f.pdf?X-Amz-Signature=SIGVALUE&token=TOKVALUE",
        "ReferrerUrl": "https://example.com/page?session=SESSVALUE"})
    fs.results["yara"] = [Finding("yara_match", "YARA rule matched: TEST_RULE", "critical")]
    f = dl / "f.pdf"
    f.write_bytes(b"%PDF-1.4\n%%EOF\n")
    assert p.handle(f, "download") == "risky"
    meta = _json.loads(next(default_root(cfg).rglob("meta.json")).read_text())
    blob = pushes[0]["body"] + meta["origin"]
    assert "dl.example.com/f.pdf" in blob
    for secret in ("SIGVALUE", "TOKVALUE", "SESSVALUE", "X-Amz-Signature"):
        assert secret not in blob

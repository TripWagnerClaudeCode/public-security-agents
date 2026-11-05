import os

import pytest

from gatekeeper.lnk import LnkError, lnk_findings, parse_lnk
from lnk_samples import make_lnk

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"


def test_parse_linkinfo_and_args():
    t = parse_lnk(make_lnk(EDGE, "--profile-directory=Default", name="Edge", idlist=True, icon=EDGE))
    assert t.path == EDGE
    assert t.args == "--profile-directory=Default"


def test_parse_ansi_strings():
    t = parse_lnk(make_lnk(r"C:\Windows\System32\cmd.exe", "/c echo hi", unicode=False))
    assert t.path == r"C:\Windows\System32\cmd.exe" and t.args == "/c echo hi"


def test_parse_env_block_when_no_linkinfo():
    t = parse_lnk(make_lnk(None, "", idlist=True, env_target=r"%ProgramFiles%\App\app.exe"))
    assert t.path == r"%ProgramFiles%\App\app.exe"


@pytest.mark.parametrize("data", [b"", b"L\x00\x00\x00" + b"\x00" * 10, b"\x00" * 200,
                                  make_lnk(EDGE, "abc")[:0x50]])
def test_parse_rejects_garbage(data):
    with pytest.raises(LnkError):
        parse_lnk(data)


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def codes(fs):
    return [(f.code, f.severity) for f in fs]


def test_edge_like_is_clean(tmp_path):
    assert lnk_findings(write(tmp_path, "Microsoft Edge.lnk", make_lnk(EDGE, "", idlist=True))) == []


def test_program_with_args_outside_lolbins_is_clean(tmp_path):
    p = write(tmp_path, "game.lnk", make_lnk(r"C:\Games\Steam\steam.exe", "-applaunch 730"))
    assert lnk_findings(p) == []


@pytest.mark.parametrize("exe", ["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
                                 "mshta.exe", "rundll32.exe", "regsvr32.exe", "bitsadmin.exe", "certutil.exe",
                                 "POWERSHELL.EXE"])
def test_lolbin_with_args_is_risky(tmp_path, exe):
    p = write(tmp_path, "x.lnk", make_lnk(rf"C:\Windows\System32\{exe}", "-enc AAAA"))
    assert codes(lnk_findings(p)) == [("lnk_target", "risky")]


def test_lolbin_without_args_is_clean(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(r"C:\Windows\System32\cmd.exe", "   "))
    assert lnk_findings(p) == []


@pytest.mark.parametrize("target", [
    os.path.join(os.environ.get("TEMP", r"C:\Users\u\AppData\Local\Temp"), "a.exe"),
    os.path.join(os.environ.get("APPDATA", r"C:\Users\u\AppData\Roaming"), "x", "b.exe"),
    r"C:\Users\someone\Downloads\setup.exe",
    r"C:\Users\someone\AppData\Local\Temp\7z123\run.exe",
    r"C:\Users\someone\AppData\Roaming\evil.exe",
    r"C:\Windows\Temp\x.exe",
    r"%TEMP%\x.exe",
    r"%APPDATA%\y.exe",
])
def test_target_in_user_writable_drop_dirs_is_risky(tmp_path, target):
    p = write(tmp_path, "x.lnk", make_lnk(target))
    assert codes(lnk_findings(p)) == [("lnk_target", "risky")]


def test_env_block_target_checked(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(None, "", idlist=True, env_target=r"%TEMP%\x.exe"))
    assert codes(lnk_findings(p)) == [("lnk_target", "risky")]


def test_unparsable_is_uninspectable(tmp_path):
    # notice severity; verdict makes it risky for internet origin (like office/pdf/archive uninspectable)
    p = write(tmp_path, "x.lnk", b"L\x00\x00\x00garbage")
    assert codes(lnk_findings(p)) == [("lnk_uninspectable", "notice")]


def test_unresolvable_idlist_only_is_uninspectable(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(None, "-nop -enc AAAA", idlist=True))
    assert codes(lnk_findings(p)) == [("lnk_uninspectable", "notice")]


def test_unc_target_is_uninspectable(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(None, unc=r"\\evil.example\share\invoice.exe"))
    t = parse_lnk(p.read_bytes())
    assert r"\\evil.example\share\invoice.exe" in t.candidates and t.network
    assert codes(lnk_findings(p)) == [("lnk_uninspectable", "notice")]


def test_unc_lolbin_with_args_is_risky(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(None, "/c x", unc=r"\\host\share\cmd.exe"))
    assert ("lnk_target", "risky") in codes(lnk_findings(p))


# ---- every candidate counts (review fix round 3)

def test_idlist_path_is_parsed():
    t = parse_lnk(make_lnk(None, idlist_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    assert r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" in t.candidates


def test_idlist_short_names_only():
    from lnk_samples import CLSID as _c  # noqa: F401  (builder import check)
    from lnk_samples import idlist_items
    import struct
    ids = idlist_items(r"C:\Windows\cmd.exe", long_names=False) + b"\x00\x00"
    data = bytearray(make_lnk(None, idlist=True))
    # splice our IDList in place of the builder's placeholder one
    old_len = struct.unpack_from("<H", data, 0x4C)[0]
    data[0x4C:0x4E + old_len] = struct.pack("<H", len(ids)) + ids
    t = parse_lnk(bytes(data))
    assert r"C:\WINDOWS\CMD.EXE" in t.candidates


def test_benign_linkinfo_plus_env_block_powershell_is_risky(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(r"C:\Program Files\App\app.exe", "-enc AAAA",
                                          env_target=r"%windir%\System32\WindowsPowerShell\v1.0\powershell.exe"))
    assert codes(lnk_findings(p, "internet")) == [("lnk_target", "risky")]


def test_env_block_unicode_differs_from_ansi(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(r"C:\Program Files\App\app.exe", "-enc AAAA",
                                          env_target=r"C:\Program Files\App\app.exe",
                                          env_unicode=r"%windir%\System32\cmd.exe"))
    assert codes(lnk_findings(p, "local")) == [("lnk_target", "risky")]


def test_idlist_lolbin_behind_benign_linkinfo_is_risky(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(r"C:\Program Files\App\app.exe", "-nop -enc AAAA",
                                          idlist_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"))
    assert codes(lnk_findings(p, "local")) == [("lnk_target", "risky")]


def test_relpath_and_workdir_candidates(tmp_path):
    a = write(tmp_path, "a.lnk", make_lnk(None, relpath=r"..\..\AppData\Local\Temp\x.exe"))
    assert codes(lnk_findings(a, "local")) == [("lnk_target", "risky")]
    b = write(tmp_path, "b.lnk", make_lnk(r"C:\Program Files\App\app.exe", workdir=r"%TEMP%\stage"))
    assert codes(lnk_findings(b, "local")) == [("lnk_target", "risky")]


@pytest.mark.parametrize("args", [
    r"powershell -nop -enc AAAA",
    r'"C:\Windows\System32\cmd.exe" /c start x',
    r"%TEMP%\payload.exe",
    r'"C:\Users\someone\AppData\Local\Temp\a.vbs"',
])
def test_arguments_are_candidates(tmp_path, args):
    p = write(tmp_path, "x.lnk", make_lnk(r"C:\Windows\explorer.exe", args))
    assert codes(lnk_findings(p, "local")) == [("lnk_target", "risky")]


@pytest.mark.parametrize("args", ["--profile-directory=Default", "--processStart Discord.exe",
                                  r'"C:\Users\me\Documents\proj\main.py"', "-applaunch 730"])
def test_ordinary_arguments_stay_clean(tmp_path, args):
    p = write(tmp_path, "x.lnk", make_lnk(r"C:\Program Files\App\app.exe", args))
    assert lnk_findings(p, "internet") == []


@pytest.mark.parametrize("exe", ["msiexec.exe", "wmic.exe", "forfiles.exe", "hh.exe", "msbuild.exe",
                                 "installutil.exe", "regasm.exe", "conhost.exe", "curl.exe"])
def test_extra_lolbins_with_args(tmp_path, exe):
    p = write(tmp_path, "x.lnk", make_lnk(rf"C:\Windows\System32\{exe}", "/q x"))
    assert codes(lnk_findings(p, "local")) == [("lnk_target", "risky")]


def test_edge_and_zoom_with_idlists_stay_clean(tmp_path):
    e = write(tmp_path, "Microsoft Edge.lnk", make_lnk(EDGE, "", idlist_path=EDGE, icon=EDGE,
                                                       workdir=r"C:\Program Files (x86)\Microsoft\Edge\Application"))
    assert lnk_findings(e, "local") == [] and lnk_findings(e, "internet") == []
    zt = os.path.join(os.environ.get("APPDATA", r"C:\Users\u\AppData\Roaming"), "Zoom", "bin", "Zoom.exe")
    z = write(tmp_path, "Zoom Workplace.lnk", make_lnk(zt, "", idlist_path=zt, workdir=os.path.dirname(zt)))
    assert lnk_findings(z, "local") == []
    assert codes(lnk_findings(z, "internet")) == [("lnk_target", "risky")]


def test_parser_bounded_on_mutations():
    import random
    import time
    rng = random.Random(1234)
    base = make_lnk(r"C:\Program Files\App\app.exe", "-x y", idlist_path=r"C:\Windows\System32\cmd.exe",
                    env_target=r"%windir%\x.exe", relpath=r"..\a.exe", workdir=r"C:\w", name="n", icon="i")
    start = time.monotonic()
    for _ in range(3000):
        d = bytearray(base)
        for _ in range(rng.randint(1, 8)):
            d[rng.randrange(len(d))] = rng.randrange(256)
        if rng.random() < 0.2:
            d = d[:rng.randrange(len(d))]
        try:
            t = parse_lnk(bytes(d))
            assert len(t.candidates) < 64
        except LnkError:
            pass
    assert time.monotonic() - start < 10


ZOOM = r"%APPDATA%\Zoom\bin\Zoom.exe"


@pytest.mark.parametrize("target", [
    ZOOM,
    os.path.join(os.environ.get("APPDATA", r"C:\x"), "Zoom", "bin", "Zoom.exe"),
    r"C:\Users\someone\Downloads\setup.exe",
    r"C:\Users\someone\AppData\Roaming\a.exe",
])
@pytest.mark.parametrize("origin", ["local", "own_device"])
def test_user_dir_target_clean_when_not_internet(tmp_path, target, origin):
    p = write(tmp_path, "Zoom Workplace.lnk", make_lnk(target))
    assert lnk_findings(p, origin) == []


@pytest.mark.parametrize("target", [
    r"%TEMP%\x.exe", r"%TMP%\x.exe", r"C:\Windows\Temp\x.exe",
    r"C:\Users\someone\AppData\Local\Temp\x.exe",
    os.path.join(os.environ.get("TEMP", r"C:\t"), "x.exe"),
])
@pytest.mark.parametrize("origin", ["local", "own_device", "internet"])
def test_temp_target_risky_any_origin(tmp_path, target, origin):
    p = write(tmp_path, "x.lnk", make_lnk(target))
    assert codes(lnk_findings(p, origin)) == [("lnk_target", "risky")]


def test_local_lolbin_with_args_still_risky(tmp_path):
    p = write(tmp_path, "x.lnk", make_lnk(r"C:\Windows\System32\cmd.exe", "/c x"))
    assert codes(lnk_findings(p, "local")) == [("lnk_target", "risky")]

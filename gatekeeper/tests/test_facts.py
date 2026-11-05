import struct
import zipfile
import zlib

import pytest

from gatekeeper import facts as facts_mod
from gatekeeper.config import Config
from gatekeeper.facts import archive_findings, gather_facts, office_findings, pdf_findings


def pe_bytes():
    b = bytearray(b"MZ" + b"\x00" * 0xBE)
    b[0x3C:0x40] = struct.pack("<I", 0x80)
    b[0x80:0x84] = b"PE\x00\x00"
    return bytes(b)


PE = pe_bytes()


def codes(fs):
    return {x.code for x in fs}


def make_zip(path, names, encrypted=False):
    with zipfile.ZipFile(path, "w") as z:
        for n in names:
            z.writestr(n, b"x")
    if encrypted:  # set the encryption flag bit in local + central headers
        data = bytearray(path.read_bytes())
        for sig, off in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = data.find(sig)
            while i != -1:
                data[i + off] |= 1
                i = data.find(sig, i + 1)
        path.write_bytes(bytes(data))
    return path


def make_docx(path, macro=False, template=None):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w/>")
        if macro:
            z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0stub")
        if template:
            z.writestr(
                "word/_rels/settings.xml.rels",
                '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/'
                'officeDocument/2006/relationships/attachedTemplate" Target="%s" TargetMode="External"/>'
                "</Relationships>" % template,
            )
    return path


@pytest.fixture
def cfg(tmp_path):
    dl = tmp_path / "Downloads"
    hub = tmp_path / "Hub"
    (hub / "projects").mkdir(parents=True)
    dl.mkdir()
    return Config(home=tmp_path / "h", watch_roots=[dl, hub, tmp_path / "Desktop"],
                  code_tree_roots=[hub / "projects"])


# ---- detectors
def test_office_macro_and_template(tmp_path):
    assert office_findings(make_docx(tmp_path / "a.docx")) == []
    assert "office_macro" in codes(office_findings(make_docx(tmp_path / "b.docx", macro=True)))
    t = office_findings(make_docx(tmp_path / "c.docx", template="http://evil.example/t.dotm"))
    assert "office_remote_template" in codes(t)


def test_office_garbage_does_not_raise(tmp_path):
    p = tmp_path / "bad.doc"
    p.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 50)
    assert isinstance(office_findings(p), list)


def test_pdf_tokens(tmp_path):
    p = tmp_path / "a.pdf"
    p.write_bytes(b"%PDF-1.4\n1 0 obj<</S/JavaScript/JS(app.alert(1))>>/OpenAction 2 0 R/Launch/EmbeddedFile")
    assert codes(pdf_findings(p)) == {"pdf_javascript", "pdf_openaction", "pdf_launch", "pdf_embedded"}
    q2 = tmp_path / "aa.pdf"
    q2.write_bytes(b"%PDF-1.4\n<< /AA << /O 1 0 R >> >>")
    assert codes(pdf_findings(q2)) == {"pdf_additional_actions"}
    q = tmp_path / "b.pdf"
    q.write_bytes(b"%PDF-1.4\n/JSON /Type /Page")
    assert pdf_findings(q) == []


def test_archive_zip(tmp_path):
    assert archive_findings(make_zip(tmp_path / "a.zip", ["readme.txt"])) == []
    assert "archive_exec" in codes(archive_findings(make_zip(tmp_path / "b.zip", ["a.exe"])))
    assert "archive_script" in codes(archive_findings(make_zip(tmp_path / "c.zip", ["d/run.PS1"])))
    assert "archive_exec" not in codes(archive_findings(make_zip(tmp_path / "c2.zip", ["d/run.PS1"])))
    assert "archive_traversal" in codes(archive_findings(make_zip(tmp_path / "d.zip", ["../x.txt"])))
    assert "archive_traversal" in codes(archive_findings(make_zip(tmp_path / "e.zip", ["..\\x.txt"])))
    assert "archive_nested" in codes(archive_findings(make_zip(tmp_path / "f.zip", ["in.zip"])))
    assert "archive_encrypted" in codes(archive_findings(make_zip(tmp_path / "g.zip", ["a.txt"], encrypted=True)))


def test_archive_uninspectable(tmp_path):
    p = tmp_path / "a.7z"
    p.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 30)
    fs = archive_findings(p)
    assert fs[0].code == "archive_uninspectable" and fs[0].detail == "can't inspect 7z"
    r = tmp_path / "a.rar"
    r.write_bytes(b"Rar!\x1a\x07\x00" + b"\x00" * 30)
    assert archive_findings(r)[0].detail == "can't inspect rar"


# ---- gather_facts: kinds
@pytest.mark.parametrize("name,content,kind", [
    ("a.exe", PE, "pe"),
    ("a.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "office"),
    ("a.pdf", b"%PDF-1.7", "pdf"),
    ("a.lnk", b"\x4c\x00\x00\x00\x01\x14\x02\x00", "lnk"),
    ("a.7z", b"7z\xbc\xaf\x27\x1c\x00", "archive"),
    ("a.gz", b"\x1f\x8b\x08\x00", "archive"),
    ("a.cab", b"MSCF\x00\x00", "archive"),
    ("a.img", b"\x00\x01\x02", "archive"),
    ("a.tgz", b"zzzz", "archive"),
    ("a.dat", b"MZ\x90 not a real pe", "text"),
    ("a.rar", b"Rar!\x1a\x07\x00", "archive"),
    ("a.ps1", b"Write-Host hi", "script"),
    ("a.bat", b"@echo off", "script"),
    ("a.txt", b"hello", "text"),
    ("a.png", b"\x89PNG\r\n\x1a\n", "media"),
    ("a.bin", b"\x00\x01\x02\xff", "other"),
])
def test_kind(tmp_path, cfg, name, content, kind):
    p = tmp_path / name
    p.write_bytes(content)
    facts = gather_facts(p, cfg, "written", None, "n/a")
    assert facts.kind == kind
    assert len(facts.sha256) == 64


def test_kind_zip_family(tmp_path, cfg):
    assert gather_facts(make_zip(tmp_path / "a.zip", ["x"]), cfg, "written", None, "n/a").kind == "archive"
    assert gather_facts(make_docx(tmp_path / "a.docx"), cfg, "written", None, "n/a").kind == "office"


def test_ext_mismatch(tmp_path, cfg):
    p = tmp_path / "invoice.pdf"
    p.write_bytes(PE)
    f = gather_facts(p, cfg, "written", None, "unsigned")
    assert f.kind == "pe" and f.ext_mismatch
    q = tmp_path / "ok.pdf"
    q.write_bytes(b"%PDF-1.4")
    assert not gather_facts(q, cfg, "written", None, "n/a").ext_mismatch
    d = tmp_path / "ok.docx"
    make_docx(d)
    assert not gather_facts(d, cfg, "written", None, "n/a").ext_mismatch
    j = tmp_path / "x.dat"
    j.write_bytes(PE)
    assert not gather_facts(j, cfg, "written", None, "unsigned").ext_mismatch  # unknown ext: no claim


# ---- origin
def test_origin_rules(tmp_path, cfg):
    dl, hub = cfg.watch_roots[0], cfg.watch_roots[1]
    f1 = dl / "a.txt"
    f1.write_text("x")
    f2 = hub / "n.txt"
    f2.write_text("x")

    def g(p, door, motw=None):
        return gather_facts(p, cfg, door, motw, "n/a").origin

    assert g(f1, "download") == "internet"
    assert g(f1, "download", {"ZoneId": 3}) == "internet"
    assert g(f1, "download", {"ZoneId": "3"}) == "internet"
    assert g(f1, "download", {"ZoneId": 2}) == "own_device"
    assert g(f1, "sync") == "internet"          # sync under Downloads
    assert g(f2, "sync") == "own_device"        # sync under Synced
    assert g(f2, "written") == "local"
    assert g(f2, "download", {"ZoneId": 3}) == "internet"


def test_desktop_origin(tmp_path, cfg):
    desk = cfg.watch_roots[2]
    desk.mkdir()
    f = desk / "Microsoft Edge.lnk"
    f.write_bytes(b"x")

    def g(motw=None):
        return gather_facts(f, cfg, "download", motw, "n/a").origin

    assert g() == "local"                       # no MotW on the Desktop: made on this PC
    assert g({"ZoneId": 3}) == "internet"       # MotW still wins
    assert g({"ZoneId": 4}) == "internet"
    assert g({"ZoneId": 2}) == "own_device"


# ---- code tree
def test_code_tree(tmp_path, cfg):
    hub, dl = cfg.watch_roots[1], cfg.watch_roots[0]
    a = hub / "projects" / "p" / "a.py"
    a.parent.mkdir(parents=True)
    a.write_text("x")
    assert gather_facts(a, cfg, "written", None, "n/a").in_code_tree
    b = hub / "other" / "b.py"
    b.parent.mkdir()
    b.write_text("x")
    assert not gather_facts(b, cfg, "written", None, "n/a").in_code_tree
    (hub / "other" / ".git").mkdir()
    assert gather_facts(b, cfg, "written", None, "n/a").in_code_tree
    (dl.parent / ".git").mkdir()  # above the watch root: must not count
    c = dl / "c.txt"
    c.write_text("x")
    assert not gather_facts(c, cfg, "download", None, "n/a").in_code_tree
    (dl / ".git").mkdir()  # at the watch root: not searched either
    assert not gather_facts(c, cfg, "download", None, "n/a").in_code_tree


# ---------------------------------------------------------------- fix round
def pdf(body: bytes) -> bytes:
    return b"%PDF-1.5\n" + body + b"\n%%EOF\n"


def test_mz_without_pe_header_is_not_pe(tmp_path, cfg):
    p = tmp_path / "a.pdf"
    p.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    f = gather_facts(p, cfg, "written", None, "n/a")
    assert f.kind != "pe" and not f.ext_mismatch



def test_pdf_stream_bytes_do_not_match(tmp_path):
    body = b"/JS junk /Launchx /OpenActionx /JavaScripty \x00\xff random"
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(b"1 0 obj<</Length %d>>\nstream\n" % len(body) + body + b"\nendstream\nendobj"))
    assert pdf_findings(p) == []
    q = tmp_path / "b.pdf"
    q.write_bytes(pdf(b"1 0 obj<</S/JavaScript/JS 5 0 R>>endobj"))
    assert codes(pdf_findings(q)) == {"pdf_javascript"}


JS_OBJ = b"2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj"


def test_pdf_stream_keyword_in_string_or_comment_does_not_hide_js(tmp_path):
    a = tmp_path / "a.pdf"
    a.write_bytes(pdf(b"1 0 obj << /Title (x stream\n) >> endobj\n" + JS_OBJ))
    assert "pdf_javascript" in codes(pdf_findings(a))
    b = tmp_path / "b.pdf"
    b.write_bytes(pdf(b"% stream\n" + JS_OBJ))
    assert "pdf_javascript" in codes(pdf_findings(b))
    c = tmp_path / "c.pdf"  # nested parens and escapes inside the string
    c.write_bytes(pdf(b"1 0 obj << /T (a \\) (b) stream\n) >> endobj\n" + JS_OBJ))
    assert "pdf_javascript" in codes(pdf_findings(c))


def test_pdf_name_escapes_and_objstm(tmp_path):
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(b"1 0 obj<</S/Java#53cript/J#53(x)>>endobj"))
    assert "pdf_javascript" in codes(pdf_findings(p))
    inner = zlib.compress(b"3 0 obj<</S/JavaScript/JS(app.alert(1))>>")
    body = (b"2 0 obj<</Type/ObjStm/Filter/FlateDecode/Length %d>>\nstream\n" % len(inner)
            + inner + b"\nendstream\nendobj")
    q = tmp_path / "b.pdf"
    q.write_bytes(pdf(body))
    assert "pdf_javascript" in codes(pdf_findings(q))


def test_pdf_objstm_bounds_and_truncation(tmp_path, monkeypatch):
    bomb = zlib.compress(b"0" * (21 * 1024 * 1024))
    body = b"2 0 obj<</Type/ObjStm/Filter/FlateDecode>>\nstream\n" + bomb + b"\nendstream\nendobj"
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(body))
    assert "pdf_uninspectable" in codes(pdf_findings(p))
    many = b"".join(
        b"%d 0 obj<</Type/ObjStm/Filter/FlateDecode>>\nstream\n" % i + zlib.compress(b"x") + b"\nendstream\nendobj\n"
        for i in range(51))
    q = tmp_path / "b.pdf"
    q.write_bytes(pdf(many))
    assert "pdf_uninspectable" not in codes(pdf_findings(q))
    monkeypatch.setattr(facts_mod, "_PDF_MAX_STREAMS", 50)
    assert "pdf_uninspectable" in codes(pdf_findings(q))


def test_pdf_read_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(facts_mod, "_PDF_MAX", 100)
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(b"x" * 500))
    assert "pdf_uninspectable" in codes(pdf_findings(p))


def make_rels_docx(path, rels_bytes):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w/>")
        z.writestr("word/_rels/settings.xml.rels", rels_bytes)
    return path


_REL = "<Relationships><Relationship Type='x/attachedTemplate' Target='h' TargetMode='External'/></Relationships>"


@pytest.mark.parametrize("rels", [
    b"<Relationships><Relationship TargetMode='External' Target='http://e/x' Type='x/attachedTemplate'/></Relationships>",
    b'<Relationships><Relationship TARGETMODE="External" Type="x/ATTACHEDTEMPLATE" Target="http://e"/></Relationships>',
    b"\xef\xbb\xbf<?xml version='1.0'?>" + _REL.encode(),
    ("<?xml version='1.0' encoding='utf-16'?>" + _REL).encode("utf-16"),
])
def test_rels_variants_detect_template(tmp_path, rels):
    assert "office_remote_template" in codes(office_findings(make_rels_docx(tmp_path / "a.docx", rels)))


def test_rels_hostile(tmp_path):
    dtd = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "b">]><Relationships/>'
    assert "office_uninspectable" in codes(office_findings(make_rels_docx(tmp_path / "a.docx", dtd)))
    assert "office_uninspectable" in codes(office_findings(make_rels_docx(tmp_path / "b.docx", b"<Relationships")))
    big = b"<Relationships>" + b" " * (2 * 1024 * 1024) + b"</Relationships>"
    assert "office_uninspectable" in codes(office_findings(make_rels_docx(tmp_path / "c.docx", big)))


def test_office_corrupt_is_uninspectable(tmp_path):
    p = tmp_path / "a.docx"
    p.write_bytes(b"PK\x03\x04 truncated")
    assert "office_uninspectable" in codes(office_findings(p))


def test_msi_detected_by_ole_content(tmp_path, cfg, monkeypatch):
    monkeypatch.setattr(facts_mod, "_ole_is_msi", lambda path: True)
    p = tmp_path / "setup.dat"
    p.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
    assert gather_facts(p, cfg, "written", None, "n/a").kind == "msi"
    q = tmp_path / "ok.msi"
    q.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
    g = gather_facts(q, cfg, "written", None, "n/a")
    assert g.kind == "msi" and not g.ext_mismatch
    r = tmp_path / "x.doc"
    r.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
    h = gather_facts(r, cfg, "written", None, "n/a")
    assert h.kind == "msi" and h.ext_mismatch


def test_ole_is_msi_on_non_ole_is_false(tmp_path):
    p = tmp_path / "a.doc"
    p.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
    assert facts_mod._ole_is_msi(p) is False


def test_tar_listing_and_uninspectable_gz(tmp_path):
    import tarfile
    t = tmp_path / "a.tar"
    src = tmp_path / "run.exe"
    src.write_bytes(b"x")
    with tarfile.open(t, "w") as tf:
        tf.add(src, arcname="run.exe")
        tf.add(src, arcname="../evil.txt")
    assert {"archive_exec", "archive_traversal"} <= codes(archive_findings(t))
    g = tmp_path / "a.tgz"
    g.write_bytes(b"\x1f\x8b\x08\x00" + b"\x00" * 20)
    f = archive_findings(g)
    assert f[0].code == "archive_uninspectable" and f[0].detail == "can't inspect gz"
    c2 = tmp_path / "a.cab"
    c2.write_bytes(b"MSCF" + b"\x00" * 20)
    assert archive_findings(c2)[0].detail == "can't inspect cab"


def test_archive_one_finding_per_code_and_entry_cap(tmp_path, monkeypatch):
    p = make_zip(tmp_path / "a.zip", ["a.exe", "b.exe", "c.dll"])
    assert [x.code for x in archive_findings(p)] == ["archive_exec"]
    monkeypatch.setattr(facts_mod, "_MAX_ENTRIES", 2)
    assert "archive_too_many_entries" in codes(archive_findings(p))


def test_archive_corrupt_is_uninspectable(tmp_path):
    p = tmp_path / "a.zip"
    p.write_bytes(b"PK\x03\x04 truncated")
    assert "archive_uninspectable" in codes(archive_findings(p))


# ---- launch-by-extension beats magic bytes
@pytest.mark.parametrize("name,content,kind", [
    ("invoice.pdf.ps1", b"%PDF-1.4 hi", "script"),
    ("cat.hta", b"GIF89a....", "script"),
    ("a.js", b"PK\x03\x04junk", "script"),
    ("a.exe", b"\x89PNG\r\n\x1a\n", "pe"),
    ("a.lnk", b"%PDF-1.4", "lnk"),
    ("a.msi", b"%PDF-1.4", "msi"),
    ("a.scr", b"\xff\xd8\xff\xe0", "pe"),
])
def test_launchable_extension_wins(tmp_path, cfg, name, content, kind):
    p = tmp_path / name
    p.write_bytes(content)
    f = gather_facts(p, cfg, "download", None, "n/a")
    # .lnk and .hta can't carry an Authenticode signature: n/a, never unsigned/invalid
    expect = "n/a" if name.endswith((".lnk", ".hta")) else "unsigned"
    assert f.kind == kind and f.ext_mismatch and f.signed == expect


@pytest.mark.parametrize("name,signed_in,expect", [
    ("a.ps1", "n/a", "unsigned"), ("a.vbs", "n/a", "unsigned"), ("a.js", "n/a", "unsigned"),
    ("a.exe", "n/a", "unsigned"), ("a.ps1", "valid", "valid"),
    ("a.lnk", "invalid", "n/a"), ("a.lnk", "unsigned", "n/a"), ("a.bat", "unsigned", "n/a"),
    ("a.cmd", "invalid", "n/a"), ("a.hta", "unsigned", "n/a"),
])
def test_signature_only_for_signable_types(tmp_path, cfg, name, signed_in, expect):
    p = tmp_path / name
    p.write_bytes(b"MZ" if name.endswith(".exe") else b"echo hi")
    assert gather_facts(p, cfg, "download", None, signed_in).signed == expect


def test_real_pdf_stays_pdf(tmp_path, cfg):
    p = tmp_path / "notes.pdf"
    p.write_bytes(b"%PDF-1.4\nhello")
    f = gather_facts(p, cfg, "download", None, "n/a")
    assert f.kind == "pdf" and not f.ext_mismatch and f.signed == "n/a"


def test_pdf_whitespace_and_comment_evasions(tmp_path):
    for i, body in enumerate([
        b"2 0 obj<</S/JavaScript/JS\x00(x)>>endobj",
        b"2 0 obj<</S%c\n/JavaScript/JS%c\n(x)>>endobj",
        b"2 0 obj<</JS 1\x000\x00R>>endobj",
        b"2 0 obj<</JS 1%c\n0%c\nR>>endobj",
        b"1 0 obj<</T (x%) /S /JavaScript /JS (a)>>endobj",
        b"<< /Names << /JavaScript (x) >> >>",
    ]):
        p = tmp_path / f"e{i}.pdf"
        p.write_bytes(pdf(body))
        assert "pdf_javascript" in codes(pdf_findings(p)), body


def test_pdf_spanning_length_attack_now_found(tmp_path):
    body = b"AAAA\nendstream\nendobj\n" + JS_OBJ + b"\n"
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(b"1 0 obj<</Length %d>>\nstream\n" % len(body) + body + b"endstream\nendobj"))
    assert "pdf_javascript" in codes(pdf_findings(p))


def test_pdf_binary_stream_no_anchor_matches(tmp_path):
    import os
    body = os.urandom(400_000) + b"/JS junk /S /JavaScripty /Launchx /AA 5"
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(b"1 0 obj<</Length %d>>\nstream\n" % len(body) + body + b"\nendstream\nendobj"))
    assert pdf_findings(p) == []


def test_pdf_openaction_to_page_is_a_notice_finding(tmp_path):
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(b"<< /Type /Catalog /OpenAction [3 0 R /Fit] >>"))
    assert [f.code for f in pdf_findings(p)] == ["pdf_openaction"]
    assert pdf_findings(p)[0].severity == "notice"


def test_pdf_planted_endstream_cannot_hide_compressed_js(tmp_path):
    co0 = zlib.compressobj(0, zlib.DEFLATED, -15)
    seg1 = co0.compress(b"AA endstream AA") + co0.flush(zlib.Z_SYNC_FLUSH)
    co9 = zlib.compressobj(9, zlib.DEFLATED, -15)
    seg2 = co9.compress(b"3 0 obj<</S/JavaScript/JS(app.alert(1))>>") + co9.flush()
    body = seg1 + seg2
    assert b"JavaScript" not in body and b"endstream" in body
    dic = b"2 0 obj<</Type/ObjStm/Length %d>>\nstream\n" % len(body)
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(dic + body + b"\nendstream\nendobj"))
    assert "pdf_javascript" in codes(pdf_findings(p))


def test_pdf_many_planted_endstreams_cannot_hide_compressed_js(tmp_path):
    co0 = zlib.compressobj(0, zlib.DEFLATED, -15)
    segs = b"".join(co0.compress(b"AA endstream AA") + co0.flush(zlib.Z_SYNC_FLUSH) for _ in range(20))
    co9 = zlib.compressobj(9, zlib.DEFLATED, -15)
    tail = co9.compress(b"3 0 obj<</S/JavaScript/JS(app.alert(1))>>") + co9.flush()
    body = segs + tail
    assert body.count(b"endstream") == 20 and b"JavaScript" not in body
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(b"2 0 obj<<>>\nstream\n" + body + b"\nendstream\nendobj"))
    assert "pdf_javascript" in codes(pdf_findings(p))


def test_pdf_flate_without_objstm_or_filter_in_dict(tmp_path):
    body = zlib.compress(b"3 0 obj<</S /JavaScript /JS (x)>>")
    assert b"JavaScript" not in body
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(b"2 0 obj<<>>\nstream\n" + body + b"\nendstream\nendobj"))
    assert "pdf_javascript" in codes(pdf_findings(p))


def test_pdf_many_binary_image_streams_clean_and_fast(tmp_path):
    import os
    import time
    objs = b""
    for i in range(60):
        img = os.urandom(300_000)
        objs += b"%d 0 obj<</Length %d/Subtype/Image>>\nstream\n" % (i + 1, len(img)) + img + b"\nendstream\nendobj\n"
    p = tmp_path / "a.pdf"
    p.write_bytes(pdf(objs))
    t0 = time.process_time()
    assert pdf_findings(p) == []
    assert time.process_time() - t0 < 2.0


def test_pdf_cpu_bound_ignores_other_threads(tmp_path, monkeypatch):
    # Final review M11: process-wide CPU (other watcher threads) must not trip the inflate time bound.
    import zlib
    import gatekeeper.facts as fm
    ticks = iter(range(0, 10**9, 1000))
    monkeypatch.setattr(fm.time, "process_time", lambda: next(ticks))
    body = zlib.compress(b"BT /F1 12 Tf (hello) Tj ET")
    p = tmp_path / "s.pdf"
    p.write_bytes(b"%PDF-1.4\n" + b"1 0 obj<</Length %d/Filter/FlateDecode>>stream\n" % len(body) + body
                  + b"\nendstream endobj\n2 0 obj<</Length 3>>stream\nabc\nendstream endobj\n%%EOF\n")
    assert pdf_findings(p) == []

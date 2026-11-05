"""File facts: true type, origin, code-tree membership, and content detectors."""
from __future__ import annotations

import hashlib
import re
import tarfile
import time
import warnings
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from xml.parsers import expat

import olefile

from gatekeeper.config import Config

Severity = Literal["notice", "risky", "secret", "critical"]
Kind = Literal["pe", "msi", "script", "lnk", "office", "pdf", "archive", "text", "media", "other"]
Origin = Literal["internet", "own_device", "local"]


@dataclass
class Finding:
    code: str
    detail: str
    severity: Severity


@dataclass
class FileFacts:
    path: Path
    sha256: str
    kind: Kind
    ext_mismatch: bool
    origin: Origin
    signed: Literal["valid", "unsigned", "invalid", "n/a"]
    in_code_tree: bool


SCRIPT_EXTS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".iso", ".img", ".gz", ".tar", ".tgz", ".cab"}
OFFICE_EXTS = {".doc", ".docx", ".docm", ".dot", ".dotm", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ppt", ".pptx",
               ".pptm", ".ppsx", ".pps", ".potm"}
TEXT_EXTS = {".txt", ".md", ".py", ".json", ".yaml", ".yml", ".toml", ".csv", ".ini", ".cfg", ".xml", ".html",
             ".htm", ".sh", ".ts", ".tsx", ".jsx", ".css", ".env", ".log", ".rs", ".go", ".c", ".h", ".cpp",
             ".java", ".sql", ".rb", ".php"}
MEDIA_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".mp4", ".mov", ".mkv", ".mp3", ".wav", ".m4a",
              ".webm", ".ico"}
MEDIA_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"RIFF", b"ID3", b"\x00\x00\x00\x18ftyp", b"\x00\x00\x00\x20ftyp")
MSI_CLSIDS = ("000C1084", "000C1086")  # Windows Installer package / patch

# Windows launches these by extension, whatever the content: the extension decides the kind.
LAUNCH_KINDS: dict[str, str] = {e: "script" for e in SCRIPT_EXTS}
LAUNCH_KINDS.update({e: "pe" for e in (".exe", ".scr", ".com", ".cpl", ".jar")})
LAUNCH_KINDS.update({e: "msi" for e in (".msi", ".msp", ".msix", ".appx")})
LAUNCH_KINDS[".lnk"] = "lnk"
LAUNCH_EXTS = frozenset(LAUNCH_KINDS)

# Content kinds an extension may legitimately carry.
_EXT_KINDS: dict[str, set[str]] = {e: {k} for e, k in LAUNCH_KINDS.items()}
_EXT_KINDS[".jar"] = {"pe", "archive"}
for _e in (".msix", ".appx"):
    _EXT_KINDS[_e] = {"msi", "archive"}
_EXT_KINDS[".dll"] = {"pe"}
_EXT_KINDS[".sys"] = {"pe"}
_EXT_KINDS[".pdf"] = {"pdf"}
for _e in OFFICE_EXTS:
    _EXT_KINDS[_e] = {"office"}
for _e in ARCHIVE_EXTS:
    _EXT_KINDS[_e] = {"archive"}
for _e in MEDIA_EXTS:
    _EXT_KINDS[_e] = {"media"}

# Authenticode applies only to PE/MSI and the script types that can carry a signature block.
# .lnk, .bat/.cmd, .hta, .vbe/.jse can't be signed: their signature status is always n/a.
SIGNABLE_SCRIPT_EXTS = frozenset({".ps1", ".psm1", ".psd1", ".ps1xml", ".vbs", ".js", ".wsf"})
UNSIGNABLE_EXTS = frozenset(e for e, k in LAUNCH_KINDS.items() if k in ("script", "lnk")) - SIGNABLE_SCRIPT_EXTS


def is_signable(kind: str, path: Path) -> bool:
    return kind in ("pe", "msi") or (kind == "script" and path.suffix.lower() in SIGNABLE_SCRIPT_EXTS)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _zip_kind(path: Path, ext: str) -> str:
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return "archive"
    if ext in (".msix", ".appx") or "AppxManifest.xml" in names:
        return "msi"
    if "[Content_Types].xml" in names and any(n.startswith(("word/", "xl/", "ppt/", "visio/")) for n in names):
        return "office"
    return "archive"


def _iso_magic(path: Path) -> bool:
    try:
        with open(path, "rb") as fh:
            fh.seek(0x8001)
            return fh.read(5) == b"CD001"
    except OSError:
        return False


def _is_pe(head: bytes) -> bool:
    if head[:2] != b"MZ" or len(head) < 0x40:
        return False
    off = int.from_bytes(head[0x3C:0x40], "little")
    return off + 4 <= len(head) and head[off:off + 4] == b"PE\x00\x00"


def _ole_is_msi(path: Path) -> bool:
    try:
        ole = olefile.OleFileIO(str(path))
    except Exception:
        return False
    try:
        clsid = str(getattr(ole.root, "clsid", "") or "").upper()
        if any(c in clsid for c in MSI_CLSIDS):
            return True
        # MSI table streams are prefixed "!" (stored encoded as U+4840)
        return any(part.startswith(("!", "䡀")) for entry in ole.listdir() for part in entry)
    except Exception:
        return False
    finally:
        ole.close()


def _archive_label(path: Path, head: bytes) -> str | None:
    """Label of a non-zip archive recognised by content, else None."""
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:6] == b"Rar!\x1a\x07":
        return "rar"
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[:4] == b"MSCF":
        return "cab"
    if head[257:262] == b"ustar":
        return "tar"
    if _iso_magic(path):
        return "iso"
    return None


def _content_kind(path: Path, head: bytes) -> str | None:
    """Kind decided by magic bytes alone, or None when the content has no recognisable signature."""
    ext = path.suffix.lower()
    if _is_pe(head):
        return "pe"
    if head[:4] == b"\xd0\xcf\x11\xe0":
        return "msi" if _ole_is_msi(path) else "office"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return _zip_kind(path, ext)
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:4] == b"\x4c\x00\x00\x00":
        return "lnk"
    if _archive_label(path, head) is not None:
        return "archive"
    if any(head.startswith(m) for m in MEDIA_MAGIC):
        return "media"
    return None


def _true_kind(path: Path, head: bytes) -> tuple[str, bool]:
    """Return (kind, ext_mismatch)."""
    ext = path.suffix.lower()
    content = _content_kind(path, head)
    expected = _EXT_KINDS.get(ext)
    mismatch = bool(content and expected is not None and content not in expected)
    if ext in LAUNCH_KINDS:  # launched by extension: that decides the kind
        return LAUNCH_KINDS[ext], mismatch
    if content:
        return content, mismatch
    if ext in MEDIA_EXTS:
        return "media", False
    if ext in ARCHIVE_EXTS:
        return "archive", False
    if ext in TEXT_EXTS or (head and b"\x00" not in head):
        return "text", False
    return "other", False


def _motw_zone(motw: dict | None) -> int | None:
    if not motw:
        return None
    for key in ("ZoneId", "zone_id", "zone"):
        if key in motw:
            try:
                return int(motw[key])
            except (TypeError, ValueError):
                return None
    return None


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError):
        return False


def _origin(path: Path, cfg: Config, doorway: str, motw: dict | None) -> str:
    if doorway == "written":
        return "local"
    zone = _motw_zone(motw)
    if zone is not None and zone >= 3:
        return "internet"
    if doorway == "download":
        if zone is None and any(r.name.lower() == "desktop" and _is_under(path, r) for r in cfg.watch_roots):
            return "local"  # no MotW on the Desktop: made on this PC (installers, shortcuts, the owner)
        return "internet" if zone is None else "own_device"
    # sync: the Downloads mirror counts as internet, everything else came from the owner's own device
    if any(r.name.lower() == "downloads" and _is_under(path, r) for r in cfg.watch_roots):
        return "internet"
    return "own_device"


def _in_code_tree(path: Path, cfg: Config) -> bool:
    if any(_is_under(path, r) for r in cfg.code_tree_roots):
        return True
    root = next((r for r in cfg.watch_roots if _is_under(path, r)), None)
    try:
        cur = path.resolve().parent
        stop = root.resolve() if root is not None else None
    except OSError:
        return False
    while cur != stop:
        if (cur / ".git").exists():
            return True
        if cur.parent == cur:
            break
        cur = cur.parent
    return False


def gather_facts(path: Path, cfg: Config, doorway: Literal["download", "sync", "written"],
                 motw: dict | None, signed: str) -> FileFacts:
    path = Path(path)
    with open(path, "rb") as fh:
        head = fh.read(4096)
    kind, mismatch = _true_kind(path, head)
    if is_signable(kind, path):
        if signed == "n/a":  # a launchable file is never "not applicable": no signature means unsigned
            signed = "unsigned"
    else:
        signed = "n/a"
    return FileFacts(path, _sha256(path), kind, mismatch, _origin(path, cfg, doorway, motw),  # type: ignore[arg-type]
                     signed, _in_code_tree(path, cfg))  # type: ignore[arg-type]


# ---------------------------------------------------------------- detectors
_MAX_ENTRIES = 10_000
_MAX_REL_BYTES = 1 << 20


def _add(out: dict[str, Finding], code: str, detail: str, severity: Severity) -> None:
    out.setdefault(code, Finding(code, detail, severity))


def _rels_attrs(data: bytes) -> list[dict[str, str]]:
    """Attributes (lower-cased keys) of every <Relationship>; rejects DOCTYPE/entities."""
    rels: list[dict[str, str]] = []

    def reject(*_a):
        raise ValueError("DTD/entity not allowed")

    def start(name, attrs):
        if name.lower().endswith("relationship"):
            rels.append({k.lower(): v for k, v in attrs.items()})

    p = expat.ParserCreate()
    p.StartDoctypeDeclHandler = reject
    p.EntityDeclHandler = reject
    p.StartElementHandler = start
    p.Parse(data, True)
    return rels


def office_findings(path: Path) -> list[Finding]:
    path = Path(path)
    out: dict[str, Finding] = {}
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
        if head[:4] == b"\xd0\xcf\x11\xe0":
            with warnings.catch_warnings():  # oletools emits pyparsing deprecation noise on import
                warnings.simplefilter("ignore")
                from oletools.olevba import VBA_Parser
            vp = VBA_Parser(str(path))
            try:
                if vp.detect_vba_macros():
                    _add(out, "office_macro", "VBA macros present", "risky")
            finally:
                vp.close()
        else:
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
                if len(infos) > _MAX_ENTRIES:
                    _add(out, "office_uninspectable", "too many entries", "notice")
                for info in infos[:_MAX_ENTRIES]:
                    name = info.filename
                    low = name.lower()
                    if low.endswith("vbaproject.bin"):
                        _add(out, "office_macro", f"VBA project {name[:80]}", "risky")
                    elif "/embeddings/" in low or low.endswith("oleobject.bin"):
                        _add(out, "office_ole_object", f"embedded object {name[:80]}", "notice")
                    elif low.endswith(".rels"):
                        if info.file_size > _MAX_REL_BYTES:
                            _add(out, "office_uninspectable", "oversized .rels part", "notice")
                            continue
                        try:
                            rels = _rels_attrs(z.read(info))
                        except (expat.ExpatError, ValueError):
                            _add(out, "office_uninspectable", "unparseable .rels part", "notice")
                            continue
                        for rel in rels:
                            if ("attachedtemplate" in rel.get("type", "").lower()
                                    and rel.get("targetmode", "").lower() == "external"):
                                _add(out, "office_remote_template",
                                     f"remote template {rel.get('target', '?')[:120]}", "risky")
    except Exception as exc:  # hostile/corrupt input: say so instead of reporting an empty list
        _add(out, "office_uninspectable", f"can't inspect: {type(exc).__name__}", "notice")
    return list(out.values())


_PDF_MAX = 64 * 1024 * 1024
_PDF_MAX_STREAMS = 5000
_PDF_MAX_CPU_S = 2.0
_PDF_MAX_INFLATED = 20 * 1024 * 1024
_STREAM_KW_RE = re.compile(rb"(?<![A-Za-z])stream(?:\r\n|\n)")
_NAME_ESC = re.compile(rb"#([0-9A-Fa-f]{2})")
# PDF whitespace is NUL/TAB/LF/FF/CR/SPACE and a %-comment counts as whitespace too.
_WS = rb"(?:[\x00\t\n\f\r ]|%[^\r\n]*[\r\n])"
_PDF_TOKENS = (
    ("pdf_javascript", re.compile(
        rb"/JS" + _WS + rb"*[(<]|/JS" + _WS + rb"+\d+" + _WS + rb"+\d+" + _WS + rb"+R"
        rb"|/S" + _WS + rb"*/JavaScript(?![A-Za-z])|/JavaScript" + _WS + rb"*[(<]"), "risky"),
    ("pdf_launch", re.compile(rb"/Launch(?![A-Za-z])"), "risky"),
    ("pdf_openaction", re.compile(rb"/OpenAction(?![A-Za-z])"), "notice"),
    ("pdf_additional_actions", re.compile(rb"/AA" + _WS + rb"*<<"), "notice"),
    ("pdf_embedded", re.compile(rb"/EmbeddedFile(?![A-Za-z])"), "notice"),
)


def _unescape_names(b: bytes) -> bytes:
    return _NAME_ESC.sub(lambda m: bytes([int(m.group(1), 16)]), b)


def _inflate_streams(data: bytes, problems: list[str]) -> list[bytes]:
    """Bounded inflation of EVERY stream, whatever its dictionary says (zlib or raw deflate).

    Non-deflate data (images etc.) fails immediately and is skipped. A stream that is still incomplete at the
    next "endstream" keeps being fed (bounded only by the total-inflate and CPU limits) so a planted "endstream" cannot cut it short.
    """
    out: list[bytes] = []
    total = 0
    n = 0
    t0 = time.thread_time()
    view = memoryview(data)
    for m in _STREAM_KW_RE.finditer(data):
        n += 1
        if n > _PDF_MAX_STREAMS:
            problems.append("too many streams")
            break
        if time.thread_time() - t0 > _PDF_MAX_CPU_S:
            problems.append("inflate time bound")
            break
        for wbits in (15, -15):
            d = zlib.decompressobj(wbits)
            got: list[bytes] = []
            pos = m.end()
            end = data.find(b"endstream", pos)
            try:
                while True:
                    stop = len(data) if end == -1 else end
                    chunk = d.decompress(view[pos:stop], _PDF_MAX_INFLATED - total + 1)
                    total += len(chunk)
                    got.append(chunk)
                    if total > _PDF_MAX_INFLATED or d.unconsumed_tail:
                        problems.append("inflate size bound")
                        return out
                    if d.eof or end == -1:
                        break
                    if time.thread_time() - t0 > _PDF_MAX_CPU_S:
                        problems.append("inflate time bound")
                        return out
                    pos = stop
                    end = data.find(b"endstream", stop + len(b"endstream"))
            except zlib.error:
                pass
            got = [c for c in got if c]
            if got:
                out.extend(got)
                break
    return out


def pdf_findings(path: Path) -> list[Finding]:
    """Structural-token scan over every byte of the file (no stream body is ever skipped) plus the inflated content of every stream."""
    out: dict[str, Finding] = {}
    problems: list[str] = []
    try:
        with open(path, "rb") as fh:
            data = fh.read(_PDF_MAX + 1)
        if len(data) > _PDF_MAX:
            problems.append("larger than read cap")
            data = data[:_PDF_MAX]
        text = _unescape_names(data) + b"\n" + b"\n".join(_inflate_streams(data, problems))
        for code, pattern, sev in _PDF_TOKENS:
            if pattern.search(text):
                _add(out, code, f"PDF contains {code[4:]} token", sev)  # type: ignore[arg-type]
    except Exception as exc:
        problems.append(type(exc).__name__)
    if problems:
        _add(out, "pdf_uninspectable", "can't fully inspect: " + "; ".join(sorted(set(problems))), "notice")
    return list(out.values())


# native executables/installers/shortcuts vs script files (scripts matter for internet origin only)
_ARC_NATIVE = {".exe", ".dll", ".scr", ".com", ".cpl", ".msi", ".msix", ".appx", ".lnk", ".jar", ".hta"}
_ARC_SCRIPT = SCRIPT_EXTS - {".hta"}
_ARC_NESTED = ARCHIVE_EXTS


def _unsafe_name(name: str) -> bool:
    n = name.replace("\\", "/")
    return n.startswith("/") or (len(n) > 1 and n[1] == ":") or ".." in n.split("/")


def _scan_names(out: dict[str, Finding], names) -> None:
    for count, name in enumerate(names, 1):
        if count > _MAX_ENTRIES:
            _add(out, "archive_too_many_entries", f"more than {_MAX_ENTRIES} entries", "notice")
            return
        ext = Path(name.replace("\\", "/")).suffix.lower()
        if _unsafe_name(name):
            _add(out, "archive_traversal", f"path traversal name {name[:80]}", "risky")
        elif ext in _ARC_NATIVE:
            _add(out, "archive_exec", f"contains {name[:80]}", "risky")
        elif ext in _ARC_SCRIPT:
            _add(out, "archive_script", f"contains {name[:80]}", "risky")
        elif ext in _ARC_NESTED:
            _add(out, "archive_nested", f"nested archive {name[:80]}", "notice")


def archive_findings(path: Path) -> list[Finding]:
    path = Path(path)
    out: dict[str, Finding] = {}
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
        label = _archive_label(path, head)
        if head[:2] == b"PK":
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()
            if any(i.flag_bits & 0x1 for i in infos):
                _add(out, "archive_encrypted", "encrypted archive", "risky")
            _scan_names(out, (i.filename for i in infos))
        elif label == "tar":
            with tarfile.open(path, "r:") as tf:
                names = []
                for member in tf:
                    names.append(member.name)
                    if (member.issym() or member.islnk()) and _unsafe_name(member.linkname):
                        _add(out, "archive_traversal", f"unsafe link target {member.linkname[:80]}", "risky")
                    if len(names) > _MAX_ENTRIES:
                        break
            _scan_names(out, names)
        else:
            label = label or path.suffix.lower().lstrip(".") or "archive"
            _add(out, "archive_uninspectable", f"can't inspect {label}", "notice")
    except Exception as exc:
        _add(out, "archive_uninspectable", f"can't inspect: {type(exc).__name__}", "notice")
    return list(out.values())

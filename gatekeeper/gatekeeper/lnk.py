"""Minimal Shell Link (.lnk, MS-SHLLINK) reader: a shortcut is judged by everything it could launch.

Windows may resolve a shortcut from its IDList, its expanded environment string, LinkInfo, or the
relative path, so every one of them is a target candidate and the shortcut is flagged if ANY matches:
  - LinkInfo LocalBasePath + CommonPathSuffix (or the network NetName + suffix),
  - EnvironmentVariableDataBlock, ANSI and Unicode (expanded when judged),
  - StringData RelativePath (WorkingDir and the arguments are checked for drop folders / LOLBins too),
  - file-name components of the LinkTargetIDList (best effort, bounded walk).
A shortcut whose target can't be determined (parse failure, unresolvable IDList only, network/UNC) gets
`lnk_uninspectable` (notice severity; the verdict makes it risky for internet origin).
Stdlib only; never executes anything; every read is bounds-checked.
"""
from __future__ import annotations

import ntpath
import os
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path

from .facts import Finding

CLSID = bytes.fromhex("0114020000000000c000000000000046")
MAX_BYTES = 1 << 20
MAX_ITEMS = 64
LOLBINS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
           "regsvr32.exe", "bitsadmin.exe", "certutil.exe", "msiexec.exe", "wmic.exe", "forfiles.exe", "hh.exe",
           "msbuild.exe", "installutil.exe", "regasm.exe", "conhost.exe", "curl.exe"}
# Path fragments (lower case, backslashes) of drop folders, on any user profile.
# Temp: risky whatever the shortcut's origin. Downloads/%APPDATA%: risky only for an internet-origin
# shortcut, because per-user installers (Zoom, ...) legitimately put their programs under %APPDATA%.
_TEMP_FRAGMENTS = ("\\appdata\\local\\temp\\", "\\windows\\temp\\")
_TEMP_ENV = ("TEMP", "TMP")
_USER_FRAGMENTS = ("\\downloads\\", "\\appdata\\roaming\\")
_USER_ENV = ("APPDATA",)

_HAS_IDLIST, _HAS_LINKINFO, _IS_UNICODE, _HAS_EXP = 0x1, 0x2, 0x80, 0x200
_STRING_FLAGS = (("name", 0x4), ("relpath", 0x8), ("workdir", 0x10), ("args", 0x20), ("icon", 0x40))
_ENV_BLOCK = 0xA0000001
_BEEF0004 = b"\x04\x00\xef\xbe"
_TOKEN = re.compile(r'"([^"]*)"|(\S+)')


class LnkError(ValueError):
    pass


@dataclass
class LnkTarget:
    path: str | None  # first target candidate
    args: str
    relpath: str = ""
    workdir: str = ""
    candidates: list[str] = field(default_factory=list)  # every target-path candidate, deduplicated
    network: bool = False


def _u16(d: bytes, o: int) -> int:
    return struct.unpack_from("<H", d, o)[0]


def _u32(d: bytes, o: int) -> int:
    return struct.unpack_from("<I", d, o)[0]


def _cstr(d: bytes, o: int, end: int) -> str:
    if not 0 <= o < end:
        raise LnkError("string offset out of range")
    z = d.find(b"\x00", o, end)
    if z < 0:
        raise LnkError("unterminated string")
    return d[o:z].decode("cp1252", "replace")


def _wstr(d: bytes, o: int, end: int) -> str:
    if not 0 <= o < end:
        raise LnkError("string offset out of range")
    i = o
    while i + 1 < end:
        if d[i] == 0 and d[i + 1] == 0:
            return d[o:i].decode("utf-16-le", "replace")
        i += 2
    raise LnkError("unterminated string")


def _join(base: str, suffix: str) -> str:
    if base and suffix and not base.endswith("\\"):
        base += "\\"
    return base + suffix


def _link_info(d: bytes, off: int) -> tuple[str | None, str | None, int]:
    """(local path, network path, end offset)."""
    size = _u32(d, off)
    end = off + size
    if size < 0x1C or end > len(d):
        raise LnkError("bad LinkInfo size")
    hsize, flags = _u32(d, off + 4), _u32(d, off + 8)
    lbp, cnrl, cps = _u32(d, off + 16), _u32(d, off + 20), _u32(d, off + 24)
    uni = hsize >= 0x24
    suffix = ""
    if uni and _u32(d, off + 32):
        suffix = _wstr(d, off + _u32(d, off + 32), end)
    elif cps:
        suffix = _cstr(d, off + cps, end)
    local = net = None
    if flags & 0x1:
        if uni and _u32(d, off + 28):
            base = _wstr(d, off + _u32(d, off + 28), end)
        else:
            base = _cstr(d, off + lbp, end)
        local = _join(base, suffix) or None
    if flags & 0x2 and cnrl:
        c = off + cnrl
        if c + 0x14 > end:
            raise LnkError("bad CommonNetworkRelativeLink")
        netname = _cstr(d, c + _u32(d, c + 8), end)
        net = _join(netname, suffix) or None
    return local, net, end


def _entry_name(item: bytes) -> str | None:
    """Long name of a FileEntry shell item (from its 0xBEEF0004 block), else its 8.3 name."""
    short = None
    z = item.find(b"\x00", 14)
    if z > 14:
        short = item[14:z].decode("cp1252", "replace")
    i = item.find(_BEEF0004, 14)
    if i >= 18:
        ext = i - 4
        try:
            ver = _u16(item, ext + 2)
            rel = 46 if ver >= 9 else 42 if ver == 8 else 38 if ver == 7 else 18
            name = _wstr(item, ext + rel, len(item))
            if name and all(ch.isprintable() for ch in name):
                return name
        except (struct.error, LnkError):
            pass
    return short


def _idlist_path(d: bytes, o: int, end: int) -> tuple[str | None, bool]:
    """Best-effort path from the IDList's volume + FileEntry items; (path, saw a network item)."""
    drive, names, network = "", [], False
    for _ in range(MAX_ITEMS):
        if o + 2 > end:
            break
        size = _u16(d, o)
        if size == 0 or size < 3 or o + size > end:
            break
        item = d[o:o + size]
        cls = item[2] & 0x70
        if cls == 0x20 and len(item) > 4:  # volume: "C:\"
            drive = item[3:].split(b"\x00", 1)[0].decode("ascii", "replace")[:3]
        elif cls == 0x30:  # file / folder entry
            n = _entry_name(item)
            if n:
                names.append(n)
        elif cls == 0x40:  # network location
            network = True
        o += size
    if not names:
        return None, network
    path = "\\".join(names)
    if drive:
        path = _join(drive, path)
    return path, network


def _env_targets(d: bytes, off: int) -> list[str]:
    out: list[str] = []
    for _ in range(MAX_ITEMS):
        if off + 8 > len(d):
            break
        size = _u32(d, off)
        if size < 4:
            break  # TerminalBlock
        if off + size > len(d):
            raise LnkError("truncated ExtraData")
        if _u32(d, off + 4) == _ENV_BLOCK and size >= 0x314:
            for s in (_cstr(d, off + 8, off + 8 + 260) if 0 in d[off + 8:off + 268] else "",
                      _wstr(d, off + 268, off + 788) if any(d[off + 268:off + 270]) else ""):
                if s:
                    out.append(s)
        off += size
    return out


def parse_lnk(data: bytes) -> LnkTarget:
    try:
        if len(data) < 0x4C or _u32(data, 0) != 0x4C or data[4:20] != CLSID:
            raise LnkError("not a shell link")
        flags = _u32(data, 0x14)
        off = 0x4C
        id_path, network = None, False
        if flags & _HAS_IDLIST:
            n = _u16(data, off)
            if off + 2 + n > len(data):
                raise LnkError("truncated IDList")
            try:
                id_path, network = _idlist_path(data, off + 2, off + 2 + n)
            except (struct.error, IndexError, LnkError):
                id_path = None
            off += 2 + n
        local = net = None
        if flags & _HAS_LINKINFO:
            local, net, off = _link_info(data, off)
        unicode = bool(flags & _IS_UNICODE)
        strings: dict[str, str] = {}
        for name, bit in _STRING_FLAGS:
            if flags & bit:
                n = _u16(data, off)
                nbytes = n * 2 if unicode else n
                raw = data[off + 2:off + 2 + nbytes]
                if len(raw) != nbytes:
                    raise LnkError("truncated StringData")
                strings[name] = raw.decode("utf-16-le" if unicode else "cp1252", "replace")
                off += 2 + nbytes
        if off > len(data):
            raise LnkError("truncated")
        env = _env_targets(data, off) if flags & _HAS_EXP else []
        cands: list[str] = []
        for c in [local, net, *env, strings.get("relpath", ""), id_path]:
            if c and c not in cands:
                cands.append(c)
        if net:
            network = True
        return LnkTarget(cands[0] if cands else None, strings.get("args", ""), strings.get("relpath", ""),
                         strings.get("workdir", ""), cands, network)
    except (struct.error, IndexError) as e:
        raise LnkError(f"malformed shell link: {type(e).__name__}") from e


def _norm(p: str) -> str:
    return ntpath.normpath(os.path.expandvars(p)).lower().replace("/", "\\")


def _under_any(target: str, env: tuple[str, ...], fragments: tuple[str, ...], extra: list[str]) -> bool:
    t = _norm(target) + "\\"
    raw = target.lower()
    if any(raw.startswith(f"%{v.lower()}%") for v in env):
        return True
    if any(f in t for f in fragments):
        return True
    dirs = [os.environ.get(v) for v in env] + extra
    return any(d and t.startswith(_norm(d).rstrip("\\") + "\\") for d in dirs)


def _in_temp(target: str) -> bool:
    return _under_any(target, _TEMP_ENV, _TEMP_FRAGMENTS, [])


def _in_user_dir(target: str) -> bool:
    return _under_any(target, _USER_ENV, _USER_FRAGMENTS, [str(Path.home() / "Downloads")])


def _tokens(args: str) -> list[str]:
    out = []
    for m in _TOKEN.finditer(args[:4096]):
        tok = m.group(1) if m.group(1) is not None else m.group(2)
        if tok:
            out.append(tok)
    return out[:256]


def _exe_name(p: str) -> str:
    base = ntpath.basename(_norm(p)) if p else ""
    return base if base.endswith(".exe") else base + ".exe"


def lnk_findings(path: Path, origin: str = "internet") -> list[Finding]:
    """Findings for a shortcut. `origin` is the .lnk's own origin (facts.origin); unknown counts as internet."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES)
        t = parse_lnk(data)
    except (OSError, LnkError) as e:
        return [Finding("lnk_uninspectable", f"shortcut could not be parsed ({str(e)[:80]})", "notice")]
    risky: list[str] = []
    args = t.args.strip()
    tokens = _tokens(args)

    def place(p: str, what: str) -> None:
        if _in_temp(p):
            risky.append(f"shortcut {what} in a temp folder: {p[:160]}")
        elif origin == "internet" and _in_user_dir(p):
            risky.append(f"internet shortcut {what} in Downloads/AppData: {p[:160]}")

    for c in t.candidates:
        exe = _exe_name(c)
        if exe in LOLBINS and args:
            risky.append(f"shortcut runs {exe} with arguments: {args[:120]}")
        place(c, "target")
    if t.workdir:
        place(t.workdir, "working folder")
    for i, tok in enumerate(tokens):
        value = tok.split("=", 1)[1] if tok.startswith("-") and "=" in tok else tok
        if _exe_name(value) in LOLBINS and i < len(tokens) - 1:
            risky.append(f"shortcut arguments run {_exe_name(value)}: {args[:120]}")
        if "\\" in value or value.startswith("%"):
            place(value, "argument")

    out: list[Finding] = []
    if risky:
        out.append(Finding("lnk_target", risky[0], "risky"))
    if not t.candidates:
        out.append(Finding("lnk_uninspectable", "shortcut target unknown (IDList could not be resolved)", "notice"))
    elif t.network or any(_norm(c).startswith("\\\\") for c in t.candidates):
        out.append(Finding("lnk_uninspectable", "shortcut points to a network/UNC location", "notice"))
    return out

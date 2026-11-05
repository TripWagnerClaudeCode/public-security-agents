"""Builds minimal, harmless MS-SHLLINK (.lnk) files for tests."""
from __future__ import annotations

import struct

CLSID = bytes.fromhex("0114020000000000c000000000000046")
MY_COMPUTER = bytes.fromhex("e04fd020ea3a6910a2d808002b30309d")
HAS_IDLIST, HAS_LINKINFO, HAS_NAME, HAS_RELPATH, HAS_WORKDIR, HAS_ARGS, HAS_ICON, IS_UNICODE = (
    0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80)
HAS_EXP_STRING = 0x200


def _str(s: str, unicode: bool) -> bytes:
    return struct.pack("<H", len(s)) + (s.encode("utf-16-le") if unicode else s.encode("cp1252"))


def _item(body: bytes) -> bytes:
    return struct.pack("<H", len(body) + 2) + body


def _file_entry(name: str, is_dir: bool, long_name: bool = True) -> bytes:
    short = name[:12].upper().encode("cp1252") + b"\x00"
    if len(short) % 2:
        short += b"\x00"
    body = bytes([0x31 if is_dir else 0x32, 0]) + struct.pack("<IIH", 0, 0, 0x10 if is_dir else 0x20) + short
    if long_name:
        # Extension block 0xBEEF0004, version 9: the long name starts 46 bytes into the block.
        head = struct.pack("<HHI", 0, 9, 0xBEEF0004) + b"\x00" * 38
        ext = head + name.encode("utf-16-le") + b"\x00\x00" + struct.pack("<H", len(short) + 14)
        ext = struct.pack("<H", len(ext)) + ext[2:]
        body += ext
    return _item(body)


def idlist_items(path: str, long_names: bool = True) -> bytes:
    """IDList for a local path: My Computer, the volume, then one FileEntry per component."""
    drive, _, rest = path.partition("\\")
    items = _item(bytes([0x1F, 0x50]) + MY_COMPUTER)
    items += _item(bytes([0x2F]) + (drive + "\\").encode("ascii").ljust(23, b"\x00"))
    parts = [p for p in rest.split("\\") if p]
    for i, p in enumerate(parts):
        items += _file_entry(p, is_dir=i < len(parts) - 1, long_name=long_names)
    return items


def make_lnk(target: str | None, args: str = "", *, unicode: bool = True, idlist: bool = False,
             name: str = "", env_target: str | None = None, icon: str = "", idlist_path: str | None = None,
             unc: str | None = None, env_unicode: str | None = None, relpath: str = "",
             workdir: str = "") -> bytes:
    flags = IS_UNICODE if unicode else 0
    body = b""
    if idlist or idlist_path:
        flags |= HAS_IDLIST
        if idlist_path:
            items = idlist_items(idlist_path)
        else:
            items = _item(b"\x1f\x50" + b"\x00" * 16)  # one root-folder item that names no file
        ids = items + b"\x00\x00"
        body += struct.pack("<H", len(ids)) + ids
    if target is not None:
        flags |= HAS_LINKINFO
        vol = struct.pack("<IIII", 0x11, 3, 0x1234, 0x10) + b"\x00"
        base = target.encode("cp1252") + b"\x00"
        hdr = 0x1C
        vol_off = hdr
        lbp_off = vol_off + len(vol)
        cps_off = lbp_off + len(base)
        info_body = vol + base + b"\x00"
        size = hdr + len(info_body)
        body += struct.pack("<IIIIIII", size, hdr, 0x1, vol_off, lbp_off, 0, cps_off) + info_body
    elif unc is not None:
        flags |= HAS_LINKINFO
        parts = unc[2:].split("\\")  # \\host\share\dir\x.exe: net name \\host\share, suffix dir\x.exe
        host, sh, suffix = parts[0], parts[1], "\\".join(parts[2:])
        netname = ("\\\\" + host + "\\" + sh).encode("cp1252") + b"\x00"
        cnrl = struct.pack("<IIIII", 0x14 + len(netname), 0x2, 0x14, 0, 0x20000) + netname
        hdr = 0x1C
        cnrl_off = hdr
        cps_off = cnrl_off + len(cnrl)
        info_body = cnrl + suffix.encode("cp1252") + b"\x00"
        size = hdr + len(info_body)
        body += struct.pack("<IIIIIII", size, hdr, 0x2, 0, 0, cnrl_off, cps_off) + info_body
    strings = b""
    if name:
        flags |= HAS_NAME
        strings += _str(name, unicode)
    if relpath:
        flags |= HAS_RELPATH
        strings += _str(relpath, unicode)
    if workdir:
        flags |= HAS_WORKDIR
        strings += _str(workdir, unicode)
    if args:
        flags |= HAS_ARGS
        strings += _str(args, unicode)
    if icon:
        flags |= HAS_ICON
        strings += _str(icon, unicode)
    extra = b""
    if env_target is not None or env_unicode is not None:
        flags |= HAS_EXP_STRING
        a = env_target if env_target is not None else ""
        u = env_unicode if env_unicode is not None else a
        ansi = a.encode("cp1252")[:259].ljust(260, b"\x00")
        uni = u.encode("utf-16-le")[:518].ljust(520, b"\x00")
        extra += struct.pack("<II", 0x314, 0xA0000001) + ansi + uni
    extra += b"\x00\x00\x00\x00"  # TerminalBlock
    header = struct.pack("<I16sIIQQQIiIHHII", 0x4C, CLSID, flags, 0x20, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0)
    assert len(header) == 0x4C
    return header + body + strings + extra

"""Adapters around external scanners. None of these raise: failure becomes a `notice` finding."""
from __future__ import annotations

import functools
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Literal

from gatekeeper.facts import UNSIGNABLE_EXTS, Finding

# Installed by tools/fetch_yara.py (not bundled: YARA Forge rules carry their own licenses).
YARA_RULES = Path(os.environ.get("GATEKEEPER_YARA_RULES") or (Path.home() / ".gatekeeper" / "yara-rules-core.yar"))
# gitleaks: $GATEKEEPER_GITLEAKS (a path), else `gitleaks` on PATH or in ~/.local/bin. On Windows it can also
# run inside WSL: GATEKEEPER_GITLEAKS_WSL="<distro>:<path to gitleaks in that distro>".
YARA_FETCH_HINT = "run tools/fetch_yara.py"
GITLEAKS_MAX_BYTES = 5 * 1024 * 1024
_NOFLASH = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def read_motw(path: Path) -> dict | None:
    """Parse the Zone.Identifier alternate data stream; None if absent or unusable."""
    try:
        with open(str(path) + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    vals: dict[str, str] = {}
    for line in text.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            vals[k.strip()] = v.strip()
    try:
        zone = int(vals["ZoneId"])
    except (KeyError, ValueError):
        return None
    return {"ZoneId": zone, "HostUrl": vals.get("HostUrl") or None, "ReferrerUrl": vals.get("ReferrerUrl") or None}


def authenticode(path: Path) -> Literal["valid", "unsigned", "invalid", "n/a"]:
    env = dict(os.environ, GK_PATH=str(path))
    cmd = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
           "(Get-AuthenticodeSignature -LiteralPath $env:GK_PATH).Status"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, env=env, creationflags=_NOFLASH)
    except (OSError, subprocess.SubprocessError):
        return "n/a"
    status = r.stdout.strip()
    if r.returncode != 0 or not status:
        return "n/a"
    if status == "Valid":
        return "valid"
    if path.suffix.lower() in UNSIGNABLE_EXTS and status in ("NotSigned", "UnknownError"):
        return "n/a"  # the type can't carry a signature: not a bad signature
    if status == "NotSigned":
        return "unsigned"
    return "invalid"


def find_mpcmdrun() -> Path | None:
    pd = os.environ.get("ProgramData", r"C:\ProgramData")
    plat = Path(pd) / "Microsoft" / "Windows Defender" / "Platform"
    try:
        dirs = sorted((d for d in plat.iterdir() if (d / "MpCmdRun.exe").is_file()),
                      key=lambda d: [int(p) if p.isdigit() else 0 for p in d.name.replace("-", ".").split(".")],
                      reverse=True)
        if dirs:
            return dirs[0] / "MpCmdRun.exe"
    except OSError:
        pass
    legacy = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"
    return legacy if legacy.is_file() else None


def defender_scan(path: Path) -> list[Finding]:
    unavailable = [Finding("defender_unavailable", "Defender unavailable", "notice")]
    exe = find_mpcmdrun()
    if exe is None:
        return unavailable
    existed = path.exists()
    try:
        r = subprocess.run([str(exe), "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"],
                           capture_output=True, text=True, timeout=120, creationflags=_NOFLASH)
    except (OSError, subprocess.SubprocessError):
        return unavailable
    if r.returncode == 2 or (existed and not path.exists()):
        detail = "removed by Defender" if existed and not path.exists() else "Defender detected a threat"
        return [Finding("defender_threat", detail, "critical")]
    if r.returncode != 0:
        return unavailable
    return []


@functools.lru_cache(maxsize=1)
def load_yara():
    """Compiled rules, or None if the rule file isn't installed (see data/yara/SOURCES.md)."""
    if not YARA_RULES.is_file():
        return None
    import yara
    return yara.compile(filepath=str(YARA_RULES))


def gitleaks_command() -> tuple[list[str], object] | None:
    """(argv prefix, path converter) for gitleaks, or None if it isn't available."""
    import shutil
    explicit = os.environ.get("GATEKEEPER_GITLEAKS", "").strip()
    if explicit:
        return [explicit], str
    found = shutil.which("gitleaks") or (str(Path.home() / ".local" / "bin" / "gitleaks")
                                         if (Path.home() / ".local" / "bin" / "gitleaks").is_file() else None)
    if found:
        return [found], str
    wsl = os.environ.get("GATEKEEPER_GITLEAKS_WSL", "").strip()
    if sys.platform == "win32" and ":" in wsl:
        distro, _, exe = wsl.partition(":")
        return ["wsl.exe", "-d", distro, "-e", exe], to_wsl_path
    return None


def yara_scan(path: Path, rules) -> list[Finding]:
    if rules is None:
        return [Finding("yara_unavailable", f"YARA rules not installed ({YARA_FETCH_HINT})", "notice")]
    try:
        matches = rules.match(filepath=str(path), timeout=30)
    except Exception:  # yara.Error, TimeoutError, OSError
        return [Finding("yara_unavailable", "YARA unavailable", "notice")]
    return [Finding("yara_match", f"YARA rule matched: {m.rule}", "critical") for m in matches]


def to_wsl_path(path: Path) -> str:
    p = str(path).replace("\\", "/")
    if len(p) > 1 and p[1] == ":":
        p = f"/mnt/{p[0].lower()}{p[2:]}"
    return p


def _is_text(path: Path) -> bool:
    try:
        if path.stat().st_size >= GITLEAKS_MAX_BYTES:
            return False
        with open(path, "rb") as fh:
            return b"\x00" not in fh.read(8192)
    except OSError:
        return False


def gitleaks_scan(path: Path) -> list[Finding]:
    if not _is_text(path):
        return []
    unavailable = [Finding("gitleaks_unavailable", "gitleaks unavailable", "notice")]
    fd, report = tempfile.mkstemp(suffix=".json", prefix="gk-leaks-")
    os.close(fd)
    try:
        resolved = gitleaks_command()
        if resolved is None:
            return unavailable
        base, conv = resolved
        cmd = base + ["dir", conv(path), "--redact", "--no-banner", "--report-format", "json",
                      "--report-path", conv(Path(report)), "--exit-code", "0", "--no-color"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, creationflags=_NOFLASH)
        except (OSError, subprocess.SubprocessError):
            return unavailable
        if r.returncode != 0:
            return unavailable
        try:
            text = Path(report).read_text(encoding="utf-8").strip()
            leaks = json.loads(text) if text else []
        except (OSError, ValueError):
            return unavailable
        return [Finding("secret_in_file", f"{x.get('RuleID', 'secret')} at line {x.get('StartLine', '?')} (redacted)",
                        "secret") for x in leaks if isinstance(x, dict)]
    finally:
        try:
            os.unlink(report)
        except OSError:
            pass

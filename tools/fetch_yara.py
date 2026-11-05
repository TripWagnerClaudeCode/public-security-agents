#!/usr/bin/env python3
"""Download the YARA Forge "core" rule set for Gatekeeper and verify it against the pinned hashes.

    python tools/fetch_yara.py [OUT]      # default OUT: ~/.gatekeeper/yara-rules-core.yar (where Gatekeeper looks)
                                          # (set GATEKEEPER_YARA_RULES to use another path)

The rules are not bundled with this repo (they are a separate project with their own per-rule licenses).
Gatekeeper runs without them: YARA checks then report a `yara_unavailable` notice instead of matching.
"""
from __future__ import annotations

import hashlib
import io
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "gatekeeper" / "gatekeeper" / "data" / "yara"
SOURCES = DATA / "SOURCES.md"
MEMBER = "packages/core/yara-rules-core.yar"


def pinned() -> tuple[str, str, str]:
    text = SOURCES.read_text(encoding="utf-8")
    url = re.search(r"- URL: (\S+)", text).group(1)
    zip_sha = re.search(r"SHA-256 of the zip: ([0-9A-Fa-f]{64})", text).group(1).lower()
    yar_sha = re.search(r"SHA-256 of yara-rules-core\.yar: ([0-9A-Fa-f]{64})", text).group(1).lower()
    return url, zip_sha, yar_sha


def main() -> int:
    url, zip_sha, yar_sha = pinned()
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as r:
        blob = r.read()
    got = hashlib.sha256(blob).hexdigest()
    if got != zip_sha:
        print(f"zip SHA-256 mismatch: expected {zip_sha}, got {got}. Not installed.", file=sys.stderr)
        return 1
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        rules = z.read(MEMBER)
    got = hashlib.sha256(rules).hexdigest()
    if got != yar_sha:
        print(f"rules SHA-256 mismatch: expected {yar_sha}, got {got}. Not installed.", file=sys.stderr)
        return 1
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.home() / ".gatekeeper" / "yara-rules-core.yar"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(rules)
    print(f"installed {out} ({len(rules):,} bytes, hashes verified)")
    print("Restart Gatekeeper (or wait for its next start) to load the rules.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""`python -m gatekeeper serve`."""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["serve"]:
        from . import serve
        return serve.main(argv[1:])
    if argv[:1] == ["backfill"]:
        from . import backfill
        return backfill.main(argv[1:])
    print("usage: python -m gatekeeper serve|backfill [--no-push]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

"""Fail-safe entry point for the Claude Code hook: `python -I gatekeeper_hook_shim.py pre|post`.

Stdlib only. If the gatekeeper package can't be imported or crashes, PreToolUse still gets an `ask`
(PostToolUse gets nothing) and the process exits 0, so a broken install never lets a tool call through
silently. Imports come from this file's own directory (the deployed snapshot), never from the cwd.
"""
import json
import os
import sys

UNAVAILABLE = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                      "permissionDecisionReason": "Gatekeeper: unavailable: import failed"}}


def _fail(mode):
    if mode == "pre":
        sys.stdout.write(json.dumps(UNAVAILABLE))
        sys.stdout.flush()


def run():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from gatekeeper.hook import main
    except BaseException as e:  # noqa: BLE001 - any import-time break must still ask
        try:
            sys.stderr.write(f"gatekeeper shim: import failed: {type(e).__name__}\n")
        except BaseException:
            pass
        _fail(mode)
        return 0
    try:
        return main(sys.argv[1:]) or 0
    except BaseException:  # noqa: BLE001 - main handles its own errors; this is the last net
        _fail(mode)
        return 0


if __name__ == "__main__":
    sys.exit(run())

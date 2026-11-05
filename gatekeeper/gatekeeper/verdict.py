"""Verdict rules: FileFacts + findings -> clean | notice | risky | secret."""
from __future__ import annotations

from typing import Literal

from gatekeeper.facts import LAUNCH_EXTS, FileFacts, Finding

Verdict = Literal["clean", "notice", "risky", "secret"]

# Finding codes whose weight depends on origin: code -> origins where they are risky (else notice).
_RISKY_ORIGINS: dict[str, set[str]] = {
    "office_macro": {"internet"},
    "office_remote_template": {"internet"},
    "archive_exec": {"internet", "own_device"},
    "archive_encrypted": {"internet"},
    "archive_uninspectable": {"internet"},
    "archive_script": {"internet"},
    "archive_too_many_entries": {"internet"},
    "office_uninspectable": {"internet"},
    "pdf_uninspectable": {"internet"},
    "lnk_uninspectable": {"internet"},
}
_TYPE_RULE_KINDS = {"pe", "msi", "script"}  # a .lnk is judged by its target (lnk_target finding)


def classify(facts: FileFacts, findings: list[Finding]) -> Verdict:
    risky = False
    secret = False
    notice = False

    for f in findings:
        if f.severity == "critical":
            risky = True
        elif f.code in _RISKY_ORIGINS:
            if facts.origin in _RISKY_ORIGINS[f.code]:
                risky = True
            else:
                notice = True
        elif f.severity == "risky":
            risky = True
        elif f.severity == "secret":
            secret = True
        else:
            notice = True

    # Internet executable/installer/script/LNK: risky unless validly signed.
    # Source/script files in a code tree only trip on scanner hits (critical findings).
    if (facts.origin == "internet" and facts.kind in _TYPE_RULE_KINDS and facts.signed != "valid"
            and not (facts.in_code_tree and facts.kind == "script")):
        risky = True

    if facts.ext_mismatch:
        if facts.kind in ("pe", "msi"):
            risky = True
        elif facts.path.suffix.lower() in LAUNCH_EXTS and facts.origin != "local":
            risky = True  # Windows launches by extension: the content is not what the name says
        else:
            notice = True

    if risky:
        return "risky"
    if secret:
        return "secret"
    if notice:
        return "notice"
    return "clean"

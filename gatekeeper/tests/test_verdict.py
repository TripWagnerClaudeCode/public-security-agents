from pathlib import Path

import pytest

from gatekeeper.facts import FileFacts, Finding
from gatekeeper.verdict import classify


def F(kind="other", origin="local", signed="n/a", mismatch=False, code_tree=False, name="x"):
    return FileFacts(Path(name), "0" * 64, kind, mismatch, origin, signed, code_tree)


def f(code, sev="risky"):
    return Finding(code, "d", sev)


CASES = [
    ("critical", F("text", "local", code_tree=True), [f("defender_hit", "critical")], "risky"),
    ("critical_own", F("other", "own_device"), [f("yara_hit", "critical")], "risky"),
    ("net_pe_unsigned", F("pe", "internet", "unsigned"), [], "risky"),
    ("net_pe_valid", F("pe", "internet", "valid"), [], "clean"),
    ("net_script_invalid", F("script", "internet", "invalid"), [], "risky"),
    ("net_lnk_judged_by_target", F("lnk", "internet", "n/a"), [], "clean"),
    ("net_lnk_invalid_ignored", F("lnk", "internet", "invalid"), [], "clean"),
    ("net_lnk_bad_target", F("lnk", "internet", "n/a"), [f("lnk_target")], "risky"),
    ("local_lnk_bad_target", F("lnk", "local", "n/a"), [f("lnk_target")], "risky"),
    ("lnk_uninspectable_net", F("lnk", "internet", "n/a"), [f("lnk_uninspectable", "notice")], "risky"),
    ("lnk_uninspectable_local", F("lnk", "local", "n/a"), [f("lnk_uninspectable", "notice")], "notice"),
    ("lnk_uninspectable_own", F("lnk", "own_device", "n/a"), [f("lnk_uninspectable", "notice")], "notice"),
    ("net_bat_unsignable", F("script", "internet", "n/a", name="a.bat"), [], "risky"),
    ("own_pe_unsigned", F("pe", "own_device", "unsigned"), [], "clean"),
    ("net_office_macro", F("office", "internet"), [f("office_macro")], "risky"),
    ("net_office_template", F("office", "internet"), [f("office_remote_template")], "risky"),
    ("own_office_macro", F("office", "own_device"), [f("office_macro")], "notice"),
    ("pdf_js_net", F("pdf", "internet"), [f("pdf_javascript")], "risky"),
    ("pdf_js_own", F("pdf", "own_device"), [f("pdf_javascript")], "risky"),
    ("pdf_launch_local", F("pdf", "local"), [f("pdf_launch")], "risky"),
    ("pdf_openaction_notice", F("pdf", "local"), [f("pdf_openaction", "notice")], "notice"),
    ("arc_exec_net", F("archive", "internet"), [f("archive_exec")], "risky"),
    ("arc_exec_own", F("archive", "own_device"), [f("archive_exec")], "risky"),
    ("arc_exec_local", F("archive", "local"), [f("archive_exec")], "notice"),
    ("arc_enc_net", F("archive", "internet"), [f("archive_encrypted")], "risky"),
    ("arc_enc_own", F("archive", "own_device"), [f("archive_encrypted")], "notice"),
    ("arc_traversal_local", F("archive", "local"), [f("archive_traversal")], "risky"),
    ("arc_traversal_net", F("archive", "internet"), [f("archive_traversal")], "risky"),
    ("arc_uninspectable_net", F("archive", "internet"), [f("archive_uninspectable", "notice")], "risky"),
    ("arc_uninspectable_own", F("archive", "own_device"), [f("archive_uninspectable", "notice")], "notice"),
    ("mismatch_pe", F("pe", "local", "unsigned", mismatch=True), [], "risky"),
    ("mismatch_pdf_only", F("pdf", "local", mismatch=True), [], "notice"),
    ("ps1_unsigned_own_codetree", F("script", "own_device", "unsigned", code_tree=True), [], "clean"),
    ("ps1_unsigned_local_codetree", F("script", "local", "unsigned", code_tree=True), [], "clean"),
    ("net_ps1_codetree", F("script", "internet", "unsigned", code_tree=True), [], "clean"),
    ("zip_exe_codetree_net", F("archive", "internet", code_tree=True), [f("archive_exec")], "risky"),
    ("arc_script_net", F("archive", "internet"), [f("archive_script")], "risky"),
    ("arc_script_own", F("archive", "own_device"), [f("archive_script")], "notice"),
    ("arc_toomany_net", F("archive", "internet"), [f("archive_too_many_entries", "notice")], "risky"),
    ("arc_toomany_own", F("archive", "own_device"), [f("archive_too_many_entries", "notice")], "notice"),
    ("office_unins_net", F("office", "internet"), [f("office_uninspectable", "notice")], "risky"),
    ("office_unins_own", F("office", "own_device"), [f("office_uninspectable", "notice")], "notice"),
    ("pdf_unins_net", F("pdf", "internet"), [f("pdf_uninspectable", "notice")], "risky"),
    ("pdf_unins_local", F("pdf", "local"), [f("pdf_uninspectable", "notice")], "notice"),
    ("launch_mismatch_net", F("script", "internet", "valid", True, name="invoice.pdf.ps1"), [], "risky"),
    ("launch_mismatch_own", F("script", "own_device", "unsigned", True, name="cat.hta"), [], "risky"),
    ("launch_mismatch_local", F("script", "local", "unsigned", True, name="cat.hta"), [], "notice"),
    ("launch_mismatch_local_hit", F("script", "local", "unsigned", True, name="cat.hta"),
     [f("yara_hit", "critical")], "risky"),
    ("secret_only", F("text", "local"), [f("gitleaks", "secret")], "secret"),
    ("secret_and_risky", F("text", "internet"), [f("gitleaks", "secret"), f("yara_hit", "critical")], "risky"),
    ("notice_only", F("text", "local"), [f("x", "notice")], "notice"),
    ("nothing", F("text", "local"), [], "clean"),
]


@pytest.mark.parametrize("facts,findings,expected", [c[1:] for c in CASES], ids=[c[0] for c in CASES])
def test_classify(facts, findings, expected):
    assert classify(facts, findings) == expected

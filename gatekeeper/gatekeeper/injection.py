"""Prompt-injection heuristics for text Claude reads from outside (web pages, email, downloads).

`injection_hits(text)` returns short labels for each heuristic that fired ([] = nothing found).
Pure, stdlib only, linear-time regexes; input is capped so huge pages stay fast.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata

MAX_SCAN_CHARS = 500_000
HIDDEN_MIN = 3        # zero-width / bidi characters outside emoji sequences
TAG_RUN_MIN = 8       # Unicode tag characters in a row (flag emoji use <= 7)
BLOB_MIN = 200        # base64 run length

_ZW = "​‌‍⁠⁡⁢⁣⁤﻿᠎­"
_BIDI = "‪‫‬‭‮⁦⁧⁨⁩"
_ZW_RE = re.compile(f"[{_ZW}{_BIDI}]")
_TAG_RE = re.compile("[\U000e0000-\U000e007f]{%d,}" % TAG_RUN_MIN)
_INVISIBLE_RE = re.compile(f"[{_ZW}{_BIDI}\U000e0000-\U000e007f]")

_AI = (r"(?:ai|a\.i\.|assistant|ai\s+assistant|ai\s+agent|agent|llm|language\s+model|claude|chatgpt|gpt|"
       r"copilot|chatbot|gemini|model)")
_ACT = (r"(?:run|execute|exec|ignore|disregard|edit|modify|write|delete|remove|fetch|download|open|visit|"
        r"browse|send|forward|reply|install|add|change|update|create|curl|wget|output|print|reveal|tell|"
        r"include|copy|paste|upload|email|call|invoke|navigate|follow|do\s+not|don't|stop)")

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore previous instructions", re.compile(
        r"\b(?:ignore|disregard|forget|override|bypass)\b\W+(?:\w+\W+){0,3}?"
        r"(?:previous|prior|above|earlier|preceding|all|any|your|the\s+system|system|existing|original)\W+"
        r"(?:\w+\W+){0,2}?(?:instructions?|prompts?|directions?|rules|guidelines|guardrails|messages?|"
        r"directives?|policies)\b")),
    ("addressed to an AI assistant", re.compile(
        rf"\b{_AI}\s*[:,]\s*(?:please\s+|now\s+|you\s+(?:must|should|need\s+to|will)\s+)?{_ACT}\b")),
    ("addressed to an AI assistant", re.compile(
        rf"\b(?:if|when)\s+you\s*(?:'re|are)\s+(?:an?\s+)?{_AI}s?\b"
        rf"|\b(?:note|message|instructions?|attention|reminder)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?{_AI}s?\b"
        rf"|\b(?:dear|attention|hey|hello|hi)\s+{_AI}\b"
        rf"|\bas\s+an?\s+{_AI}\s*,\s*you\s+(?:must|should|will|need)"
        r"|\byou\s+are\s+now\s+(?:in\s+)?(?:developer|dan|jailbreak|god|admin|unrestricted)\s*mode"
        r"|\b(?:new|updated|real|actual|hidden)\s+(?:system\s+)?instructions\s*:"
        r"|<\s*/?\s*(?:system|im_start|im_end)\s*>|\[\s*(?:system|inst)\s*\]")),
    ("asks to edit agent or shell config", re.compile(
        r"\b(?:edit|modify|change|update|overwrite|write|append|add|replace|create|delete|put)\b[^\n]{0,60}?"
        r"(?:~?[/\\]\.claude(?:[/\\]|\.json)|\.claude[/\\]|\bclaude\.md\b|\.mcp\.json|\bmcpservers\b|"
        r"authorized_keys|\.bashrc|\.zshrc|\.bash_profile|\$profile\b|core\.hookspath)")),
    ("asks to send secrets", re.compile(
        r"\b(?:send|upload|forward|exfiltrate|post|email|paste|share)\b[^\n]{0,60}?"
        r"\b(?:api[\s_-]?keys?|tokens?|passwords?|credentials|secrets?|private\s+keys?|ssh\s+keys?|"
        r"id_rsa|\.env\b|cookies)\b[^\n]{0,40}?\b(?:to|at)\b\s*(?:https?://|\S+@\S+\.\w)")),
]

_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{%d,}={0,2}" % BLOB_MIN)
_DATA_URI_TAIL = re.compile(r"data:[\w.+-]+/[\w.+-]+(?:;[\w=.-]+)*;base64,\s*$", re.IGNORECASE)


def _is_emoji_neighbour(ch: str) -> bool:
    return ord(ch) >= 0x2190 and unicodedata.category(ch) in ("So", "Sk", "Mn", "Cf")


def _hidden_count(text: str) -> int:
    n = 0
    for m in _ZW_RE.finditer(text):
        i = m.start()
        ch = text[i]
        if ch == "‍":  # zero-width joiner inside an emoji sequence is normal
            prev = text[i - 1] if i else ""
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if prev and nxt and _is_emoji_neighbour(prev) and _is_emoji_neighbour(nxt):
                continue
        if ch == "﻿" and i == 0:  # byte-order mark
            continue
        n += 1
    return n


def _blob_hits(text: str) -> tuple[bool, list[str]]:
    """(found a base64 blob, labels from scanning its decoded text)."""
    found = False
    decoded_hits: list[str] = []
    for m in _BLOB_RE.finditer(text):
        run = m.group(0)
        if _DATA_URI_TAIL.search(text[max(0, m.start() - 120):m.start()]):
            continue
        if not (re.search(r"[A-Z]", run) and re.search(r"[a-z]", run) and re.search(r"\d", run)):
            continue
        found = True
        if not decoded_hits:
            try:
                raw = base64.b64decode(run.replace("-", "+").replace("_", "/") + "==="[: (-len(run)) % 4],
                                       validate=False)
                inner = raw[:20_000].decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            decoded_hits = [f"{h} (in base64)" for h in _phrase_hits(_normalise(inner))]
    return found, decoded_hits


def _normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", _INVISIBLE_RE.sub("", text))
    return re.sub(r"\s+", " ", text).lower()


def _phrase_hits(norm: str) -> list[str]:
    return [label for label, pat in _PATTERNS if pat.search(norm)]


def injection_hits(text: str) -> list[str]:
    if not text:
        return []
    text = text[:MAX_SCAN_CHARS]
    hits: list[str] = []

    def add(h: str) -> None:
        if h not in hits:
            hits.append(h)

    if _hidden_count(text) >= HIDDEN_MIN or _TAG_RE.search(text):
        add("hidden or zero-width text")
    for h in _phrase_hits(_normalise(text)):
        add(h)
    found, decoded = _blob_hits(text)
    if found:
        add("long base64 blob")
    for h in decoded:
        add(h)
    return hits

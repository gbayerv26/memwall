"""Heuristic rule engine: fast, zero-dependency first pass.

Each rule has a regex specification, id, severity, and description. Delimiter
rules use forward-only matchers to avoid repeatedly scanning the same suffix.
A combo rule (MW000) escalates to CRITICAL when a record contains both a
standing order and an outbound destination — the classic shape of a
memory-poisoning exfiltration attack.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Iterable, Optional

from .models import Finding, MemoryRecord, RecordReport, Severity


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: Severity
    description: str
    pattern: "re.Pattern"
    matcher: Optional[Callable[[str], Optional["re.Match"]]] = None

    def search(self, text: str) -> Optional["re.Match"]:
        return self.matcher(text) if self.matcher else self.pattern.search(text)


def _rx(pattern: str) -> "re.Pattern":
    return re.compile(pattern, re.IGNORECASE | re.MULTILINE)


_SPAN = re.compile(r"[\s\S]*")
_MARKDOWN_DESTINATION = _rx(r"\(\s*https?://")
_IMAGE_TOKENS = _rx(r"<img|>|src=[\"']?https?://")


def _comment_match(text: str) -> Optional["re.Match"]:
    start = text.find("<!--")
    if start < 0:
        return None
    # Every later opener needs a closer at least as far into the same suffix.
    # Search that suffix once, including nested openers as comment content.
    end = text.find("-->", start + 4)
    return _SPAN.match(text, start, end + 3) if end >= 0 else None


def _beacon_match(text: str) -> Optional["re.Match"]:
    markdown = None
    position = 0
    while True:
        start = text.find("![", position)
        if start < 0:
            break
        close = text.find("]", start + 2)
        if close < 0:
            break
        destination = _MARKDOWN_DESTINATION.match(text, close + 1)
        if destination:
            markdown = (start, destination.end())
            break
        # All openers before this ] share the same failed destination. Do not
        # rescan it for each nested opener.
        position = close + 1

    html = None
    start = end = None
    for token in _IMAGE_TOKENS.finditer(text):
        value = token.group(0)
        if value == ">":
            if end is not None:
                html = (start, end)
                break
            start = None
        elif value.startswith("<"):
            if start is None:
                start = token.start()
        elif start is not None and token.start() > start + 4:
            # Preserve [^>]+ (at least one character before src) and its
            # greedy choice of the last matching src before the next >.
            end = token.end()
    else:
        if end is not None:
            html = (start, end)

    spans = [span for span in (markdown, html) if span is not None]
    if not spans:
        return None
    start, end = min(spans)
    return _SPAN.match(text, start, end)


RULES = [
    Rule("MW001", "override-instruction", Severity.HIGH,
         "Tries to override or replace the agent's standing instructions.",
         _rx(r"\b(?:ignore|disregard|forget|override)\b[\s\S]{0,30}\b(?:previous|prior|earlier|above|all|any)\b[\s\S]{0,30}\b(?:instructions?|rules?|context|prompts?|guidelines?)\b"
             r"|\b(?:new|updated) (?:system )?instructions?\b")),
    Rule("MW002", "imperative-directive", Severity.MEDIUM,
         "Memory phrased as a standing order instead of a fact or preference.",
         _rx(r"^\s*(?:always\b|never\b|from now on\b|important[:!]|note to self[:!]?"
             r"|remember(?: to\b|:)|make sure\b|be sure to\b|do not\b|don'?t\b"
             r"|you (?:must|should|need to)\b|whenever\b|before (?:replying|responding|answering)\b)")),
    Rule("MW003", "secrecy-pressure", Severity.HIGH,
         "Tells the agent to hide activity from the user.",
         _rx(r"\bdo(?:n'?t| not) (?:tell|mention|reveal|inform|notify|alert|show|log)\b"
             r"|\bwithout (?:telling|informing|alerting|notifying)\b"
             r"|\bkeep (?:this|it) (?:secret|hidden|private|between)\b"
             r"|\bhide this\b|\bsilently\b|\bnever (?:mention|reveal|tell|disclose)\b")),
    Rule("MW004", "self-referential-order", Severity.MEDIUM,
         "Addresses the agent directly with obligations.",
         _rx(r"\b(?:the (?:assistant|agent|ai|model)|claude|chatgpt|copilot|gemini)\b"
             r"[\s\S]{0,50}\b(?:should|must|shall|will now|is (?:required|instructed))\b")),
    Rule("MW005", "authority-claim", Severity.HIGH,
         "Claims system, admin, or developer authority inside remembered content.",
         _rx(r"\bsystem (?:message|prompt|note|override|directive)\b"
             r"|\badmin(?:istrator)? (?:says|note|override|approved|instruction)\b"
             r"|\bofficial (?:instruction|directive|notice)\b|\bdeveloper mode\b"
             r"|\bthis is an? (?:system|admin|official)\b"
             r"|\bon behalf of (?:anthropic|openai|google|microsoft)\b")),
    Rule("MW006", "tool-or-command-directive", Severity.MEDIUM,
         "Directs the agent to run tools, commands, or code.",
         _rx(r"\b(?:run|execute|invoke|launch)\b[\s\S]{0,30}\b(?:command|tool|script|shell|terminal|curl|wget|powershell|bash|cmd)\b"
             r"|\b(?:curl|wget)\s+-?\S*\s*https?://|\brm\s+-rf\b|\bdrop\s+table\b")),
    Rule("MW007", "payment-redirect", Severity.HIGH,
         "Redirects payments, refunds, or banking details.",
         _rx(r"\b(?:send|redirect|forward|transfer|route|wire)\b[\s\S]{0,40}\b(?:payments?|refunds?|money|funds|invoices?|deposits?|transfers?)\b"
             r"|\b(?:new|updated|changed) (?:bank|payment|billing|wallet) (?:details?|accounts?|address(?:es)?|info(?:rmation)?)\b"
             r"|\brouting number\b|\biban\b")),
    Rule("MW008", "outbound-destination", Severity.LOW,
         "Contains an outbound destination (URL, email address, or IP).",
         _rx(r"https?://[^\s\"'<>]+|\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[a-z]{2,}\b|\b\d{1,3}(?:\.\d{1,3}){3}\b")),
    Rule("MW009", "crypto-wallet", Severity.HIGH,
         "Contains a cryptocurrency wallet address.",
         _rx(r"\b(?:bc1[ac-hj-np-z02-9]{20,}|0x[a-f0-9]{40})\b")),
    Rule("MW010", "encoded-payload", Severity.MEDIUM,
         "Long base64/hex blob that could smuggle instructions.",
         _rx(r"\b(?:[A-Za-z0-9+/]{60,}={0,2}|[a-f0-9]{64,})\b")),
    Rule("MW011", "hidden-characters", Severity.HIGH,
         "Zero-width or bidi control characters that hide content from humans.",
         re.compile("[​‌‍⁠﻿‪-‮⁦-⁩]")),
    Rule("MW012", "pii-retention", Severity.INFO,
         "Personal data that may need an expiry or erasure policy.",
         _rx(r"\b\d{3}-\d{2}-\d{4}\b|\bpassport (?:no|number|#)\b"
             r"|\b(?:\+?\d{1,3}[\s.-])?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}\b")),
    Rule("MW013", "hidden-html-comment", Severity.LOW,
         "HTML comment invisible when the file renders as Markdown.",
         _rx(r"<!--[\s\S]*?-->"), matcher=_comment_match),
    Rule("MW014", "role-marker-smuggling", Severity.MEDIUM,
         "Chat-template or role markers smuggled into memory content.",
         _rx(r"<\|[a-z_]{2,}\|>|\[/?INST\]|\bbegin_of_text\b|^(?:assistant|system)\s*:")),
    Rule("MW015", "rendering-beacon", Severity.MEDIUM,
         "Markdown/HTML image pointing at a remote URL - exfiltrates when rendered.",
         _rx(r"!\[[^\]]*\]\(\s*https?://|<img[^>]+src=[\"']?https?://"),
         matcher=_beacon_match),
    Rule("MW016", "delayed-trigger", Severity.MEDIUM,
         "Conditional trigger phrasing - the signature of memory implants that fire later.",
         _rx(r"\bwhen(?:ever)? the (?:user|owner|human|customer) (?:asks|mentions|says|requests|talks about)\b"
             r"|\bthe next time\b|\bnext time the\b"
             r"|\bon (?:the )?next (?:session|run|startup|login)\b"
             r"|\bif (?:the user|anyone|someone) (?:asks|mentions|requests)\b")),
]

# In instruction files (CLAUDE.md, AGENTS.md, ...) imperatives, direct
# address, and conditional guidance are the normal register, so these rules
# would only produce noise.
SKIP_FOR_INSTRUCTION_FILES = {"MW002", "MW004", "MW016"}

INSTRUCTION_RULES = {"MW001", "MW002", "MW003", "MW004", "MW005", "MW006", "MW014", "MW016"}
VECTOR_RULES = {"MW007", "MW008", "MW009", "MW015"}


def evaluate(record: MemoryRecord) -> RecordReport:
    report = RecordReport(record=record)
    kind = record.metadata.get("kind")
    hits = set()
    for rule in RULES:
        if kind == "instructions" and rule.id in SKIP_FOR_INSTRUCTION_FILES:
            continue
        match = rule.search(record.content)
        if match:
            snippet = " ".join(match.group(0).split())[:80]
            report.findings.append(Finding(rule.id, rule.name, rule.severity, f"matched: {snippet}"))
            hits.add(rule.id)
    if hits & INSTRUCTION_RULES and hits & VECTOR_RULES:
        report.findings.append(Finding(
            "MW000", "instruction-plus-destination", Severity.CRITICAL,
            "standing order combined with an outbound destination - the classic exfiltration shape"))
    return report


def scan_records(records: Iterable[MemoryRecord]) -> list:
    return [evaluate(r) for r in records]

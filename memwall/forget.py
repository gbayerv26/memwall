"""GDPR / right-to-be-forgotten verification.

Given subject identifiers (an email, a name, an account id), find every memory
that still references them. Summarized long-term memory is where erasure
quietly fails - a name survives inside a paraphrase after the source row was
deleted. This proves whether a subject was actually forgotten.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import adapters


@dataclass
class ForgetHit:
    record: object
    matched: list = field(default_factory=list)


def find_subject(records, subjects) -> list:
    needles = [(s, s.lower()) for s in subjects if s and s.strip()]
    hits = []
    for record in records:
        low = record.content.lower()
        matched = [original for original, needle in needles if needle in low]
        if matched:
            hits.append(ForgetHit(record=record, matched=matched))
    return hits


def scan_path(path, subjects, fmt: str = "auto") -> list:
    return find_subject(adapters.load(path, fmt), subjects)

"""The detector interface and the context window.

A detector is a compiled pattern plus a ``validate`` step. The pattern finds
candidates cheaply; ``validate`` decides whether a candidate is the identifier
and how sure we are. Nearby words then move the confidence: ``aadhaar_no =``
to the left of a 12-digit value raises it, ``order_id =`` lowers it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from re import Match, Pattern

from dpdp_scan.model import Category, Confidence, Provision

#: Characters of text looked at before a match for context words.
CONTEXT_BEFORE = 48
#: And after. Field names usually precede a value, but JSON keys and YAML can
#: put the value first in log lines, so look a little way forward too.
CONTEXT_AFTER = 16

#: The two provisions every found identifier engages. Wording is a pointer, not
#: advice; the catalogue (DS-6) carries the reviewed sentence for each.
SAFEGUARDS: tuple[Provision, ...] = (
    Provision("S.8(5)", "reasonable security safeguards to prevent a personal data breach"),
    Provision("Rule 6(1)(a)", "security measures such as encryption, obfuscation or masking"),
)


class Step(IntEnum):
    LOW = 0
    MEDIUM = 1
    HIGH = 2

    def to_confidence(self) -> Confidence:
        return (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)[self]

    def up(self) -> Step:
        return Step(min(self + 1, Step.HIGH))

    def down(self) -> Step:
        return Step(max(self - 1, Step.LOW))


@dataclass(frozen=True, slots=True)
class Candidate:
    """A validated match, before context is applied."""

    compact: str  # separators removed, case normalised; what the allowlist sees
    step: Step


def compact_value(raw: str) -> str:
    return re.sub(r"[\s\-./:]", "", raw).upper()


@dataclass(frozen=True, slots=True)
class Detector:
    id: str
    category: Category
    pattern: Pattern[str]
    #: Words that, near the match, raise confidence one step.
    positive_context: tuple[str, ...]
    #: Words that lower it one step (order ids, timestamps, invoice numbers).
    negative_context: tuple[str, ...] = ()
    provisions: tuple[Provision, ...] = SAFEGUARDS
    #: Human label used in messages, e.g. "Aadhaar number".
    label: str = ""

    def validate(self, match: Match[str]) -> Candidate | None:  # pragma: no cover
        raise NotImplementedError

    def context_step(self, text: str, start: int, end: int, step: Step) -> Step:
        before = text[max(0, start - CONTEXT_BEFORE) : start].lower()
        after = text[end : end + CONTEXT_AFTER].lower()
        window = before + " " + after
        if any(word in window for word in self.positive_context):
            step = step.up()
        elif any(word in window for word in self.negative_context) or _CODE_PREFIX.search(before):
            step = step.down()
        return step


#: ``ORD-``, ``TXN_``, ``REF#`` glued to the value: the shape of a generated code,
#: not of a field holding someone's number.
_CODE_PREFIX = re.compile(r"[a-z]{2,}[-_#]$")


def has_word(window: str, words: tuple[str, ...]) -> bool:
    return any(w in window for w in words)

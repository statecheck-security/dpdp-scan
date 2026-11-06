"""Masking of matched values.

Ground rule: the scanner must never move a personal identifier from a repository
into a report, a log line or a CI console. Every value that leaves the scanner
passes through :func:`mask`, and :class:`dpdp_scan.model.Finding` refuses evidence
that does not look masked. There is no "unmasked" option.
"""

from __future__ import annotations

import re

MASK_CHAR = "*"
#: Visible characters at the end of a masked value. "Last 4 characters at most."
KEEP = 4
#: Longest run of mask characters shown. Capped so a mask does not reveal the exact
#: length of a long value, while still telling a 12-digit value from a 10-digit one.
MAX_MASK_RUN = 8
#: Values this short (or shorter) are masked completely: four visible characters
#: of a six-character value would be most of it.
FULLY_MASK_UP_TO = 6

_MASKED_RE = re.compile(rf"^\{MASK_CHAR}{{1,{MAX_MASK_RUN}}}[^\s{MASK_CHAR}]{{0,{KEEP}}}$")

#: Evidence for a finding that has no value: a declared field in a schema. It
#: passes :func:`is_masked` and says "nothing was read" rather than "hidden".
DECLARED = MASK_CHAR


def mask(value: str) -> str:
    """Return ``value`` with all but its last :data:`KEEP` characters replaced.

    - Whitespace and common separators are dropped first, so ``"1234 5678 9012"``
      and ``"1234-5678-9012"`` mask the same way.
    - Values of :data:`FULLY_MASK_UP_TO` characters or fewer show nothing.
    - The empty string masks to a single mask character so that an empty evidence
      field is still visibly "masked" rather than absent.

    >>> mask("234567890123")
    '********0123'
    >>> mask("ABCDE1234F")
    '******234F'
    >>> mask("short")
    '*****'
    """
    compact = re.sub(r"[\s\-./:]", "", value)
    if not compact:
        return MASK_CHAR
    if len(compact) <= FULLY_MASK_UP_TO:
        return MASK_CHAR * len(compact)
    hidden = len(compact) - KEEP
    return MASK_CHAR * min(hidden, MAX_MASK_RUN) + compact[-KEEP:]


def is_masked(text: str) -> bool:
    """True if ``text`` has the shape :func:`mask` produces.

    This is the check :class:`~dpdp_scan.model.Finding` applies to its evidence.
    It is deliberately strict: a run of mask characters, then at most
    :data:`KEEP` visible characters, nothing else.
    """
    return bool(_MASKED_RE.match(text))


def mask_in(text: str, value: str) -> str:
    """Replace every occurrence of ``value`` inside ``text`` with its mask.

    For messages that quote context around a match (a log line, a field
    declaration). The surrounding text is kept; the value is not.
    """
    if not value:
        return text
    return text.replace(value, mask(value))

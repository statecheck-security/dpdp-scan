"""Values that are personal-data-shaped but are known not to be anyone's.

Documented test values, sequences and repeated digits. A match against this
list is dropped before it becomes a finding, so a repository that uses the
published UIDAI test numbers in its fixtures is not told it holds Aadhaar
numbers.

Users add their own in ``.dpdp-scan.yml`` (DS-7) as hashes, not plaintext.
"""

from __future__ import annotations

import re

#: UIDAI publishes these UIDs for testing authentication clients.
#: Source: UIDAI Authentication API developer documentation (test data).
UIDAI_TEST_UIDS: frozenset[str] = frozenset(
    {
        "999999990019",
        "999999990026",
        "999999990042",
        "999999990057",
        "999999990068",
        "999999990071",
        "999999990083",
        "999999990092",
        "999941057058",
        "999971658847",
        "999933119405",
        "999955183433",
        "999990501894",
        "999920211341",
    }
)

#: PAN values that appear in examples and documentation everywhere.
DOCUMENTED_PANS: frozenset[str] = frozenset(
    {
        "ABCDE1234F",
        "AAAAA0000A",
        "AAAAA1111A",
        "AAAPL1234C",  # the Income Tax Department's own format illustration
        "ABCPD1234E",
        "AAAAA9999A",
        "XXXXX0000X",
    }
)

#: GSTINs used as format illustrations in tutorials that also pass the check
#: character. Illustrations that fail it (22AAAAA0000A1Z5 and friends) never
#: become findings anyway; those with a documented PAN inside are caught by the
#: embedded-PAN rule below.
DOCUMENTED_GSTINS: frozenset[str] = frozenset({"27AAPFU0939F1ZV"})

_REPEATED = re.compile(r"^(\d)\1+$")
_ASCENDING = "01234567890123456789"
_DESCENDING = "98765432109876543210"


def is_trivial_digits(digits: str) -> bool:
    """All one digit, or a straight ascending or descending run."""
    if _REPEATED.match(digits):
        return True
    return digits in _ASCENDING or digits in _DESCENDING


def is_allowlisted(detector_id: str, compact: str) -> bool:
    """True if ``compact`` (separators removed, upper-cased) is a known non-value."""
    if compact.isdigit() and is_trivial_digits(compact):
        return True
    if detector_id == "in_aadhaar":
        return compact in UIDAI_TEST_UIDS
    if detector_id == "in_pan":
        return compact in DOCUMENTED_PANS
    if detector_id == "in_gstin":
        return compact in DOCUMENTED_GSTINS or compact[2:12] in DOCUMENTED_PANS
    return False

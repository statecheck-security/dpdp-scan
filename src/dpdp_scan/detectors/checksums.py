"""Checksums for Indian identifiers.

Pure functions, no I/O. These are what separate an identifier from a look-alike:
a 12-digit order number fails Verhoeff nine times out of ten, a 15-character SKU
fails the GSTIN check character thirty-five times out of thirty-six.
"""

from __future__ import annotations

# Verhoeff (Aadhaar). Tables from J. Verhoeff, "Error Detecting Decimal Codes", 1969.
_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_check_digit(digits: str) -> str:
    """The Verhoeff check digit to append to ``digits``."""
    if not digits.isdigit():
        raise ValueError("digits only")
    c = 0
    for i, ch in enumerate(reversed(digits), start=1):
        c = _D[c][_P[i % 8][int(ch)]]
    return str(_INV[c])


def verhoeff_valid(number: str) -> bool:
    """True if ``number`` (digits, check digit last) passes Verhoeff."""
    if not number.isdigit() or len(number) < 2:
        return False
    c = 0
    for i, ch in enumerate(reversed(number)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


# GSTIN: mod-36 check character over the first 14 characters.
_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def gstin_check_character(first14: str) -> str:
    """The 15th character of a GSTIN, computed from the first fourteen."""
    if len(first14) != 14 or any(ch not in _ALPHABET for ch in first14):
        raise ValueError("fourteen characters from 0-9A-Z")
    total = 0
    for i, ch in enumerate(first14):
        value = _ALPHABET.index(ch)
        product = value * (1 if i % 2 == 0 else 2)
        total += product // 36 + product % 36
    return _ALPHABET[(36 - total % 36) % 36]


def gstin_checksum_valid(gstin: str) -> bool:
    """True if the 15-character ``gstin`` ends with the right check character."""
    if len(gstin) != 15 or any(ch not in _ALPHABET for ch in gstin):
        return False
    return gstin_check_character(gstin[:14]) == gstin[14]

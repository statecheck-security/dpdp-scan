import pytest

from dpdp_scan.detectors.checksums import (
    gstin_check_character,
    gstin_checksum_valid,
    verhoeff_check_digit,
    verhoeff_valid,
)


def test_verhoeff_published_example() -> None:
    # The worked example in the Verhoeff literature: 236 -> check digit 3.
    assert verhoeff_check_digit("236") == "3"
    assert verhoeff_valid("2363")
    assert not verhoeff_valid("2364")


@pytest.mark.parametrize(
    "uid", ["999999990019", "999999990026", "999999990042", "999941057058", "999971658847"]
)
def test_verhoeff_accepts_uidai_test_uids(uid: str) -> None:
    assert verhoeff_valid(uid)


def test_verhoeff_detects_single_digit_and_transposition_errors() -> None:
    good = "999999990019"
    assert not verhoeff_valid("999999990018")  # last digit changed
    assert not verhoeff_valid("999999900019")  # a middle digit changed
    assert not verhoeff_valid(good[:-2] + good[-1] + good[-2])  # adjacent transposition


def test_verhoeff_rejects_non_digits_and_short_input() -> None:
    assert not verhoeff_valid("12a4")
    assert not verhoeff_valid("1")
    with pytest.raises(ValueError):
        verhoeff_check_digit("12x")


def test_gstin_published_example() -> None:
    assert gstin_check_character("27AAPFU0939F1Z") == "V"
    assert gstin_checksum_valid("27AAPFU0939F1ZV")


@pytest.mark.parametrize("bad", ["27AAPFU0939F1ZW", "22AAAAA0000A1Z5", "29ABCDE1234F1Z5"])
def test_gstin_rejects_wrong_check_character(bad: str) -> None:
    assert not gstin_checksum_valid(bad)


def test_gstin_rejects_bad_length_or_alphabet() -> None:
    assert not gstin_checksum_valid("27AAPFU0939F1Z")
    assert not gstin_checksum_valid("27AAPFU0939F1Z*")
    with pytest.raises(ValueError):
        gstin_check_character("27AAPFU0939F1")

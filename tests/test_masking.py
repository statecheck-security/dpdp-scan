import pytest

from dpdp_scan.masking import KEEP, MAX_MASK_RUN, is_masked, mask, mask_in

# Synthetic values only. 999999990019 is a UIDAI-published test UID.
AADHAAR = "999999990019"
PAN = "ABCDE1234F"
GSTIN = "22ABCDE1234F1Z5"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (AADHAAR, "********0019"),
        ("9999 9999 0019", "********0019"),
        ("9999-9999-0019", "********0019"),
        (PAN, "******234F"),
        (GSTIN, "********F1Z5"),
        ("short", "*****"),
        ("sixsix", "******"),
        ("seven77", "***en77"),
        ("", "*"),
        ("   ", "*"),
    ],
)
def test_mask_shapes(value: str, expected: str) -> None:
    assert mask(value) == expected


def test_mask_shows_at_most_keep_characters() -> None:
    for n in range(1, 40):
        masked = mask("x" * (n - 1) + "Z")
        visible = masked.strip("*")
        assert len(visible) <= KEEP
        assert masked.count("*") <= max(MAX_MASK_RUN, n)


def test_mask_caps_the_hidden_run() -> None:
    long_value = "9" * 60
    assert mask(long_value) == "*" * MAX_MASK_RUN + "9999"


def test_mask_output_never_contains_the_input() -> None:
    for value in (AADHAAR, PAN, GSTIN, "user@example.in", "+91 98765 43210"):
        assert value not in mask(value)
        assert value.replace(" ", "") not in mask(value)


@pytest.mark.parametrize("value", [AADHAAR, PAN, GSTIN, "short", "", "a" * 100])
def test_mask_output_is_recognised_as_masked(value: str) -> None:
    assert is_masked(mask(value))


@pytest.mark.parametrize(
    "text",
    [AADHAAR, PAN, "****12345", "**** 0019", "0019", "", "*********0019", "***ABCDEF", "* 1"],
)
def test_is_masked_rejects_unmasked_or_malformed(text: str) -> None:
    assert not is_masked(text)


def test_mask_in_replaces_every_occurrence_and_keeps_context() -> None:
    line = f'logger.info("user {AADHAAR} logged in"); audit({AADHAAR})'
    out = mask_in(line, AADHAAR)
    assert AADHAAR not in out
    assert out.count(mask(AADHAAR)) == 2
    assert out.startswith('logger.info("user ')


def test_mask_in_with_empty_value_is_identity() -> None:
    assert mask_in("nothing here", "") == "nothing here"

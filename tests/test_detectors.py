"""Detector tests: positives, context, allowlist, overlap, and the hard-negative corpus.

Every identifier here is synthetic. Aadhaar-shaped values are generated with the
Verhoeff routine so they validate without being anyone's number.
"""

from __future__ import annotations

import json
import random
import uuid

import pytest

from dpdp_scan.detectors import BY_ID, scan_text
from dpdp_scan.detectors.base import Step
from dpdp_scan.detectors.checksums import gstin_check_character, verhoeff_check_digit
from dpdp_scan.model import Confidence


def aadhaar(prefix11: str = "23456789012") -> str:
    assert len(prefix11) == 11 and prefix11[0] in "23456789"
    return prefix11 + verhoeff_check_digit(prefix11)


def gstin(first14: str = "29AAACB2230M1Z") -> str:
    return first14 + gstin_check_character(first14)


AADHAAR = aadhaar()
PAN = "BNZPM2501F"
GSTIN = gstin()


def ids(findings) -> list[str]:
    return [f.detector_id for f in findings]


def one(text: str, detector_id: str):
    found = [f for f in scan_text(text, "t.py") if f.detector_id == detector_id]
    assert len(found) == 1, f"expected one {detector_id} in {text!r}, got {ids(found)}"
    return found[0]


# ---- positives -------------------------------------------------------------


def test_aadhaar_valid_checksum_is_high() -> None:
    f = one(f"uid = '{AADHAAR}'", "in_aadhaar")
    assert f.confidence == Confidence.HIGH
    assert f.evidence == "********" + AADHAAR[-4:]
    assert f.line == 1 and f.column == 8


def test_aadhaar_with_spaces_and_hyphens() -> None:
    spaced = f"{AADHAAR[:4]} {AADHAAR[4:8]} {AADHAAR[8:]}"
    hyphen = f"{AADHAAR[:4]}-{AADHAAR[4:8]}-{AADHAAR[8:]}"
    assert one(spaced, "in_aadhaar").evidence == one(hyphen, "in_aadhaar").evidence


def test_aadhaar_bad_checksum_is_not_a_finding() -> None:
    bad = AADHAAR[:-1] + str((int(AADHAAR[-1]) + 1) % 10)
    assert "in_aadhaar" not in ids(scan_text(f"aadhaar = {bad}", "t.py"))


def test_aadhaar_first_digit_0_or_1_is_not_a_finding() -> None:
    v = "1" + AADHAAR[1:11]
    v += verhoeff_check_digit(v)
    assert "in_aadhaar" not in ids(scan_text(v, "t.py"))


def test_pan_is_medium_and_high_with_context() -> None:
    assert one(f"x = '{PAN}'", "in_pan").confidence == Confidence.MEDIUM
    assert one(f"pan_number = '{PAN}'", "in_pan").confidence == Confidence.HIGH


def test_pan_wrong_holder_type_is_not_a_finding() -> None:
    assert "in_pan" not in ids(scan_text("code = 'BNZZM2501F'", "t.py"))


def test_gstin_valid_is_high_and_bad_check_char_is_dropped() -> None:
    assert one(f"gstin: {GSTIN}", "in_gstin").confidence == Confidence.HIGH
    bad = GSTIN[:-1] + ("A" if GSTIN[-1] != "A" else "B")
    assert "in_gstin" not in ids(scan_text(bad, "t.py"))


def test_gstin_bad_state_code_is_dropped() -> None:
    assert "in_gstin" not in ids(scan_text(gstin("45AAACB2230M1Z"), "t.py"))


def test_ifsc() -> None:
    assert one("ifsc: HDFC0001234", "in_ifsc").confidence == Confidence.HIGH
    assert one("HDFC0001234", "in_ifsc").confidence == Confidence.MEDIUM
    assert "in_ifsc" not in ids(scan_text("HDFC1001234", "t.py"))


def test_upi_known_handle_wins_over_email() -> None:
    found = scan_text("pay to ravi.k@okaxis today", "t.py")
    assert ids(found) == ["in_upi"]
    assert found[0].confidence == Confidence.HIGH


def test_upi_unknown_handle_is_not_upi() -> None:
    assert "in_upi" not in ids(scan_text("ravi@gmail", "t.py"))


@pytest.mark.parametrize(
    ("text", "conf"),
    [
        ("+91 98123 45670", Confidence.MEDIUM),
        ("+91-9812345670", Confidence.MEDIUM),
        ("9812345670", Confidence.LOW),
        ("09812345670", Confidence.LOW),
        ("mobile: 9812345670", Confidence.MEDIUM),
        ("phone = +919812345670", Confidence.HIGH),
    ],
)
def test_mobile_confidence_ladder(text: str, conf: Confidence) -> None:
    assert one(text, "in_mobile").confidence == conf


def test_mobile_starting_below_6_is_dropped() -> None:
    assert "in_mobile" not in ids(scan_text("5876543210", "t.py"))


def test_shape_only_detectors_need_context_to_rise() -> None:
    assert one("ABC1234567", "in_voter_epic").confidence == Confidence.LOW
    assert one("voter id ABC1234567", "in_voter_epic").confidence == Confidence.MEDIUM
    assert one("passport: K8765432", "in_passport").confidence == Confidence.MEDIUM
    assert one("dl_no = MH12 20110012345", "in_driving_licence").confidence == Confidence.MEDIUM


def test_email_personal_vs_role_vs_example() -> None:
    assert one("ravi.kumar@acme.in", "email").confidence == Confidence.MEDIUM
    assert one("email: ravi.kumar@acme.in", "email").confidence == Confidence.HIGH
    assert one("noreply@acme.in", "email").confidence == Confidence.LOW
    assert one("email: privacy@acme.in", "email").confidence == Confidence.LOW  # capped
    assert "email" not in ids(scan_text("user@example.com", "t.py"))
    assert "email" not in ids(scan_text("x@host.test", "t.py"))
    assert "email" not in ids(scan_text("you@company.com or jane.doe@acme.in", "t.py"))
    assert one("email: legal@acme.in", "email").confidence == Confidence.LOW  # role, capped


# ---- context and allowlist -------------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "uses: statecheck-security/dpdp-scan@v0.1.0",
        'depends on "react@18.3.1" and lodash@4',
        "git+ssh://git@github.com:org/repo.git",
        "https://deploy@internal.example.org/x",
        "image: ghcr.io/org/app@sha256",
    ],
)
def test_version_refs_and_git_urls_are_not_emails(text: str) -> None:
    found = [f for f in scan_text(text, "t.yml") if f.detector_id == "email"]
    # A service account ("git@") may still register, but never above LOW.
    assert all(f.confidence == Confidence.LOW for f in found), text


def test_negative_context_lowers_a_step() -> None:
    assert one(f"order_id = {AADHAAR}", "in_aadhaar").confidence == Confidence.MEDIUM


def test_positive_context_wins_over_negative() -> None:
    assert one(f"order aadhaar = {AADHAAR}", "in_aadhaar").confidence == Confidence.HIGH


def test_allowlist_drops_uidai_test_uids_and_documented_pans() -> None:
    assert scan_text("aadhaar = 999999990019", "t.py") == []
    assert scan_text("pan = ABCDE1234F", "t.py") == []
    assert scan_text("gstin = 27AAPFU0939F1ZV", "t.py") == []


def test_allowlist_drops_trivial_digit_runs() -> None:
    assert scan_text("9999999999 and 6666666666", "t.py") == []


def test_min_step_filters() -> None:
    assert scan_text("9812345670", "t.py", min_step=Step.MEDIUM) == []


# ---- positions and leak proof ----------------------------------------------


def test_line_and_column_are_one_based_across_lines() -> None:
    text = f"a = 1\nb = 2\n  pan = '{PAN}'\n"
    f = one(text, "in_pan")
    assert (f.line, f.column) == (3, 10)


def test_no_raw_value_reaches_any_finding_field() -> None:
    text = f"""
    aadhaar: {AADHAAR}
    pan: {PAN}
    gstin: {GSTIN}
    upi: ravi.k@okaxis
    phone: +91 98123 45670
    email: ravi.kumar@acme.in
    """
    dump = json.dumps([f.to_dict() for f in scan_text(text, "fixture.yml")])
    for raw in (AADHAAR, PAN, GSTIN, "ravi.k@okaxis", "9812345670", "ravi.kumar@acme.in"):
        assert raw not in dump
    assert len(json.loads(dump)) == 6


# ---- hard-negative corpus --------------------------------------------------


def _corpus() -> dict[str, list[str]]:
    rng = random.Random(20261106)
    return {
        "uuid": [str(uuid.UUID(int=rng.getrandbits(128))) for _ in range(200)],
        "sha": [f"{rng.getrandbits(160):040x}" for _ in range(200)],
        "epoch_s": [str(rng.randint(1_600_000_000, 1_800_000_000)) for _ in range(200)],
        "epoch_ms": [str(rng.randint(1_600_000_000_000, 1_800_000_000_000)) for _ in range(200)],
        "iso_datetime": [
            f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}T{rng.randint(0, 23):02d}:"
            f"{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d}Z"
            for _ in range(200)
        ],
        "order_id": [f"ORD-{rng.randint(10**11, 10**12 - 1)}" for _ in range(200)],
        "order_id_ctx": [f"order_id = {rng.randint(2 * 10**11, 10**12 - 1)}" for _ in range(200)],
        "random_12_digits": [str(rng.randint(2 * 10**11, 10**12 - 1)) for _ in range(1000)],
        "random_10_digits": [str(rng.randint(10**9, 10**10 - 1)) for _ in range(1000)],
        "port_and_version": [
            f"port {rng.randint(1024, 65535)} v{rng.randint(1, 9)}.{rng.randint(0, 20)}"
            for _ in range(200)
        ],
        "pincode": [f"pincode: {rng.randint(110001, 855117)}" for _ in range(200)],
        "card_like_16": [
            " ".join(str(rng.randint(1000, 9999)) for _ in range(4)) for _ in range(200)
        ],
        "hex_tokens": [f"{rng.getrandbits(128):032x}" for _ in range(200)],
        "sku": [f"SKU{rng.randint(10**7, 10**8 - 1)}X" for _ in range(200)],
    }


# The numbers each class may produce, as findings per 100 samples, by detector.
# These are the DS-3 precision record: tighten them when the detectors improve,
# never loosen them silently.
BUDGET_PER_100: dict[str, dict[str, float]] = {
    "uuid": {},
    "sha": {},
    "epoch_s": {},
    "epoch_ms": {},
    "iso_datetime": {},
    # Verhoeff passes ~1 in 10 random 12-digit values: the irreducible floor. The
    # 200-sample classes get 15 for sampling noise; the 1000-sample class gets 12.
    "order_id": {"in_aadhaar": 15.0},  # ORD- prefix lowers every one to MEDIUM
    "order_id_ctx": {"in_aadhaar": 15.0},  # order context lowers every one to MEDIUM
    "random_12_digits": {"in_aadhaar": 12.0},  # all HIGH; nothing to lower them
    "random_10_digits": {"in_mobile": 50.0},  # 4 of 9 first digits are 6–9; shape only, all LOW
    "port_and_version": {},
    "pincode": {},
    "card_like_16": {},
    "hex_tokens": {},
    "sku": {},
}


def test_hard_negative_corpus_stays_within_budget() -> None:
    corpus = _corpus()
    report: dict[str, dict[str, float]] = {}
    for cls, samples in corpus.items():
        text = "\n".join(samples)
        counts: dict[str, int] = {}
        for f in scan_text(text, "corpus.txt"):
            counts[f.detector_id] = counts.get(f.detector_id, 0) + 1
        per100 = {k: round(v * 100 / len(samples), 1) for k, v in counts.items()}
        report[cls] = per100
        budget = BUDGET_PER_100[cls]
        for det, rate in per100.items():
            assert rate <= budget.get(det, 0.0), f"{cls}: {det} at {rate}/100 exceeds {budget}"
    # Every finding from random digits with order context is at most MEDIUM.
    for cls in ("order_id", "order_id_ctx"):
        ctx = scan_text("\n".join(corpus[cls]), "c.txt")
        assert all(f.confidence != Confidence.HIGH for f in ctx), cls
    # Every finding from bare ten-digit numbers is LOW.
    tens = scan_text("\n".join(corpus["random_10_digits"]), "c.txt")
    assert all(f.confidence == Confidence.LOW for f in tens)


def test_every_detector_is_registered_once() -> None:
    assert len(BY_ID) == 10

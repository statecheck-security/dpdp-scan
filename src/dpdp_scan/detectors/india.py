"""Detectors for Indian identifiers.

Confidence rules, so the numbers in the README mean the same thing everywhere:

- ``HIGH``: a checksum passed, or an unambiguous shape plus a matching field
  name nearby.
- ``MEDIUM``: the shape is specific (PAN, GSTIN structure, IFSC) but there is
  no checksum to confirm it, or a weak shape has a matching field name.
- ``LOW``: shape only, and the shape is common (ten digits, two letters and
  seven digits).

A candidate whose checksum *fails* is not a finding at all. Dropping it is the
whole point of validating.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Match

from dpdp_scan.detectors.base import Candidate, Detector, Step, compact_value
from dpdp_scan.detectors.checksums import gstin_checksum_valid, verhoeff_valid
from dpdp_scan.model import Category

# Boundaries: a value must not sit inside a longer alphanumeric run, which is
# how UUIDs, hashes and epoch timestamps are excluded. A hex hash can hold a
# ten-digit run, so the all-digit detectors use the alphanumeric boundary too.
_NOT_ALNUM_BEFORE = r"(?<![A-Za-z0-9])"
_NOT_ALNUM_AFTER = r"(?![A-Za-z0-9])"


@dataclass(frozen=True, slots=True)
class AadhaarDetector(Detector):
    def validate(self, match: Match[str]) -> Candidate | None:
        compact = compact_value(match.group(0))
        if len(compact) != 12 or compact[0] not in "23456789":
            return None
        if not verhoeff_valid(compact):
            return None
        return Candidate(compact, Step.HIGH)


@dataclass(frozen=True, slots=True)
class PanDetector(Detector):
    def validate(self, match: Match[str]) -> Candidate | None:
        compact = compact_value(match.group(0))
        # 4th character is the holder type; the Income Tax Department uses these.
        if compact[3] not in "ABCFGHJLPT":
            return None
        return Candidate(compact, Step.MEDIUM)


@dataclass(frozen=True, slots=True)
class GstinDetector(Detector):
    def validate(self, match: Match[str]) -> Candidate | None:
        compact = compact_value(match.group(0))
        state = int(compact[:2])
        # 01–38 are states and UTs; 97 is "other territory", 99 the Centre.
        if not (1 <= state <= 38 or state in (97, 99)):
            return None
        if compact[5] not in "ABCFGHJLPT":  # embedded PAN holder type
            return None
        if not gstin_checksum_valid(compact):
            return None
        return Candidate(compact, Step.HIGH)


@dataclass(frozen=True, slots=True)
class IfscDetector(Detector):
    def validate(self, match: Match[str]) -> Candidate | None:
        compact = compact_value(match.group(0))
        return Candidate(compact, Step.MEDIUM)


#: Handles of UPI payment service providers and banks. A VPA with an unknown
#: handle is reported as an email at most, never as a UPI id.
UPI_HANDLES: frozenset[str] = frozenset(
    {
        "upi",
        "ybl",
        "ibl",
        "axl",
        "okaxis",
        "okhdfcbank",
        "okicici",
        "oksbi",
        "paytm",
        "ptyes",
        "ptaxis",
        "pthdfc",
        "ptsbi",
        "apl",
        "yapl",
        "abfspay",
        "axisbank",
        "sbi",
        "hdfcbank",
        "icici",
        "kotak",
        "indus",
        "idfcbank",
        "federal",
        "fbl",
        "ikwik",
        "freecharge",
        "airtel",
        "jio",
        "waaxis",
        "wahdfcbank",
        "waicici",
        "wasbi",
        "naviaxis",
        "slice",
        "superyes",
        "timecosmos",
        "cnrb",
        "boi",
        "pnb",
        "unionbank",
        "barodampay",
        "dbs",
        "rbl",
        "yesbank",
        "citi",
        "hsbc",
        "sc",
        "axisb",
        "idbi",
        "uco",
        "cbin",
        "iob",
        "mahb",
        "psb",
        "allbank",
        "andb",
        "jkb",
        "kbl",
        "kvb",
        "lvb",
        "sib",
        "tjsb",
        "utbi",
        "vijb",
        "ezeepay",
        "amazonpay",
    }
)


@dataclass(frozen=True, slots=True)
class UpiDetector(Detector):
    def validate(self, match: Match[str]) -> Candidate | None:
        local, handle = match.group(1), match.group(2).lower()
        if handle not in UPI_HANDLES:
            return None
        # Numeric local parts are usually a mobile number; still a UPI id.
        return Candidate(f"{local.lower()}@{handle}", Step.HIGH)


@dataclass(frozen=True, slots=True)
class MobileDetector(Detector):
    def validate(self, match: Match[str]) -> Candidate | None:
        digits = re.sub(r"\D", "", match.group(0))
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        elif digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]
        if len(digits) != 10 or digits[0] not in "6789":
            return None
        # An explicit +91 is a strong signal; a bare ten digits is weak.
        step = Step.MEDIUM if match.group(0).lstrip().startswith("+") else Step.LOW
        return Candidate(digits, step)


@dataclass(frozen=True, slots=True)
class ShapeOnlyDetector(Detector):
    """Voter EPIC, passport, driving licence: a specific shape, no checksum."""

    base_step: Step = Step.LOW

    def validate(self, match: Match[str]) -> Candidate | None:
        return Candidate(compact_value(match.group(0)), self.base_step)


_ROLE_LOCAL_PARTS = (
    "noreply",
    "no-reply",
    "donotreply",
    "support",
    "info",
    "admin",
    "sales",
    "hello",
    "contact",
    "help",
    "team",
    "security",
    "privacy",
    "dpo",
    "grievance",
    "billing",
    "careers",
    "jobs",
    "press",
    "webmaster",
    "postmaster",
    "abuse",
    "notifications",
    "alerts",
    "bot",
    "legal",
    "compliance",
    "incident",
    "incidents",
    "soc",
    "noc",
    "onboarding",
    "marketing",
    "hr",
    "finance",
    "accounts",
    "office",
    "enquiries",
    "inquiries",
    "feedback",
    "newsletter",
    "ops",
    "devops",
    "dev",
    "engineering",
    "product",
    "partners",
    "partnerships",
    "media",
    "investors",
    "nodal",
    "mailer-daemon",
    "system",
    "root",
    "git",
    "deploy",
    "ci",
    "build",
    "jenkins",
    "github-actions",
)
#: Locals that are placeholders in documentation and templates, never a person.
_PLACEHOLDER_LOCAL_PARTS = (
    "you",
    "your",
    "yourname",
    "your.name",
    "your-name",
    "name",
    "user",
    "username",
    "someone",
    "somebody",
    "me",
    "email",
    "firstname.lastname",
    "first.last",
    "john.doe",
    "jane.doe",
    "foo",
    "bar",
    "test",
    "a",
    "x",
)
_EXAMPLE_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "example.in",
    "test.com",
    "email.com",
    "domain.com",
    "company.com",
    "yourdomain.com",
    "yourcompany.com",
)


@dataclass(frozen=True, slots=True)
class EmailDetector(Detector):
    def validate(self, match: Match[str]) -> Candidate | None:
        local, domain = match.group(1), match.group(2).lower()
        # "ssh://git@host" and "https://user@host": a URL userinfo, not a mailbox.
        if match.string[max(0, match.start() - 3) : match.start()] == "://":
            return None
        # "owner/repo@v0.1.0" and "react@18.3.1" have the shape but not a real
        # top-level label: a TLD is letters only, two or more of them.
        if not domain.rsplit(".", 1)[-1].isalpha() or len(domain.rsplit(".", 1)[-1]) < 2:
            return None
        if domain in _EXAMPLE_DOMAINS or domain.endswith((".example", ".invalid", ".test")):
            return None
        if domain.split(".")[0] in ("localhost",):
            return None
        if local.lower() in _PLACEHOLDER_LOCAL_PARTS:
            return None
        if local.lower() in _ROLE_LOCAL_PARTS:
            return Candidate(f"{local.lower()}@{domain}", Step.LOW, cap=Step.LOW)
        return Candidate(f"{local.lower()}@{domain}", Step.MEDIUM)


# Context words. Lower-case; matched as substrings of the window.
_AADHAAR_WORDS = ("aadhaar", "aadhar", "adhaar", "adhar", "uid", "uidai", "vid")
_PAN_WORDS = ("pan", "permanent account", "pan_no", "pancard", "pan card")
_GSTIN_WORDS = ("gst", "gstin", "gstno", "tax id", "taxid")
_IFSC_WORDS = ("ifsc", "branch", "bank code", "neft", "rtgs", "imps")
_MOBILE_WORDS = (
    "mobile",
    "phone",
    "mob_no",
    "mobno",
    "contact",
    "whatsapp",
    "msisdn",
    "tel",
    "cell",
    "otp",
    "sms",
)
_VOTER_WORDS = ("voter", "epic", "election", "electoral")
_PASSPORT_WORDS = ("passport",)
_DL_WORDS = ("driving", "licence", "license", "dl_no", "dlno", "rto")
_EMAIL_WORDS = ("email", "e-mail", "mail", "user", "customer", "login")
_ORDER_WORDS = (
    "order",
    "invoice",
    "txn",
    "transaction",
    "ref",
    "sku",
    "tracking",
    "awb",
    "timestamp",
    "epoch",
    "ticket",
    "build",
    "version",
    "port",
    "pincode",
    "zip",
)

DETECTORS: tuple[Detector, ...] = (
    AadhaarDetector(
        id="in_aadhaar",
        category=Category.IDENTITY,
        label="Aadhaar number",
        pattern=re.compile(
            # Not preceded or followed by another digit group: the first twelve
            # digits of a 16-digit card-style number are not an Aadhaar.
            _NOT_ALNUM_BEFORE
            + r"(?<![0-9][ -])[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?![ -][0-9])"
            + _NOT_ALNUM_AFTER
        ),
        positive_context=_AADHAAR_WORDS,
        negative_context=_ORDER_WORDS,
    ),
    PanDetector(
        id="in_pan",
        category=Category.IDENTITY,
        label="PAN",
        pattern=re.compile(_NOT_ALNUM_BEFORE + r"[A-Z]{5}[0-9]{4}[A-Z]" + _NOT_ALNUM_AFTER),
        positive_context=_PAN_WORDS,
        negative_context=_ORDER_WORDS,
    ),
    GstinDetector(
        id="in_gstin",
        category=Category.FINANCIAL,
        label="GSTIN",
        pattern=re.compile(
            _NOT_ALNUM_BEFORE + r"\d{2}[A-Z]{5}\d{4}[A-Z][1-9A-Z]Z[0-9A-Z]" + _NOT_ALNUM_AFTER
        ),
        positive_context=_GSTIN_WORDS,
        negative_context=(),
    ),
    IfscDetector(
        id="in_ifsc",
        category=Category.FINANCIAL,
        label="IFSC code",
        pattern=re.compile(_NOT_ALNUM_BEFORE + r"[A-Z]{4}0[A-Z0-9]{6}" + _NOT_ALNUM_AFTER),
        positive_context=_IFSC_WORDS,
        negative_context=_ORDER_WORDS,
    ),
    UpiDetector(
        id="in_upi",
        category=Category.FINANCIAL,
        label="UPI id",
        pattern=re.compile(
            _NOT_ALNUM_BEFORE + r"([A-Za-z0-9._-]{2,64})@([A-Za-z]{2,16})" + _NOT_ALNUM_AFTER
        ),
        positive_context=("upi", "vpa"),
        negative_context=(),
    ),
    MobileDetector(
        id="in_mobile",
        category=Category.CONTACT,
        label="Indian mobile number",
        pattern=re.compile(
            _NOT_ALNUM_BEFORE + r"(?:\+91[ -]?|0)?[6-9]\d{4}[ -]?\d{5}" + _NOT_ALNUM_AFTER
        ),
        positive_context=_MOBILE_WORDS,
        negative_context=_ORDER_WORDS,
    ),
    ShapeOnlyDetector(
        id="in_voter_epic",
        category=Category.IDENTITY,
        label="Voter EPIC number",
        pattern=re.compile(_NOT_ALNUM_BEFORE + r"[A-Z]{3}\d{7}" + _NOT_ALNUM_AFTER),
        positive_context=_VOTER_WORDS,
        negative_context=_ORDER_WORDS,
    ),
    ShapeOnlyDetector(
        id="in_passport",
        category=Category.IDENTITY,
        label="Passport number",
        pattern=re.compile(_NOT_ALNUM_BEFORE + r"[A-PR-WY][1-9]\d{6}" + _NOT_ALNUM_AFTER),
        positive_context=_PASSPORT_WORDS,
        negative_context=_ORDER_WORDS,
    ),
    ShapeOnlyDetector(
        id="in_driving_licence",
        category=Category.IDENTITY,
        label="Driving licence number",
        pattern=re.compile(
            _NOT_ALNUM_BEFORE
            + r"[A-Z]{2}[ -]?\d{2}[ -]?(?:19|20)\d{2}[ -]?\d{7}"
            + _NOT_ALNUM_AFTER
        ),
        positive_context=_DL_WORDS,
        negative_context=_ORDER_WORDS,
    ),
    EmailDetector(
        id="email",
        category=Category.CONTACT,
        label="Email address",
        pattern=re.compile(
            _NOT_ALNUM_BEFORE
            + r"([A-Za-z0-9._%+-]{1,64})@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)"
            + _NOT_ALNUM_AFTER
        ),
        positive_context=_EMAIL_WORDS,
        negative_context=(),
    ),
)

BY_ID: dict[str, Detector] = {d.id: d for d in DETECTORS}

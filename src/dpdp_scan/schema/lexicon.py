"""Field-name lexicon: what a column, property or model field is called tells
you what it holds.

``classify_name("aadhar_no")`` → identity, HIGH. The lexicon knows the English
words, the Indian abbreviations and the common misspellings (``aadhar``,
``adhaar``, ``mobno``, ``pincode``, ``fathername``). Specific phrases are tried
before generic ones so ``ip_address`` is an online identifier and
``contract_address`` is nothing, while plain ``address`` is a postal address.

Confidence here means "how sure we are the field holds personal data", not
whether a value was seen. Categories are inventory labels, not legal tiers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from dpdp_scan.detectors.base import Step
from dpdp_scan.model import Category, Provision

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SPLIT = re.compile(r"[^a-z0-9]+")


def tokens(name: str) -> tuple[str, ...]:
    """Split a field name into lower-case words.

    ``"aadhaarNo"`` → ``("aadhaar", "no")``; ``"DATE_OF_BIRTH"`` → ``("date", "of", "birth")``.
    """
    spaced = _CAMEL.sub(" ", name)
    parts = [p for p in _SPLIT.split(spaced.lower()) if p]
    # Separate trailing digits: "phone2" -> "phone"; keep "f2f" as is.
    out: list[str] = []
    for p in parts:
        m = re.fullmatch(r"([a-z]+)(\d+)", p)
        out.append(m.group(1) if m else p)
    return tuple(out)


@dataclass(frozen=True, slots=True)
class Classification:
    category: Category
    step: Step
    label: str


#: ``None`` means "explicitly not personal data": stops the generic rules.
Rule = tuple[tuple[str, ...], Classification | None]

_I, _C, _F, _H, _B, _L, _A, _O = (
    Category.IDENTITY,
    Category.CONTACT,
    Category.FINANCIAL,
    Category.HEALTH,
    Category.BIOMETRIC,
    Category.LOCATION,
    Category.AGE_DOB,
    Category.OTHER,
)
HIGH, MED, LOW = Step.HIGH, Step.MEDIUM, Step.LOW


def _c(cat: Category, step: Step, label: str) -> Classification:
    return Classification(cat, step, label)


#: Phrase rules, matched as a contiguous token sub-sequence. Longer and more
#: specific phrases first; the first match wins.
PHRASES: tuple[Rule, ...] = (
    # Explicitly not personal data (or not a person's).
    (("contract", "address"), None),
    (("contract", "addr"), None),
    (("event", "name"), None),
    (("class", "name"), None),
    (("field", "name"), None),
    (("column", "name"), None),
    (("model", "name"), None),
    (("service", "name"), None),
    (("app", "name"), None),
    (("role", "name"), None),
    (("tx", "hash"), None),
    (("token", "hash"), None),
    (("password", "hash"), None),
    (("mac", "address"), _c(_O, MED, "device identifier")),
    (("ip", "address"), _c(_O, MED, "IP address")),
    (("ip", "addr"), _c(_O, MED, "IP address")),
    (("device", "fingerprint"), _c(_O, MED, "device identifier")),
    (("wallet", "address"), _c(_F, LOW, "crypto wallet address")),
    (("email", "address"), _c(_C, HIGH, "email address")),
    (("date", "of", "birth"), _c(_A, HIGH, "date of birth")),
    (("birth", "date"), _c(_A, HIGH, "date of birth")),
    (("year", "of", "birth"), _c(_A, HIGH, "year of birth")),
    (("father", "name"), _c(_I, HIGH, "parent's name")),
    (("mother", "name"), _c(_I, HIGH, "parent's name")),
    (("spouse", "name"), _c(_I, HIGH, "spouse's name")),
    (("guardian", "name"), _c(_I, HIGH, "guardian's name")),
    (("full", "name"), _c(_I, MED, "name")),
    (("first", "name"), _c(_I, MED, "name")),
    (("last", "name"), _c(_I, MED, "name")),
    (("middle", "name"), _c(_I, MED, "name")),
    (("display", "name"), _c(_I, LOW, "name")),
    (("user", "name"), _c(_I, LOW, "username")),
    (("company", "name"), None),
    (("product", "name"), None),
    (("game", "name"), None),
    (("table", "name"), None),
    (("file", "name"), None),
    (("host", "name"), None),
    (("pan", "no"), _c(_I, HIGH, "PAN")),
    (("pan", "number"), _c(_I, HIGH, "PAN")),
    (("pan", "card"), _c(_I, HIGH, "PAN")),
    (("voter", "id"), _c(_I, HIGH, "voter EPIC")),
    (("driving", "licence"), _c(_I, HIGH, "driving licence")),
    (("driving", "license"), _c(_I, HIGH, "driving licence")),
    (("dl", "no"), _c(_I, HIGH, "driving licence")),
    (("dl", "number"), _c(_I, HIGH, "driving licence")),
    (("ration", "card"), _c(_I, HIGH, "ration card")),
    (("national", "id"), _c(_I, HIGH, "national identifier")),
    (("mobile", "no"), _c(_C, HIGH, "mobile number")),
    (("phone", "no"), _c(_C, HIGH, "phone number")),
    (("contact", "no"), _c(_C, HIGH, "phone number")),
    (("contact", "number"), _c(_C, HIGH, "phone number")),
    (("postal", "code"), _c(_C, MED, "postal code")),
    (("pin", "code"), _c(_C, MED, "postal code")),
    (("zip", "code"), _c(_C, MED, "postal code")),
    (("bank", "account"), _c(_F, HIGH, "bank account")),
    (("account", "no"), _c(_F, MED, "account number")),
    (("account", "number"), _c(_F, MED, "account number")),
    (("acct", "no"), _c(_F, MED, "account number")),
    (("card", "number"), _c(_F, HIGH, "card number")),
    (("card", "no"), _c(_F, HIGH, "card number")),
    (("gst", "no"), _c(_F, HIGH, "GSTIN")),
    (("gst", "number"), _c(_F, HIGH, "GSTIN")),
    (("blood", "group"), _c(_H, HIGH, "blood group")),
    (("face", "id"), _c(_B, HIGH, "facial biometric")),
    (("face", "embedding"), _c(_B, HIGH, "facial biometric")),
    (("marital", "status"), _c(_O, MED, "marital status")),
    (("user", "agent"), _c(_O, LOW, "user agent")),
    (("device", "id"), _c(_O, MED, "device identifier")),
    (("session", "id"), None),
    (("is", "minor"), _c(_A, MED, "age flag")),
    (("parent", "consent"), _c(_A, MED, "parental consent")),
    (("parental", "consent"), _c(_A, MED, "parental consent")),
)

#: Single-token rules. Checked after phrases.
WORDS: dict[str, Classification | None] = {
    "aadhaar": _c(_I, HIGH, "Aadhaar"),
    "aadhar": _c(_I, HIGH, "Aadhaar"),
    "adhaar": _c(_I, HIGH, "Aadhaar"),
    "adhar": _c(_I, HIGH, "Aadhaar"),
    "uidai": _c(_I, HIGH, "Aadhaar"),
    "vid": _c(_I, MED, "Aadhaar VID"),
    "pan": _c(_I, MED, "PAN"),
    "pancard": _c(_I, HIGH, "PAN"),
    "passport": _c(_I, HIGH, "passport"),
    "epic": _c(_I, HIGH, "voter EPIC"),
    "abha": _c(_H, HIGH, "ABHA health id"),
    "uan": _c(_F, HIGH, "UAN (provident fund)"),
    "esic": _c(_F, HIGH, "ESIC number"),
    "tan": _c(_F, LOW, "TAN"),
    "name": _c(_I, LOW, "name"),
    "fathername": _c(_I, HIGH, "parent's name"),
    "mothername": _c(_I, HIGH, "parent's name"),
    "username": _c(_I, LOW, "username"),
    "photo": _c(_I, MED, "photograph"),
    "avatar": _c(_I, LOW, "profile image"),
    "selfie": _c(_I, HIGH, "photograph"),
    "signature": _c(_I, MED, "signature"),
    "email": _c(_C, HIGH, "email address"),
    "emailid": _c(_C, HIGH, "email address"),
    "mail": _c(_C, MED, "email address"),
    "phone": _c(_C, HIGH, "phone number"),
    "phoneno": _c(_C, HIGH, "phone number"),
    "mobile": _c(_C, HIGH, "mobile number"),
    "mobileno": _c(_C, HIGH, "mobile number"),
    "mobno": _c(_C, HIGH, "mobile number"),
    "msisdn": _c(_C, HIGH, "mobile number"),
    "whatsapp": _c(_C, HIGH, "mobile number"),
    "telephone": _c(_C, HIGH, "phone number"),
    "tel": _c(_C, MED, "phone number"),
    "address": _c(_C, MED, "postal address"),
    "addr": _c(_C, LOW, "postal address"),
    "pincode": _c(_C, MED, "postal code"),
    "zipcode": _c(_C, MED, "postal code"),
    "zip": _c(_C, LOW, "postal code"),
    "city": _c(_L, LOW, "city"),
    "district": _c(_L, LOW, "district"),
    "ifsc": _c(_F, HIGH, "IFSC"),
    "upi": _c(_F, HIGH, "UPI id"),
    "vpa": _c(_F, HIGH, "UPI id"),
    "gstin": _c(_F, HIGH, "GSTIN"),
    "gst": _c(_F, LOW, "GST reference"),
    "iban": _c(_F, HIGH, "IBAN"),
    "cvv": _c(_F, HIGH, "card security code"),
    "salary": _c(_F, MED, "salary"),
    "income": _c(_F, MED, "income"),
    "health": _c(_H, MED, "health data"),
    "medical": _c(_H, MED, "health data"),
    "diagnosis": _c(_H, HIGH, "diagnosis"),
    "prescription": _c(_H, HIGH, "prescription"),
    "disability": _c(_H, HIGH, "disability"),
    "allergy": _c(_H, HIGH, "allergy"),
    "allergies": _c(_H, HIGH, "allergy"),
    "biometric": _c(_B, HIGH, "biometric"),
    "fingerprint": _c(_B, HIGH, "fingerprint"),
    "iris": _c(_B, HIGH, "iris scan"),
    "retina": _c(_B, HIGH, "retina scan"),
    "voiceprint": _c(_B, HIGH, "voiceprint"),
    "latitude": _c(_L, MED, "coordinates"),
    "longitude": _c(_L, MED, "coordinates"),
    "lat": _c(_L, LOW, "coordinates"),
    "lng": _c(_L, LOW, "coordinates"),
    "lon": _c(_L, LOW, "coordinates"),
    "geo": _c(_L, LOW, "location"),
    "gps": _c(_L, MED, "location"),
    "location": _c(_L, LOW, "location"),
    "coordinates": _c(_L, MED, "coordinates"),
    "dob": _c(_A, HIGH, "date of birth"),
    "birthday": _c(_A, HIGH, "date of birth"),
    "birthdate": _c(_A, HIGH, "date of birth"),
    "age": _c(_A, MED, "age"),
    "minor": _c(_A, MED, "age flag"),
    "guardian": _c(_A, MED, "guardian"),
    "gender": _c(_O, MED, "gender"),
    "sex": _c(_O, MED, "gender"),
    "religion": _c(_O, HIGH, "religion"),
    "caste": _c(_O, HIGH, "caste"),
    "nationality": _c(_O, MED, "nationality"),
    "ethnicity": _c(_O, HIGH, "ethnicity"),
    "imei": _c(_O, HIGH, "device identifier"),
    "ip": _c(_O, LOW, "IP address"),
}

#: Substrings of the fused lower-case name, for misspellings glued to other
#: words where tokenising fails ("aadhaarno", "custaadhar", "mobno").
FUSED: tuple[tuple[str, Classification], ...] = (
    ("aadhaar", _c(_I, HIGH, "Aadhaar")),
    ("aadhar", _c(_I, HIGH, "Aadhaar")),
    ("adhaar", _c(_I, HIGH, "Aadhaar")),
    ("mobno", _c(_C, HIGH, "mobile number")),
    ("mobileno", _c(_C, HIGH, "mobile number")),
    ("phoneno", _c(_C, HIGH, "phone number")),
    ("emailid", _c(_C, HIGH, "email address")),
    ("pincode", _c(_C, MED, "postal code")),
    ("ifsc", _c(_F, HIGH, "IFSC")),
    ("gstin", _c(_F, HIGH, "GSTIN")),
    ("passport", _c(_I, HIGH, "passport")),
    ("biometric", _c(_B, HIGH, "biometric")),
    ("fingerprint", _c(_B, HIGH, "fingerprint")),
    ("fathername", _c(_I, HIGH, "parent's name")),
    ("dateofbirth", _c(_A, HIGH, "date of birth")),
    ("birthdate", _c(_A, HIGH, "date of birth")),
)

_SUFFIX_NOISE = frozenset({"no", "num", "number", "id", "code", "str", "txt", "val", "value"})


#: Containers (tables, models, schemas) that are about people. A bare ``name``
#: column means a person's name in ``users`` and a label in ``games``.
PERSON_CONTAINERS: frozenset[str] = frozenset(
    {
        "user",
        "users",
        "customer",
        "customers",
        "employee",
        "employees",
        "member",
        "members",
        "person",
        "persons",
        "people",
        "patient",
        "patients",
        "student",
        "students",
        "account",
        "accounts",
        "profile",
        "profiles",
        "principal",
        "principals",
        "contact",
        "contacts",
        "applicant",
        "applicants",
        "candidate",
        "candidates",
        "subscriber",
        "subscribers",
        "lead",
        "leads",
        "client",
        "clients",
        "borrower",
        "borrowers",
        "driver",
        "drivers",
        "rider",
        "riders",
        "parent",
        "parents",
        "guardian",
        "guardians",
        "author",
        "authors",
        "owner",
        "owners",
        "staff",
        "vendor",
        "vendors",
        "merchant",
        "merchants",
        "tenant",
        "tenants",
        "kyc",
    }
)

#: Words that are personal data only inside a person container.
_NEEDS_PERSON_CONTAINER = frozenset({"name"})


def _is_person_container(container: str) -> bool:
    return any(t in PERSON_CONTAINERS for t in tokens(container.split(".")[-1]))


def classify_name(name: str, container: str = "") -> Classification | None:
    """Return what personal data a field called ``name`` holds, or None.

    ``container`` is the table, model or schema the field sits in; it decides
    ambiguous words such as ``name``.
    """
    toks = tokens(name)
    if not toks:
        return None
    for phrase, cls in PHRASES:
        n = len(phrase)
        if any(toks[i : i + n] == phrase for i in range(len(toks) - n + 1)):
            return cls
    for t in toks:
        if t in WORDS:
            if t in _NEEDS_PERSON_CONTAINER and not _is_person_container(container):
                return None
            return WORDS[t]
    fused = "".join(toks)
    for needle, cls in FUSED:
        if needle in fused:
            return cls
    return None


def provisions_for(category: Category) -> tuple[Provision, ...]:
    base = (
        Provision("S.8(5)", "reasonable security safeguards to prevent a personal data breach"),
        Provision("Rule 6(1)(a)", "security measures such as encryption, obfuscation or masking"),
    )
    if category is Category.AGE_DOB:
        return (
            Provision("S.9", "verifiable parental consent before processing a child's data"),
            *base,
        )
    return base

"""The catalogue: every finding id, its reader-facing text and its provisions.

The engine emits ids and evidence; every sentence a reader sees comes from
here or from the rule pack's own metadata. Keeping the wording in one place
is what lets it be reviewed once (and legal-checked once) rather than
scattered across detectors.

Three families of id:

- ``in_*`` and ``email``: value detectors (``dpdp_scan.detectors``)
- ``schema_sql``, ``schema_prisma``, ``schema_openapi``: declared fields
- ``rule:<id>``: Semgrep rules, whose text is read from ``rules/dpdpa.yml``
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import yaml

from dpdp_scan.detectors.india import DETECTORS
from dpdp_scan.model import Category, Provision
from dpdp_scan.semgrep_runner import RULES_DIR

CATALOGUE_VERSION = "2026-11-06"

SAFEGUARDS = (
    Provision("S.8(5)", "reasonable security safeguards to prevent a personal data breach"),
    Provision("Rule 6(1)(a)", "security measures such as encryption, obfuscation or masking"),
)


@dataclass(frozen=True, slots=True)
class RuleInfo:
    id: str
    name: str  # short, title-case: "Aadhaar number in source"
    description: str  # one or two sentences on what was found and why it matters
    remediation: str  # one sentence on what to do
    category: Category
    provisions: tuple[Provision, ...]


_VALUE_REMEDIATION = (
    "Remove the value from the repository; use synthetic test data, and keep real "
    "identifiers in a secret store or an encrypted datastore."
)
_VALUE_DESCRIPTION = {
    "in_aadhaar": "A 12-digit value with a valid Verhoeff checksum, so almost certainly an "
    "Aadhaar number, appears in the repository.",
    "in_pan": "A value shaped like a Permanent Account Number appears in the repository.",
    "in_gstin": "A GSTIN with a valid check character appears in the repository. A sole "
    "proprietor's GSTIN embeds their PAN and identifies them.",
    "in_ifsc": "An IFSC bank branch code appears in the repository, usually alongside an "
    "account number.",
    "in_upi": "A UPI payment address on a known payment-service handle appears in the repository.",
    "in_mobile": "A value shaped like an Indian mobile number appears in the repository.",
    "in_voter_epic": "A value shaped like a voter EPIC number appears in the repository.",
    "in_passport": "A value shaped like an Indian passport number appears in the repository.",
    "in_driving_licence": "A value shaped like a driving licence number appears in the repository.",
    "email": "An email address appears in the repository.",
}

_SCHEMA_DESCRIPTION = (
    "A field declared in a {what} is named like it holds personal data. Declared fields "
    "are the start of a data inventory: know what is collected before deciding whether "
    "it is needed, how long it is kept and how it is protected."
)
_SCHEMA_REMEDIATION = (
    "Confirm the field is needed for a stated purpose (S.4, S.5), record it in the data "
    "map, and apply field-level protection and a retention rule (S.8(7))."
)
_SCHEMA_WHAT = {
    "schema_sql": "SQL table definition",
    "schema_prisma": "Prisma model",
    "schema_openapi": "OpenAPI or JSON Schema document",
}
_SCHEMA_PROVISIONS = (
    Provision("S.4", "processing only for a lawful purpose"),
    Provision("S.5", "the notice must say what data is collected and why"),
    Provision("S.8(7)", "erase personal data once the purpose is served"),
    *SAFEGUARDS,
)


def _value_rules() -> dict[str, RuleInfo]:
    out: dict[str, RuleInfo] = {}
    for det in DETECTORS:
        out[det.id] = RuleInfo(
            id=det.id,
            name=f"{det.label} in source",
            description=_VALUE_DESCRIPTION.get(det.id, f"A {det.label} appears in the repository."),
            remediation=_VALUE_REMEDIATION,
            category=det.category,
            provisions=det.provisions,
        )
    return out


def _schema_rules() -> dict[str, RuleInfo]:
    return {
        rid: RuleInfo(
            id=rid,
            name=f"Personal data field declared in a {what}",
            description=_SCHEMA_DESCRIPTION.format(what=what),
            remediation=_SCHEMA_REMEDIATION,
            category=Category.OTHER,  # the finding's own category is per field
            provisions=_SCHEMA_PROVISIONS,
        )
        for rid, what in _SCHEMA_WHAT.items()
    }


def _semgrep_rules() -> dict[str, RuleInfo]:
    out: dict[str, RuleInfo] = {}
    for yml in sorted(RULES_DIR.glob("*.yml")):
        data = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
        for rule in data.get("rules", []):
            rid = f"rule:{rule['id']}"
            meta = rule.get("metadata", {})
            message = " ".join(str(rule.get("message", "")).split())
            # The last sentence of each rule message is its remediation.
            parts = [p.strip() for p in message.split(". ") if p.strip()]
            remediation = parts[-1] if len(parts) > 1 else ""
            description = ". ".join(parts[:-1]) + "." if len(parts) > 1 else message
            out[rid] = RuleInfo(
                id=rid,
                name=str(meta.get("label", rule["id"])).capitalize(),
                description=description,
                remediation=remediation.rstrip(".") + "." if remediation else "",
                category=Category(meta.get("category", "other")),
                provisions=tuple(Provision(str(ref)) for ref in meta.get("dpdpa", [])),
            )
    return out


@lru_cache(maxsize=1)
def catalogue() -> dict[str, RuleInfo]:
    return {**_value_rules(), **_schema_rules(), **_semgrep_rules()}


def rule_info(detector_id: str) -> RuleInfo:
    cat = catalogue()
    if detector_id in cat:
        return cat[detector_id]
    return RuleInfo(
        id=detector_id,
        name=detector_id,
        description="Finding from an unknown detector.",
        remediation="",
        category=Category.OTHER,
        provisions=(),
    )


CATEGORY_LABELS: dict[Category, str] = {
    Category.IDENTITY: "Identity documents and names",
    Category.CONTACT: "Contact details",
    Category.FINANCIAL: "Financial identifiers",
    Category.HEALTH: "Health data",
    Category.BIOMETRIC: "Biometric data",
    Category.LOCATION: "Location data",
    Category.AGE_DOB: "Age and date of birth (children: S.9)",
    Category.OTHER: "Other personal data and online identifiers",
}

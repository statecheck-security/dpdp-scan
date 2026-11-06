"""Schema classifier: declared fields → inventory findings.

A declared field has no value to mask, so its finding carries the
:data:`~dpdp_scan.masking.DECLARED` evidence sentinel and names the field in
``locator`` (``users.aadhaar_no``, ``User.walletAddress``,
``components.schemas.Customer.dob``).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import PurePosixPath

from dpdp_scan.detectors.base import Step
from dpdp_scan.masking import DECLARED
from dpdp_scan.model import Finding
from dpdp_scan.schema.lexicon import classify_name, provisions_for
from dpdp_scan.schema.parsers import Field, parse_prisma, parse_schema_document, parse_sql

__all__ = ["classify_file", "schema_kind"]

_PARSERS: dict[str, Callable[[str], list[Field]]] = {
    "sql": parse_sql,
    "prisma": parse_prisma,
    "openapi": parse_schema_document,
}


def schema_kind(path: str) -> str | None:
    """Which parser handles ``path``, by name, or None."""
    p = PurePosixPath(path)
    suffix = p.suffix.lower()
    if suffix == ".sql":
        return "sql"
    if suffix == ".prisma":
        return "prisma"
    if suffix in (".json", ".yaml", ".yml"):
        name = p.name.lower()
        if name in ("package.json", "package-lock.json", "tsconfig.json", "composer.json"):
            return None
        return "openapi"  # the parser itself checks for schema markers
    return None


def classify_file(text: str, path: str, *, min_step: Step = Step.LOW) -> list[Finding]:
    kind = schema_kind(path)
    if kind is None:
        return []
    findings: list[Finding] = []
    for field in _PARSERS[kind](text):
        cls = classify_name(field.name, field.container)
        if cls is None or cls.step < min_step:
            continue
        findings.append(
            Finding(
                detector_id=f"schema_{kind}",
                category=cls.category,
                path=path,
                line=field.line,
                column=0,
                evidence=DECLARED,
                confidence=cls.step.to_confidence(),
                provisions=provisions_for(cls.category),
                message=f"Declared field holds {cls.label} ({cls.step.name.lower()} confidence)",
                locator=field.locator,
            )
        )
    return findings

"""Findings and the inventory they roll up into.

A :class:`Finding` is one place in one file where a detector or rule matched. Its
``evidence`` is always masked: the constructor rejects anything that does not have
the shape :func:`dpdp_scan.masking.mask` produces, so no code path can build a
finding that carries a raw identifier.

Categories are *inventory labels*, not legal tiers. The DPDP Act has no
"sensitive personal data" class, so the scanner groups data by what it is
(identity, contact, financial ...) and lets the provision pointer say which
obligation is engaged.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Any

from dpdp_scan.masking import is_masked

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


class Category(StrEnum):
    """What kind of personal data a finding is about. Inventory labels only."""

    IDENTITY = "identity"  # Aadhaar, PAN, passport, voter EPIC, driving licence
    CONTACT = "contact"  # email, phone, postal address
    FINANCIAL = "financial"  # bank account, IFSC, UPI VPA, card, GSTIN (sole proprietors)
    HEALTH = "health"
    BIOMETRIC = "biometric"
    LOCATION = "location"
    AGE_DOB = "age_dob"  # date of birth, age: a Section 9 (children) signal
    OTHER = "other"


class Confidence(StrEnum):
    """How sure the detector is that this is personal data, not a look-alike."""

    HIGH = "high"  # checksum passed, or an unambiguous field name
    MEDIUM = "medium"  # shape matched and context agrees
    LOW = "low"  # shape only


@dataclass(frozen=True, slots=True)
class Provision:
    """A pointer at the Act or the Rules. ``ref`` is the citation, e.g. ``"S.8(5)"``."""

    ref: str
    #: One line on why this obligation is engaged. Reviewed wording lives in the
    #: catalogue (DS-6); detectors supply the ref and a short default.
    note: str = ""


@dataclass(frozen=True, slots=True)
class Finding:
    """One match. Immutable, and its evidence is masked by construction."""

    detector_id: str
    category: Category
    path: str  # repo-relative, POSIX separators, as the walker yields it
    line: int  # 1-based; 0 when the finding is about the whole file
    column: int  # 1-based; 0 when unknown
    evidence: str  # masked; see dpdp_scan.masking
    confidence: Confidence
    provisions: tuple[Provision, ...] = ()
    #: Free text the reporter may show. Must not contain the raw value either;
    #: build it with masking.mask_in when quoting context.
    message: str = ""
    #: Where a declared field lives: ``table.column``, ``Model.field`` or a
    #: schema path. A name, never a value, so it is not masked. Empty for
    #: value findings.
    locator: str = ""

    def __post_init__(self) -> None:
        if not is_masked(self.evidence):
            raise ValueError(
                f"Finding evidence must be masked (got {len(self.evidence)} chars for "
                f"{self.detector_id} at {self.path}:{self.line})"
            )
        if self.line < 0 or self.column < 0:
            raise ValueError("line and column must be 0 or positive")
        if (
            "\\" in self.path
            or PurePosixPath(self.path).is_absolute()
            or _DRIVE_RE.match(self.path)
        ):
            raise ValueError("path must be repo-relative with POSIX separators")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = str(self.category)
        d["confidence"] = str(self.confidence)
        d["provisions"] = [asdict(p) for p in self.provisions]
        return d


@dataclass(slots=True)
class Inventory:
    """Counts of findings, by category, detector and file. Seeds a data map later."""

    findings: list[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding] | tuple[Finding, ...]) -> None:
        self.findings.extend(findings)

    @property
    def by_category(self) -> dict[str, int]:
        return dict(sorted(Counter(str(f.category) for f in self.findings).items()))

    @property
    def by_detector(self) -> dict[str, int]:
        return dict(sorted(Counter(f.detector_id for f in self.findings).items()))

    @property
    def by_path(self) -> dict[str, int]:
        return dict(sorted(Counter(f.path for f in self.findings).items()))

    def sorted(self) -> list[Finding]:
        """Deterministic order: path, line, column, detector."""
        return sorted(
            self.findings, key=lambda f: (f.path, f.line, f.column, f.detector_id, f.evidence)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": len(self.findings),
            "by_category": self.by_category,
            "by_detector": self.by_detector,
            "by_path": self.by_path,
            "findings": [f.to_dict() for f in self.sorted()],
        }

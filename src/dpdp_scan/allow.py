"""User allowlist: values accepted by hash, and the organisation's own domains.

Kept free of other dpdp-scan imports so both the detectors and the config
loader can use it without a cycle.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def value_hash(compact: str) -> str:
    """sha256 of the compact (separator-free, upper-cased) value."""
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class AllowList:
    #: Email and UPI findings whose domain or handle is one of these are dropped.
    domains: tuple[str, ...] = ()
    #: sha256 hex digests of compact values that are known not to be anyone's.
    value_hashes: frozenset[str] = frozenset()

    def allows_value(self, compact: str) -> bool:
        return bool(self.value_hashes) and value_hash(compact) in self.value_hashes

    def allows_domain(self, compact: str) -> bool:
        if "@" not in compact or not self.domains:
            return False
        domain = compact.rsplit("@", 1)[1].lower()
        return any(domain == d or domain.endswith("." + d) for d in self.domains)

"""``.dpdp-scan.yml``: what to skip, what to switch off, what to accept.

.. code-block:: yaml

    version: 1
    ignore:
      paths:                     # repo-relative prefixes or globs
        - fixtures/
        - "docs/**/*.md"
    detectors:
      disable:                   # ids, or the families "schema" and "rules"
        - in_mobile
        - rule:dob-without-age-gate-js
    allow:
      domains:                   # your own mailboxes are not personal data findings
        - statechecksecurity.com
      values_sha256:             # sha256 of the value as dpdp-scan sees it;
        - 9f86d081...            # get it with `dpdp-scan --hash-value VALUE`
    fail_on: medium              # default for --fail-on (none, low, medium, high)
    baseline: .dpdp-scan-baseline.json

Values are allowlisted by hash so the config never holds the value itself.
Unknown keys are errors: a typo must not silently switch a check off.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from dpdp_scan.detectors.base import Step

CONFIG_FILENAME = ".dpdp-scan.yml"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_STEPS = {"none": None, "low": Step.LOW, "medium": Step.MEDIUM, "high": Step.HIGH}


class ConfigError(ValueError):
    pass


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


@dataclass(frozen=True, slots=True)
class Config:
    ignore_paths: tuple[str, ...] = ()
    disabled: frozenset[str] = frozenset()
    allow: AllowList = field(default_factory=AllowList)
    #: None means "never fail"; the CLI flag overrides this.
    fail_on: Step | None = None
    baseline: str = ""
    source: str = ""  # where it was read from, for messages

    def detector_enabled(self, detector_id: str) -> bool:
        if detector_id in self.disabled:
            return False
        if detector_id.startswith("schema_") and "schema" in self.disabled:
            return False
        return not (detector_id.startswith("rule:") and "rules" in self.disabled)


def value_hash(compact: str) -> str:
    """sha256 of the compact (separator-free, upper-cased) value."""
    return hashlib.sha256(compact.encode("utf-8")).hexdigest()


def _expect(cond: bool, msg: str) -> None:
    if not cond:
        raise ConfigError(msg)


def _str_list(value: Any, key: str) -> tuple[str, ...]:
    _expect(
        isinstance(value, list) and all(isinstance(v, str) for v in value),
        f"{key} must be a list of strings",
    )
    return tuple(v.strip() for v in value if v.strip())


def parse_config(data: Any, source: str = "") -> Config:
    if data is None:
        return Config(source=source)
    _expect(isinstance(data, dict), "config must be a mapping")
    unknown = set(data) - {"version", "ignore", "detectors", "allow", "fail_on", "baseline"}
    _expect(not unknown, f"unknown config keys: {', '.join(sorted(unknown))}")
    _expect(data.get("version", 1) == 1, "only config version 1 is supported")

    ignore = data.get("ignore") or {}
    _expect(isinstance(ignore, dict), "ignore must be a mapping")
    _expect(set(ignore) <= {"paths"}, "ignore accepts only: paths")
    ignore_paths = _str_list(ignore.get("paths", []), "ignore.paths")
    for p in ignore_paths:
        _expect(
            not p.startswith("/") and ".." not in p.split("/"),
            f"ignore path must be repo-relative: {p}",
        )

    detectors = data.get("detectors") or {}
    _expect(isinstance(detectors, dict), "detectors must be a mapping")
    _expect(set(detectors) <= {"disable"}, "detectors accepts only: disable")
    disabled = frozenset(_str_list(detectors.get("disable", []), "detectors.disable"))

    allow = data.get("allow") or {}
    _expect(isinstance(allow, dict), "allow must be a mapping")
    _expect(
        set(allow) <= {"domains", "values_sha256"}, "allow accepts only: domains, values_sha256"
    )
    domains = tuple(
        d.lower().lstrip("@") for d in _str_list(allow.get("domains", []), "allow.domains")
    )
    hashes = _str_list(allow.get("values_sha256", []), "allow.values_sha256")
    for h in hashes:
        _expect(
            bool(_HEX64.match(h.lower())),
            f"allow.values_sha256 entries must be 64 hex characters: {h[:12]}…",
        )

    fail_on_raw = data.get("fail_on", "none")
    _expect(
        isinstance(fail_on_raw, str) and fail_on_raw in _STEPS,
        "fail_on must be none, low, medium or high",
    )

    baseline = data.get("baseline", "")
    _expect(isinstance(baseline, str), "baseline must be a path string")

    return Config(
        ignore_paths=ignore_paths,
        disabled=disabled,
        allow=AllowList(domains=domains, value_hashes=frozenset(h.lower() for h in hashes)),
        fail_on=_STEPS[fail_on_raw],
        baseline=baseline,
        source=source,
    )


def load_config(root: Path, explicit: str | None = None) -> Config:
    """Read ``explicit`` if given, else ``<root>/.dpdp-scan.yml`` if present."""
    path = Path(explicit) if explicit else root / CONFIG_FILENAME
    if explicit is None and not path.is_file():
        return Config()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML: {exc}") from exc
    try:
        return parse_config(data, str(path))
    except ConfigError as exc:
        raise ConfigError(f"{path}: {exc}") from exc

import json

import pytest

from dpdp_scan.masking import mask
from dpdp_scan.model import Category, Confidence, Finding, Inventory, Provision

RAW = "999999990019"  # UIDAI-published test UID, never a real one


def make(path: str = "src/app.py", line: int = 10, column: int = 5, raw: str = RAW) -> Finding:
    return Finding(
        detector_id="in_aadhaar",
        category=Category.IDENTITY,
        path=path,
        line=line,
        column=column,
        evidence=mask(raw),
        confidence=Confidence.HIGH,
        provisions=(Provision("S.8(5)", "security safeguards"),),
        message="Aadhaar-shaped value with a valid checksum",
    )


def test_finding_rejects_unmasked_evidence() -> None:
    with pytest.raises(ValueError, match="must be masked"):
        Finding(
            detector_id="in_aadhaar",
            category=Category.IDENTITY,
            path="a.py",
            line=1,
            column=1,
            evidence=RAW,
            confidence=Confidence.HIGH,
        )


def test_finding_rejects_partially_masked_evidence() -> None:
    with pytest.raises(ValueError, match="must be masked"):
        Finding("d", Category.OTHER, "a.py", 1, 1, "****90019", Confidence.LOW)


@pytest.mark.parametrize("path", ["C:/abs/file.py", "/abs/file.py", "src\\win\\file.py"])
def test_finding_rejects_absolute_or_backslash_paths(path: str) -> None:
    with pytest.raises(ValueError, match="repo-relative"):
        make(path=path)


def test_finding_rejects_negative_positions() -> None:
    with pytest.raises(ValueError, match="positive"):
        make(line=-1)


def test_finding_is_immutable() -> None:
    f = make()
    with pytest.raises(AttributeError):
        f.evidence = "changed"  # type: ignore[misc]


def test_finding_to_dict_is_json_serialisable_and_masked() -> None:
    d = make().to_dict()
    text = json.dumps(d)
    assert RAW not in text
    assert d["category"] == "identity"
    assert d["confidence"] == "high"
    assert d["provisions"] == [{"ref": "S.8(5)", "note": "security safeguards"}]


def test_inventory_counts_and_sorts_deterministically() -> None:
    inv = Inventory()
    inv.add(make(path="z.py", line=3))
    inv.add(make(path="a.py", line=9))
    inv.add(make(path="a.py", line=2, column=1))
    inv.add(
        Finding("in_pan", Category.IDENTITY, "a.py", 2, 1, mask("ABCDE1234F"), Confidence.MEDIUM)
    )
    inv.extend([make(path="m.py", line=1)])

    assert inv.by_category == {"identity": 5}
    assert inv.by_detector == {"in_aadhaar": 4, "in_pan": 1}
    assert inv.by_path == {"a.py": 3, "m.py": 1, "z.py": 1}
    order = [(f.path, f.line, f.detector_id) for f in inv.sorted()]
    assert order == [
        ("a.py", 2, "in_aadhaar"),
        ("a.py", 2, "in_pan"),
        ("a.py", 9, "in_aadhaar"),
        ("m.py", 1, "in_aadhaar"),
        ("z.py", 3, "in_aadhaar"),
    ]
    d = inv.to_dict()
    assert d["total"] == 5
    assert RAW not in json.dumps(d)

import json
from pathlib import Path

from dpdp_scan.detectors.checksums import verhoeff_check_digit
from dpdp_scan.engine import scan_path
from dpdp_scan.walker import WalkOptions

AADHAAR = "34567890123" + verhoeff_check_digit("34567890123")


def test_scan_path_walks_and_masks(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "seed.py").write_text(
        f"USER = {{'aadhaar': '{AADHAAR}', 'email': 'ravi.kumar@acme.in'}}\n", encoding="utf-8"
    )
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.js").write_text(f"// {AADHAAR}\n", encoding="utf-8")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\0\0" + AADHAAR.encode())

    result = scan_path(tmp_path, walk_options=WalkOptions(use_git=False))

    assert result.files_scanned == 1
    assert result.inventory.by_path == {"src/seed.py": 2}
    assert result.inventory.by_detector == {"email": 1, "in_aadhaar": 1}
    assert AADHAAR not in json.dumps(result.inventory.to_dict())

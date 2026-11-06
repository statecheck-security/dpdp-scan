import json
import shutil
from pathlib import Path

import pytest

from dpdp_scan import semgrep_runner
from dpdp_scan.engine import scan_path
from dpdp_scan.masking import DECLARED
from dpdp_scan.model import Category, Confidence
from dpdp_scan.semgrep_findings import sanitise, to_findings
from dpdp_scan.semgrep_runner import RULES_DIR, batch_by_argv_length, run_semgrep
from dpdp_scan.walker import WalkOptions

FIXTURES = Path(__file__).parent / "semgrep"
HAVE_SEMGREP = shutil.which("semgrep") is not None

CANNED = {
    "version": "1.178.0",
    "results": [
        {
            "check_id": "src.dpdp_scan.rules.dpdpa.pii-in-logs-python",
            "path": "app/views.py",
            "start": {"line": 12, "col": 5},
            "end": {"line": 12, "col": 40},
            "extra": {
                "message": "Personal data is passed to a log call.   Keep it out.",
                "metadata": {
                    "category": "identity",
                    "confidence": "medium",
                    "dpdpa": ["S.8(5)", "Rule 6(1)(a)"],
                },
                "metavars": {
                    "$X": {"abstract_content": 'f"aadhaar {user.aadhaar_no} 999999990019"'},
                    "$M": {"abstract_content": "info"},
                },
                "lines": 'logger.info(f"aadhaar {user.aadhaar_no} 999999990019")',
            },
        },
        {
            "check_id": "dob-without-age-gate-js",
            "path": "web\\signup.ts",
            "start": {"line": 3, "col": 1},
            "extra": {"message": "DOB", "metadata": {"category": "age_dob", "confidence": "low"}},
        },
    ],
    "errors": [],
}


def test_rules_dir_ships_with_the_package() -> None:
    assert (RULES_DIR / "dpdpa.yml").is_file()


def test_batching_respects_argv_budget() -> None:
    paths = [f"dir/file{i:04d}.py" for i in range(1000)]
    batches = batch_by_argv_length(paths, budget=200)
    assert sum(len(b) for b in batches) == 1000
    assert all(sum(len(p) + 1 for p in b) <= 200 for b in batches)
    assert batch_by_argv_length([]) == []


def test_sanitise_masks_values_in_matched_code() -> None:
    out = sanitise('send(user.email, "ravi.kumar@acme.in", 999999990019,   x)')
    assert "ravi.kumar@acme.in" not in out and "999999990019" not in out
    assert "user.email" in out and "  " not in out
    assert len(sanitise("x" * 500)) == 80
    out = sanitise("pan='BNZPM2501F' gst='27AAPFU0939F1ZV' upi='ravi.k@okaxis' phone=9812345670")
    for raw in ("BNZPM2501F", "27AAPFU0939F1ZV", "ravi.k@okaxis", "9812345670"):
        assert raw not in out
    assert out.startswith("pan='")


def test_to_findings_falls_back_to_matched_line_when_no_metavars() -> None:
    res = [
        {
            "check_id": "pii-in-logs-js",
            "path": "a.js",
            "start": {"line": 4, "col": 3},
            "extra": {"message": "m", "lines": 'console.log("otp", user.phone, 9812345670)'},
        }
    ]
    f = to_findings(res)[0]
    assert "user.phone" in f.locator and "9812345670" not in f.locator


def test_to_findings_reads_span_from_file_when_lines_require_login(tmp_path: Path) -> None:
    src = "\n".join(["x();", 'console.log("otp", user.phone, 9812345670); // trailing', ""])
    (tmp_path / "a.js").write_text(src, encoding="utf-8")
    res = [
        {
            "check_id": "pii-in-logs-js",
            "path": "a.js",
            "start": {"line": 2, "col": 1},
            "end": {"line": 2, "col": 45},
            "extra": {"message": "m", "lines": "requires login"},
        }
    ]
    f = to_findings(res, tmp_path.as_posix())[0]
    assert f.locator.startswith('console.log("otp", user.phone,')
    assert "9812345670" not in f.locator and "trailing" not in f.locator
    assert to_findings(res)[0].locator == ""  # no root, nothing to read


def test_to_findings_maps_metadata_and_masks() -> None:
    findings = to_findings(CANNED["results"])
    assert len(findings) == 2
    f = findings[0]
    assert f.detector_id == "rule:pii-in-logs-python"
    assert f.category == Category.IDENTITY and f.confidence == Confidence.MEDIUM
    assert [p.ref for p in f.provisions] == ["S.8(5)", "Rule 6(1)(a)"]
    assert f.path == "app/views.py" and (f.line, f.column) == (12, 5)
    assert f.evidence == DECLARED
    assert "999999990019" not in f.locator and "user.aadhaar_no" in f.locator
    assert f.message == "Personal data is passed to a log call. Keep it out."
    g = findings[1]
    assert g.path == "web/signup.ts" and g.category == Category.AGE_DOB
    assert g.confidence == Confidence.LOW and g.provisions == ()
    assert "999999990019" not in json.dumps([x.to_dict() for x in findings])


def test_to_findings_strips_root_prefix_and_drops_absolute() -> None:
    res = [{"check_id": "r", "path": "/repo/a.py", "start": {"line": 1, "col": 1}}]
    assert to_findings(res, "/repo")[0].path == "a.py"
    assert to_findings(res, "/other") == []


def test_missing_binary_degrades(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("DPDP_SCAN_SEMGREP", raising=False)
    monkeypatch.setattr(semgrep_runner.shutil, "which", lambda _name: None)
    run = run_semgrep(tmp_path, ["a.py"])
    assert run.status == "missing" and run.results == []
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    result = scan_path(tmp_path, walk_options=WalkOptions(use_git=False))
    assert result.semgrep is not None and result.semgrep.status == "missing"
    assert result.files_scanned == 1


def test_no_targets_is_skipped(tmp_path: Path) -> None:
    run = run_semgrep(tmp_path, ["README.md", "schema.sql"], binary="semgrep-not-called")
    assert run.status == "skipped"


def test_rules_off(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert scan_path(tmp_path, walk_options=WalkOptions(use_git=False), rules=False).semgrep is None


@pytest.mark.skipif(not HAVE_SEMGREP, reason="semgrep not installed")
def test_rule_pack_fires_on_fixtures_and_only_there(tmp_path: Path) -> None:
    for name in ("dpdpa.py", "dpdpa.js"):
        shutil.copy(FIXTURES / name, tmp_path / name)
    (tmp_path / "clean.py").write_text(
        'import logging\nlogging.getLogger().info("order %s", order_id)\n', encoding="utf-8"
    )
    result = scan_path(tmp_path, walk_options=WalkOptions(use_git=False))
    assert result.semgrep is not None and result.semgrep.status == "ok", result.semgrep.errors
    rules = {f.detector_id for f in result.inventory.findings if f.detector_id.startswith("rule:")}
    assert rules == {
        "rule:pii-in-logs-python",
        "rule:pii-in-logs-js",
        "rule:pii-to-analytics-python",
        "rule:pii-to-analytics-js",
        "rule:dob-without-age-gate-python",
        "rule:dob-without-age-gate-js",
    }
    assert all(
        f.path != "clean.py" for f in result.inventory.findings if f.detector_id.startswith("rule:")
    )
    dob = [
        f for f in result.inventory.findings if f.detector_id == "rule:dob-without-age-gate-python"
    ]
    assert [p.ref for p in dob[0].provisions] == ["S.9", "Rule 10"]
    assert dob[0].confidence == Confidence.LOW
    logs = [f for f in result.inventory.findings if f.detector_id == "rule:pii-in-logs-python"]
    assert all(f.locator for f in logs), "every rule finding names what matched"

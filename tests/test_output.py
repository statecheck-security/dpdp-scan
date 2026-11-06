"""Output writers: SARIF validates against the 2.1.0 schema, nothing leaks."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from dpdp_scan.catalogue import catalogue, rule_info
from dpdp_scan.cli import main
from dpdp_scan.detectors.checksums import verhoeff_check_digit
from dpdp_scan.engine import ScanResult, scan_path
from dpdp_scan.model import Category
from dpdp_scan.output import build_inventory, build_markdown, build_sarif
from dpdp_scan.output.sarif import to_sarif_uri
from dpdp_scan.semgrep_runner import SemgrepRun
from dpdp_scan.walker import WalkOptions

SCHEMA = json.loads((Path(__file__).parent / "data" / "sarif-2.1.0.json").read_text("utf-8"))
AADHAAR = "56789012345" + verhoeff_check_digit("56789012345")
PAN = "BNZPM2501F"
EMAIL = "ravi.kumar@acme.in"
RAW = (AADHAAR, PAN, EMAIL)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "db").mkdir()
    (tmp_path / "db" / "schema.sql").write_text(
        "CREATE TABLE customers (id int, aadhar_no char(12), dob date, email text);\n",
        encoding="utf-8",
    )
    (tmp_path / "seed.py").write_text(
        f"USER = {{'aadhaar': '{AADHAAR}', 'pan': '{PAN}', 'email': '{EMAIL}'}}\n", encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def result(repo: Path) -> ScanResult:
    r = scan_path(repo, walk_options=WalkOptions(use_git=False), rules=False)
    r.semgrep = SemgrepRun("missing")  # exercise the notification path deterministically
    return r


def test_catalogue_covers_every_detector_and_rule() -> None:
    cat = catalogue()
    for rid in ("in_aadhaar", "email", "schema_sql", "schema_prisma", "schema_openapi"):
        assert rid in cat
    rules = [r for r in cat if r.startswith("rule:")]
    assert len(rules) == 6
    info = rule_info("rule:pii-in-logs-python")
    assert info.category == Category.IDENTITY
    assert [p.ref for p in info.provisions] == ["S.8(5)", "Rule 6(1)(a)"]
    assert info.remediation.endswith(".") and info.description
    assert rule_info("nope").name == "nope"


def test_to_sarif_uri() -> None:
    assert to_sarif_uri("src\\app\\x.py") == "src/app/x.py"
    assert to_sarif_uri(Path("src") / "x.py") == "src/x.py"


def test_sarif_validates_against_schema_and_anchors(result: ScanResult, repo: Path) -> None:
    doc = build_sarif(result, repo)
    jsonschema.validate(doc, SCHEMA)
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "dpdp-scan"
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].startswith("file:///")
    assert run["originalUriBaseIds"]["%SRCROOT%"]["uri"].endswith("/")
    assert len(run["results"]) == len(result.inventory.findings) >= 6
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for r in run["results"]:
        assert r["ruleId"] in ids
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
        loc = r["locations"][0]["physicalLocation"]
        assert "\\" not in loc["artifactLocation"]["uri"]
        assert loc["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
        assert loc["region"]["startLine"] >= 1
        assert r["level"] in ("warning", "note")
        assert len(r["partialFingerprints"]["dpdpScanFinding/v1"]) == 32
    notes = run["invocations"][0]["toolExecutionNotifications"]
    assert notes and "missing" in notes[0]["message"]["text"]


def test_sarif_uses_github_workspace_when_set(
    result: ScanResult, repo: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    monkeypatch.setenv("GITHUB_WORKSPACE", str(ws))
    uri = build_sarif(result, repo)["runs"][0]["originalUriBaseIds"]["%SRCROOT%"]["uri"]
    assert uri == ws.resolve().as_uri() + "/"


def test_sarif_fingerprints_are_stable(result: ScanResult, repo: Path) -> None:
    a = build_sarif(result, repo)["runs"][0]["results"]
    b = build_sarif(result, repo)["runs"][0]["results"]
    assert [r["partialFingerprints"] for r in a] == [r["partialFingerprints"] for r in b]


def test_inventory_shape_and_data_map(result: ScanResult) -> None:
    inv = build_inventory(result)
    assert inv["summary"]["files_scanned"] == 2
    assert inv["summary"]["semgrep"]["status"] == "missing"
    assert {c["category"] for c in inv["categories"]} >= {"identity", "contact", "age_dob"}
    dm = {d["container"]: d for d in inv["data_map"]}
    assert dm["customers"]["path"] == "db/schema.sql"
    fields = {f["field"]: f for f in dm["customers"]["fields"]}
    assert fields["aadhar_no"]["category"] == "identity"
    assert fields["dob"]["provisions"][0] == "S.9"
    assert "id" not in fields
    assert {v["detector"] for v in inv["values"]} == {"in_aadhaar", "in_pan", "email"}
    assert inv["rules"] == []
    assert inv["not_legal_advice"].startswith("dpdp-scan reports")


def test_markdown_groups_by_category(result: ScanResult) -> None:
    md = build_markdown(result, "demo")
    assert md.startswith("# dpdp-scan report: demo")
    assert "## Summary" in md and "| Category | Findings | Engages |" in md
    assert "## Identity documents and names" in md
    assert "Age and date of birth (children: S.9)" in md
    assert "S.9" in md and "`db/schema.sql:1` `customers.dob`" in md
    assert "Semgrep status `missing`" in md
    assert md.rstrip().endswith("gives no compliance verdict.*")


def test_markdown_empty_result() -> None:
    md = build_markdown(ScanResult(), "x")
    assert "No personal data found" in md


def test_no_raw_value_in_any_output(result: ScanResult, repo: Path) -> None:
    texts = [
        json.dumps(build_sarif(result, repo)),
        json.dumps(build_inventory(result)),
        build_markdown(result, "demo"),
    ]
    for text in texts:
        for raw in RAW:
            assert raw not in text
        assert AADHAAR[-4:] in text  # masks keep the last four, so evidence is present


def test_cli_formats_and_files(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    code = main(
        [
            str(repo),
            "--no-git",
            "--no-rules",
            "--format",
            "sarif",
            "--sarif",
            str(out_dir / "r.sarif"),
            "--json",
            str(out_dir / "r.json"),
            "--markdown",
            str(out_dir / "r.md"),
        ]
    )
    assert code == 0
    stdout = capsys.readouterr().out
    jsonschema.validate(json.loads(stdout), SCHEMA)
    jsonschema.validate(json.loads((out_dir / "r.sarif").read_text("utf-8")), SCHEMA)
    assert json.loads((out_dir / "r.json").read_text("utf-8"))["tool"] == "dpdp-scan"
    assert (out_dir / "r.md").read_text("utf-8").startswith("# dpdp-scan report")
    for raw in RAW:
        assert raw not in stdout
        for name in ("r.sarif", "r.json", "r.md"):
            assert raw not in (out_dir / name).read_text("utf-8")


def test_cli_json_and_markdown_stdout(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(repo), "--no-git", "--no-rules", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["findings"] >= 6
    assert main([str(repo), "--no-git", "--no-rules", "--format", "markdown"]) == 0
    assert capsys.readouterr().out.startswith("# dpdp-scan report")

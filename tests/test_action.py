"""The Action and Dockerfile stay consistent with the CLI they wrap."""

from pathlib import Path

import yaml

from dpdp_scan.cli import build_parser

ROOT = Path(__file__).parent.parent
ACTION = yaml.safe_load((ROOT / "action.yml").read_text("utf-8"))


def test_action_is_composite_with_branding() -> None:
    assert ACTION["runs"]["using"] == "composite"
    assert ACTION["branding"] == {"icon": "shield", "color": "green"}
    assert "Not legal advice" in ACTION["description"]


def test_action_inputs_map_to_cli_flags() -> None:
    flags = {a for action in build_parser()._actions for a in action.option_strings}
    for name in ("min-confidence", "fail-on", "fail-on-category", "baseline", "config"):
        assert name in ACTION["inputs"]
        assert f"--{name}" in flags
    for name in ("path", "sarif-file", "upload-sarif", "semgrep", "version", "python-version"):
        assert name in ACTION["inputs"]
    assert set(ACTION["outputs"]) == {"sarif-file", "findings", "exit-code"}


def test_action_steps_pin_shas_and_upload_before_failing() -> None:
    steps = ACTION["runs"]["steps"]
    names = [s.get("name", s.get("uses", "")) for s in steps]
    assert names.index("Upload SARIF to code scanning") < names.index("Apply fail-on")
    for s in steps:
        uses = s.get("uses", "")
        if uses.startswith("actions/"):
            assert "@" in uses and len(uses.split("@")[1].split()[0]) == 40, uses
    scan = next(s for s in steps if s.get("id") == "scan")
    assert "--sarif" in scan["run"] and "GITHUB_OUTPUT" in scan["run"]


def test_dockerfile_runs_as_non_root_with_semgrep() -> None:
    text = (ROOT / "Dockerfile").read_text("utf-8")
    assert "semgrep" in text and "USER scanner" in text
    assert 'ENTRYPOINT ["dpdp-scan"]' in text
    assert "SEMGREP_SEND_METRICS=off" in text


def test_dogfood_workflow_grants_security_events() -> None:
    wf = yaml.safe_load((ROOT / ".github" / "workflows" / "dpdp-scan.yml").read_text("utf-8"))
    assert wf["permissions"]["security-events"] == "write"
    assert any(s.get("uses") == "./" for s in wf["jobs"]["scan"]["steps"])

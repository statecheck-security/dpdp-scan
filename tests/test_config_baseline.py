import json
from pathlib import Path

import pytest

from dpdp_scan.baseline import BaselineError, apply_baseline, load_baseline, write_baseline
from dpdp_scan.cli import main
from dpdp_scan.config import AllowList, Config, ConfigError, load_config, parse_config, value_hash
from dpdp_scan.detectors.base import Step, compact_value
from dpdp_scan.detectors.checksums import verhoeff_check_digit
from dpdp_scan.engine import scan_path
from dpdp_scan.model import fingerprint
from dpdp_scan.walker import WalkOptions

AADHAAR = "67890123456" + verhoeff_check_digit("67890123456")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "fixtures").mkdir()
    lines = [
        f"A = '{AADHAAR}'",
        "E = 'ravi@acme.in'",
        "O = 'hello@statechecksecurity.com'",
        "M = '9812345670'",
        "",
    ]
    (tmp_path / "src" / "app.py").write_text("\n".join(lines), encoding="utf-8")
    (tmp_path / "fixtures" / "seed.py").write_text(f"B = '{AADHAAR}'\n", encoding="utf-8")
    (tmp_path / "db.sql").write_text("CREATE TABLE users (id int, dob date);\n", encoding="utf-8")
    return tmp_path


def run(repo: Path, config: Config | None = None):
    return scan_path(repo, walk_options=WalkOptions(use_git=False), rules=False, config=config)


# ---- config ----------------------------------------------------------------


def test_parse_defaults_and_full_config() -> None:
    assert parse_config(None) == Config()
    cfg = parse_config(
        {
            "version": 1,
            "ignore": {"paths": ["fixtures/", "docs/**/*.md"]},
            "detectors": {"disable": ["in_mobile", "rule:dob-without-age-gate-js", "schema"]},
            "allow": {"domains": ["@StateCheckSecurity.com"], "values_sha256": ["A" * 64]},
            "fail_on": "medium",
            "baseline": ".dpdp-scan-baseline.json",
        }
    )
    assert cfg.ignore_paths == ("fixtures/", "docs/**/*.md")
    assert not cfg.detector_enabled("in_mobile")
    assert not cfg.detector_enabled("rule:dob-without-age-gate-js")
    assert cfg.detector_enabled("rule:pii-in-logs-js")
    assert not cfg.detector_enabled("schema_sql") and not cfg.detector_enabled("schema_prisma")
    assert cfg.allow.domains == ("statechecksecurity.com",)
    assert cfg.allow.value_hashes == {"a" * 64}
    assert cfg.fail_on == Step.MEDIUM and cfg.baseline == ".dpdp-scan-baseline.json"


@pytest.mark.parametrize(
    ("data", "msg"),
    [
        ({"typo": 1}, "unknown config keys"),
        ({"version": 2}, "version 1"),
        ({"ignore": {"paths": ["/abs"]}}, "repo-relative"),
        ({"ignore": {"paths": ["../x"]}}, "repo-relative"),
        ({"ignore": {"globs": []}}, "accepts only"),
        ({"detectors": {"disable": "in_mobile"}}, "list of strings"),
        ({"allow": {"values_sha256": ["notahash"]}}, "64 hex"),
        ({"fail_on": "severe"}, "fail_on must be"),
        ({"baseline": 3}, "path string"),
        ("just a string", "mapping"),
    ],
)
def test_parse_rejects_bad_config(data, msg: str) -> None:
    with pytest.raises(ConfigError, match=msg):
        parse_config(data)


def test_load_config_from_root_and_explicit(tmp_path: Path) -> None:
    assert load_config(tmp_path) == Config()
    (tmp_path / ".dpdp-scan.yml").write_text("fail_on: high\n", encoding="utf-8")
    assert load_config(tmp_path).fail_on == Step.HIGH
    other = tmp_path / "other.yml"
    other.write_text("ignore:\n  paths: [a/]\n", encoding="utf-8")
    assert load_config(tmp_path, str(other)).ignore_paths == ("a/",)
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(tmp_path, str(tmp_path / "missing.yml"))
    (tmp_path / "bad.yml").write_text("a: [unclosed\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(tmp_path, str(tmp_path / "bad.yml"))


def test_allowlist_hash_and_domain() -> None:
    allow = AllowList(domains=("acme.in",), value_hashes=frozenset({value_hash(AADHAAR)}))
    assert allow.allows_value(AADHAAR) and not allow.allows_value("1" + AADHAAR[1:])
    assert allow.allows_domain("ravi@acme.in") and allow.allows_domain("x@mail.acme.in")
    assert not allow.allows_domain("ravi@notacme.in") and not allow.allows_domain(AADHAAR)


# ---- engine with config ----------------------------------------------------


def test_ignore_paths_prefix_and_glob(repo: Path) -> None:
    base = run(repo).inventory.by_path
    assert "fixtures/seed.py" in base
    inv = run(repo, Config(ignore_paths=("fixtures/",))).inventory
    assert "fixtures/seed.py" not in inv.by_path and "src/app.py" in inv.by_path
    inv = run(repo, Config(ignore_paths=("**/seed.py",))).inventory
    assert "fixtures/seed.py" not in inv.by_path
    inv = run(repo, Config(ignore_paths=("*.sql",))).inventory
    assert "db.sql" not in inv.by_path


def test_disable_detectors_and_families(repo: Path) -> None:
    inv = run(repo, Config(disabled=frozenset({"in_mobile", "schema"}))).inventory
    assert "in_mobile" not in inv.by_detector and "schema_sql" not in inv.by_detector
    assert "in_aadhaar" in inv.by_detector


def test_allow_domain_drops_own_mailboxes_but_not_others(repo: Path) -> None:
    inv = run(repo, Config(allow=AllowList(domains=("statechecksecurity.com",)))).inventory
    emails = [f for f in inv.findings if f.detector_id == "email"]
    assert len(emails) == 1 and emails[0].evidence == "*******mein"  # "ravi@acmein" is 11 chars


def test_allow_value_by_hash(repo: Path) -> None:
    cfg = Config(allow=AllowList(value_hashes=frozenset({value_hash(compact_value(AADHAAR))})))
    assert "in_aadhaar" not in run(repo, cfg).inventory.by_detector


# ---- baseline --------------------------------------------------------------


def test_baseline_round_trip(repo: Path, tmp_path: Path) -> None:
    result = run(repo)
    path = tmp_path / "b.json"
    n = write_baseline(path, result.inventory)
    assert n == len({fingerprint(f) for f in result.inventory.findings}) > 0
    doc = json.loads(path.read_text("utf-8"))
    assert AADHAAR not in path.read_text("utf-8") and doc["version"] == 1
    kept, suppressed = apply_baseline(result.inventory, load_baseline(path))
    assert suppressed == len(result.inventory.findings) and kept.findings == []
    # A new finding is not in the baseline.
    (repo / "src" / "new.py").write_text("P = 'BNZPM2501F'\n", encoding="utf-8")
    kept, suppressed = apply_baseline(run(repo).inventory, load_baseline(path))
    assert [f.detector_id for f in kept.findings] == ["in_pan"]


@pytest.mark.parametrize(
    ("content", "msg"),
    [
        ("not json", "not valid JSON"),
        ('{"version": 9}', "not a dpdp-scan baseline"),
        ('{"version": 1, "fingerprints": [1]}', "list of strings"),
    ],
)
def test_load_baseline_rejects(tmp_path: Path, content: str, msg: str) -> None:
    p = tmp_path / "b.json"
    p.write_text(content, encoding="utf-8")
    with pytest.raises(BaselineError, match=msg):
        load_baseline(p)


# ---- CLI exit codes --------------------------------------------------------


def test_exit_codes(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    common = [str(repo), "--no-git", "--no-rules"]
    assert main(common) == 0  # default: never fail
    assert main([*common, "--fail-on", "high"]) == 1  # the Aadhaar is HIGH
    assert main([*common, "--fail-on", "none"]) == 0
    assert main([*common, "--min-confidence", "medium", "--fail-on", "low"]) == 1
    assert main([*common, "--fail-on-category", "age_dob"]) == 1  # users.dob
    assert main([*common, "--fail-on-category", "health"]) == 0
    assert main([*common, "--fail-on-category", "bogus"]) == 2
    assert "unknown category" in capsys.readouterr().err
    assert main([str(repo / "nope")]) == 2


def test_config_fail_on_and_flag_override(repo: Path) -> None:
    (repo / ".dpdp-scan.yml").write_text("fail_on: high\n", encoding="utf-8")
    assert main([str(repo), "--no-git", "--no-rules"]) == 1
    assert main([str(repo), "--no-git", "--no-rules", "--fail-on", "none"]) == 0


def test_config_error_exits_2(repo: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repo / ".dpdp-scan.yml").write_text("typo: 1\n", encoding="utf-8")
    assert main([str(repo), "--no-git", "--no-rules"]) == 2
    assert "config error" in capsys.readouterr().err


def test_write_then_use_baseline_via_cli(
    repo: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    b = tmp_path / "base.json"
    assert main([str(repo), "--no-git", "--no-rules", "--write-baseline", str(b)]) == 0
    assert "wrote" in capsys.readouterr().err
    code = main([str(repo), "--no-git", "--no-rules", "--baseline", str(b), "--fail-on", "low"])
    out = capsys.readouterr().out
    assert code == 0 and "0 findings" in out and "accepted by the baseline" in out
    (repo / ".dpdp-scan.yml").write_text(f"baseline: {b.name}\n", encoding="utf-8")
    b.replace(repo / b.name)
    assert main([str(repo), "--no-git", "--no-rules", "--fail-on", "low"]) == 0
    assert (
        main([str(repo), "--no-git", "--no-rules", "--baseline", str(tmp_path / "missing.json")])
        == 2
    )


def test_hash_value_flag(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--hash-value", "9999 9999 0019"]) == 0
    assert capsys.readouterr().out.strip() == value_hash("999999990019")

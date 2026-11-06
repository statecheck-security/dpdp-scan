# dpdp-scan

Finds Indian personal data in code, schemas, fixtures and logs, and points each finding
at the obligation under India's Digital Personal Data Protection Act, 2023 and the DPDP
Rules, 2025 that it touches. A CLI and a GitHub Action, built to run in CI.

**Status:** v0.1.0 (6 November 2026). Value detectors, schema classifier, Semgrep rule
pack, SARIF/JSON/Markdown outputs, config, baseline, a GitHub Action and a Docker image.
See [CHANGELOG.md](CHANGELOG.md); the build plan is in [`.claude/PLAN.md`](.claude/PLAN.md).
Try it on [DVDPA](https://github.com/statecheck-security/dvdpa), a deliberately leaky demo app.

> **Not legal advice.** dpdp-scan reports where personal data appears and which
> obligation it engages. It gives no compliance verdict. Whether a finding matters
> depends on your processing, your contracts and how the Data Protection Board reads
> the Rules.

## What it does

| Part | What | Why it matters |
|---|---|---|
| Validated detectors | Aadhaar (Verhoeff checksum, first digit 2–9), PAN (holder-type character), GSTIN (mod-36 check character, state code, embedded PAN), IFSC, UPI VPA (known PSP handles), Indian mobile numbers, voter EPIC, passport, driving licence, email | Checksums are what keep false positives down. A 12-digit order id is not an Aadhaar. |
| Schema classifier | SQL DDL and migrations, Prisma, OpenAPI / JSON Schema; a field-name lexicon that knows `aadhar_no`, `pan_no`, `mob_no`, `dob`, `father_name` | Most personal data in a repo is declared, not written out. The inventory starts here. |
| Semgrep rule pack | Personal data written to logs; personal data sent to analytics SDKs; age or DOB collected with no age gate nearby (a Section 9 signal) | The rules are plain YAML you can read, test and extend. |
| Outputs | SARIF 2.1.0 for GitHub code scanning, a JSON data inventory, a Markdown summary | SARIF puts findings in the Security tab; the inventory seeds a data map or RoPA. |
| CI ergonomics | `.dpdp-scan.yml`, a baseline file to accept existing findings, `--fail-on`, documented exit codes, a pre-commit hook | The gitleaks shape: drop it in, it only fails on what is new. |

**Masking is a ground rule.** Every report, log line and SARIF snippet masks matched
values (at most the last four characters). The scanner must never move an Aadhaar number
from a repository into a CI log. A test fails the build if any raw value reaches an output.

**Not in v0.1:** cross-service data-flow mapping, free-text NER (an optional Presidio
plug-in later), databases or live systems (it scans repositories only), any compliance
score or verdict.

## Precision and recall

Measured on a synthetic, labelled corpus that the benchmark generates (no real identifier
is stored anywhere). Numbers are k/N with the misses named, so they can be checked and so
nobody has to write "detects all Aadhaar numbers".

**Precision and recall on the synthetic benchmark (2026-11-06, commit 82ab268).** `python -m dpdp_scan.bench`, seed 20261106, 200 per class.

| Detector | Recall (found / positives) | Precision (true / fired) | Misses | False hits |
|---|---:|---:|---|---|
| `email` | 200/200 (100%) | 200/200 (100%) | none | none |
| `in_aadhaar` | 200/200 (100%) | 200/236 (85%) | none | order_id_prefixed 21, random_12_digits 15 |
| `in_driving_licence` | 200/200 (100%) | 200/200 (100%) | none | none |
| `in_gstin` | 200/200 (100%) | 200/200 (100%) | none | none |
| `in_ifsc` | 200/200 (100%) | 200/200 (100%) | none | none |
| `in_mobile` | 200/200 (100%) | 200/299 (67%) | none | random_10_digits 99 |
| `in_pan` | 200/200 (100%) | 200/200 (100%) | none | none |
| `in_passport` | 200/200 (100%) | 200/200 (100%) | none | none |
| `in_upi` | 200/200 (100%) | 200/200 (100%) | none | none |
| `in_voter_epic` | 200/200 (100%) | 200/200 (100%) | none | none |

Recall counts a positive as found at any confidence. Precision counts every firing on a
negative as a false hit, including the ones the detector itself marks LOW. Two floors are
structural: about one random 12-digit number in ten passes the Verhoeff checksum, and four
random 10-digit numbers in nine start with 6 to 9 and so look like a mobile number. Both are
reported at reduced confidence (MEDIUM with an order-id context, LOW for a bare ten digits),
and field names are what lift real values above them. The corpus does not yet contain
real-world text with Indian names, addresses or Hinglish, so these numbers are an upper
bound on synthetic data, not a claim about your repository.

## How it compares

Checked on 5 November 2026 against each project's repository.

| Project | Indian identifiers with checksums | Scans code, schemas, logs | Readable rules | SARIF + Action | Licence |
|---|---|---|---|---|---|
| **dpdp-scan** (v0.1 target) | yes | yes | yes (Semgrep YAML) | yes | Apache-2.0 |
| [Privado](https://github.com/Privado-Inc/privado) | no | code data-flow (Joern) | partial | no SARIF | LGPL-3.0 |
| [Bearer CLI](https://github.com/Bearer/bearer) | no | code, 122 data types | partial | yes | Elastic 2.0 (not open source) |
| [Presidio](https://github.com/data-privacy-stack/presidio) | Aadhaar yes; PAN, GSTIN regex only; no UPI, IFSC, mobile | free text | n/a | no | MIT |
| [VibeDoctor](https://github.com/neural-axis/VibeDoctor) | Aadhaar | code, logs, prompts | no | SARIF, no Action | GPL-3.0 |
| [Vettam dpdp-compliance-scanner](https://github.com/Vettam/dpdp-compliance-scanner) | not found | JS/TS/Python data map | partial | Action, no SARIF | Apache-2.0 |
| [truscanner](https://github.com/truconsent/truscanner) | regex, no checksums | code | no | no | MIT |
| [Scrutora dpdp-scan Action](https://github.com/Scrutora/scrutora-scan) | unknown (closed engine) | code | no | yes | none (engine is not open source) |
| [gitleaks](https://github.com/gitleaks/gitleaks) | n/a (secrets, not personal data) | code | yes | yes | MIT |

Presidio is the engine dpdp-scan builds on for recogniser interfaces; gitleaks is the
CI experience it copies. The rest are the field.

## Install

```bash
pipx install dpdp-scan semgrep   # or: pip install dpdp-scan semgrep
dpdp-scan .                      # text summary
dpdp-scan . --format sarif --sarif results.sarif --fail-on high
```

Semgrep is optional: without it the value detectors and schema classifier still run and
the rule pack is skipped with a note. Until the PyPI release lands, install from GitHub:
`pip install git+https://github.com/statecheck-security/dpdp-scan@v0.1.1`.

**GitHub Action.** Findings go to the Security tab as code scanning alerts:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v5
  - uses: statecheck-security/dpdp-scan@v0.1.1
    with:
      fail-on: high            # none | low | medium | high
      # baseline: .dpdp-scan-baseline.json
```

**Docker.** `docker build -t dpdp-scan .` then
`docker run --rm -v "$PWD:/repo:ro" dpdp-scan /repo --format sarif > results.sarif`.

## Configuration

Put a `.dpdp-scan.yml` in the repository root (or pass `--config FILE`):

```yaml
version: 1
ignore:
  paths: ["fixtures/", "docs/**/*.md"]      # prefixes or globs, repo-relative
detectors:
  disable: ["in_mobile", "rule:dob-without-age-gate-js"]   # ids, or "schema" / "rules"
allow:
  domains: ["example-company.in"]            # your own mailboxes are not findings
  values_sha256: ["<sha256>"]                # from `dpdp-scan --hash-value VALUE`; never the value
fail_on: medium                              # default for --fail-on
baseline: .dpdp-scan-baseline.json
```

Values are allowlisted by hash so the config never holds the value itself. Unknown keys are
errors: a typo must not silently switch a check off.

**Baseline.** `dpdp-scan --write-baseline .dpdp-scan-baseline.json` records a fingerprint
for every current finding (detector, path, line and masked evidence; no values). With
`--baseline` or the config's `baseline`, those findings are dropped and CI fails only on
what is new.

**Exit codes.**

| Code | Meaning |
|---|---|
| 0 | Scan completed; no finding at or above `--fail-on` (default `none`: never fail) |
| 1 | Scan completed; a finding is at or above `--fail-on`, or in a `--fail-on-category` |
| 2 | Scan did not complete: bad arguments, unreadable path, invalid config or baseline |

Semgrep being absent is not an error: the rule pack is skipped, a note goes to stderr, and
the SARIF carries a tool notification.

## Development

```bash
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
ruff check . && ruff format --check . && pytest
```

CI runs the same on Ubuntu and Windows for Python 3.12 and 3.13.

## Related

- [DPDPA Engineering Kit](https://github.com/statecheck-security/dpdpa-engineering-kit):
  tested code for consent, breach notification, encryption, residency and CI privacy
  gates. The Semgrep rules and the field lexicon here grow out of its `ci-cd/` folder.
- [Paranoid](https://github.com/theAstiv/paranoid): threat modelling with LLMs. The
  Semgrep runner and SARIF exporter are ported from it (see `NOTICE`).
- [DPDPA checklist for small companies](https://statechecksecurity.com/dpdpa) and the
  free [DPDP Gap Identifier](https://statechecksecurity.com/dpdpa/gap-identifier).

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Built by [StateCheck Security](https://statechecksecurity.com).

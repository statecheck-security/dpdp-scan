# dpdp-scan

Finds Indian personal data in code, schemas, fixtures and logs, and points each finding
at the obligation under India's Digital Personal Data Protection Act, 2023 and the DPDP
Rules, 2025 that it touches. A CLI and a GitHub Action, built to run in CI.

**Status:** v0.0.1 holds the name. The scanner is being built; the plan is in
[`.claude/PLAN.md`](.claude/PLAN.md). Target for a usable v0.1: early December 2026.

> **Not legal advice.** dpdp-scan reports where personal data appears and which
> obligation it engages. It gives no compliance verdict. Whether a finding matters
> depends on your processing, your contracts and how the Data Protection Board reads
> the Rules.

## What it will do (v0.1)

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
pipx install dpdp-scan   # or: pip install dpdp-scan
dpdp-scan --version
```

The v0.0.1 CLI exits with code 2 and reads nothing. It exists so the name is taken.

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

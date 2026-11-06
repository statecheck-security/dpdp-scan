# Changelog

All notable changes to dpdp-scan. Dates are UTC. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-11-06

First usable release.

### Added

- Value detectors with validation for Aadhaar (Verhoeff), PAN (holder type), GSTIN
  (mod-36 check character, state code, embedded PAN), IFSC, UPI (known PSP handles),
  Indian mobile numbers, voter EPIC, passport, driving licence and email, with a
  context window that raises or lowers confidence from nearby field names.
- A built-in allowlist of UIDAI test UIDs, documented PANs and trivial digit runs.
- Schema classifier for SQL DDL and migrations, Prisma and OpenAPI/JSON Schema, with a
  field-name lexicon that knows Indian abbreviations and misspellings; declared fields
  carry a `table.column` locator.
- Semgrep rule pack (Python, JS/TS): personal data in log calls, personal data sent to
  analytics SDKs, date of birth read with no age gate (S.9 signal). Runs through a
  hardened runner and degrades to a note when Semgrep is absent.
- Outputs: SARIF 2.1.0 for GitHub code scanning, a JSON inventory with a data map, a
  Markdown summary and a text report. Every finding masks its value.
- `.dpdp-scan.yml` with ignore paths, detector toggles, domain and hashed-value
  allowlists; a baseline file; `--fail-on` and documented exit codes.
- A composite GitHub Action that uploads SARIF, a Docker image with Semgrep, and a
  synthetic benchmark (`python -m dpdp_scan.bench`) whose numbers the README carries.

### Not in this release

Cross-service data-flow mapping, free-text NER, database or live-system scanning,
ORM and TypeScript model parsing, and any compliance score or verdict.

[0.1.0]: https://github.com/statecheck-security/dpdp-scan/releases/tag/v0.1.0

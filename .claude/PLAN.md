# dpdp-scan — Implementation Plan

> An open-source CLI and GitHub Action that finds Indian personal data in code, schemas, fixtures and logs, and points each finding at the DPDPA obligation it touches.
> Written: 2026-10-17 | Moved into this repo at DS-1 on 2026-11-06 | Tracked in MemStack as project `dpdp-scan`, tasks 1–10.
> Decisions taken 2026-11-06: name `dpdp-scan`, Python 3.12+, org `statecheck-security`, Apache-2.0, public from the first commit. Ordered to-do across the three tools: scs `.claude/tasks/tooling-checklist.md`.

---

## Why build it

- **The market gap:** about 20 Indian DPDPA vendors exist, and almost all sell consent banners or consent management. Global tools (OneTrust, Securiti) target enterprise budgets. Commentators point to two gaps: affordable tooling for MSMEs, and weak discovery of **Indian** identifiers (Aadhaar, PAN, UPI and so on) in global tools. A search on 2026-10-17 found **no open-source CI tool** for DPDPA data discovery; the nearest are generic PII engines such as Presidio and commercial discovery suites.
  - **Revised 2026-11-05:** no longer cleanly true. Vettam's Apache-2.0 scanner ships a GitHub Action building a data map from JS/TS/Python; VibeDoctor (GPL, 34★) finds Aadhaar with Verhoeff in code and logs with a SARIF reporter; Scrutora sells a free closed-engine `dpdp-scan` Action with SARIF. The gap that remains: an identifier-first, checksum-validated, Semgrep-native rule pack with SARIF whose rules a team can read. Nine overlapping repos appeared Sep–Nov 2026; the star bar to lead the category is 18. Full table: statecheck-docs `docs/strategy/github-and-tooling-competitor-research.md`.
- **StateCheck's positioning:** "engineering compliance": we fix the code, not just the policy. A scanner that runs in CI proves this better than another article, and it fills the "security safeguards / know your data" gaps that the Gap Identifier raises.
- **Reuse:** paranoid already has a hardened Semgrep subprocess wrapper (`backend/deps/scanner.py`), SARIF export with repo-relative anchoring (`backend/export/sarif.py`) and a GitHub Action image. Both projects are Apache-2.0, so the code can be copied over directly.
- **Later:** the data inventory it produces seeds a RoPA/data map, which can feed a paranoid "DPDPA mode" and DPIA documents generated with docx-go.

## Scope

**v0.1 (MVP):**
1. **Value detectors with validation:**
   - Aadhaar: 12 digits, first digit 2–9, Verhoeff checksum
   - PAN: AAAAA9999A, with the 4th character as the holder type
   - GSTIN: 15 characters, with the embedded PAN and a mod-36 check character
   - IFSC
   - UPI VPA (a known PSP handle list)
   - Indian mobile numbers (+91/0 prefixes, starting 6–9)
   - Voter EPIC, passport, driving licence, email

   Validation is what keeps false positives down.
2. **Schema and field-name classifier:**
   - Sources: SQL DDL and migrations, Prisma, OpenAPI/JSON Schema. ORM models (Django, SQLAlchemy, TypeORM, Mongoose) come in v0.2.
   - A lexicon covering common Indian abbreviations (`aadhar_no`, `pan_no`, `mob_no`, `dob`, `father_name`) maps fields to inventory categories: identity, contact, financial, health, biometric, location, age/DOB.
3. **Semgrep rule pack:**
   - personal data written to logs;
   - personal data sent to third-party analytics SDKs (Segment, Mixpanel, GA, Firebase Analytics);
   - age/DOB collected without an age gate, a signal to check Section 9.
4. **Outputs:** SARIF 2.1.0 (GitHub code scanning), a JSON data inventory and a Markdown summary. Exit codes with `--fail-on`.
5. **Config:** `.dpdp-scan.yml` with ignore paths, allowlisted test values and a baseline file to accept existing findings.

**Not in v0.1:** cross-service data-flow mapping, free-text NER (an optional Presidio plug-in later), databases or live systems (it scans repos only), any compliance "verdict".

## Ground rules

- **Never leak what it finds.** Every report, log line and SARIF snippet masks matched values (last 4 characters at most). The scanner must not move Aadhaar numbers from a repo into CI logs.
- **Legal wording:** categories are *inventory* labels, not legal tiers, because DPDPA has no "sensitive personal data" category. Findings cite Act sections such as S.8(5) safeguards, S.9 children and S.8(7) retention. Run the `social-legal-check` patterns on rule messages and docs.
- **Honest numbers:** publish precision and recall per detector as k/N, with the misses named, the way paranoid's BM1 does. Never write "detects all Aadhaar numbers".
- "Not legal advice" goes in the README and the report footer.

## Stack

Python 3.12 (paranoid reuse; Semgrep and Presidio are Python), Apache-2.0, `uv`/`pyproject`, ruff, pytest, Semgrep as an optional runtime (missing Semgrep degrades to value and schema detectors only, the same as paranoid).

---

## Tasks

### DS-1 · Repo bootstrap · ~0.5 d
- [x] Check the name is free on PyPI and GitHub (fallbacks: `dpdpscan`, `india-pii-scan`) *(free on PyPI, npm and GitHub on 2026-11-05)*
- [x] `H:\github\dpdp-scan`: `pyproject.toml`, Apache-2.0 `LICENSE` + `NOTICE` (crediting the code ported from paranoid), ruff, pytest, CI (lint + test on Linux and Windows), and a README with scope, non-goals and "not legal advice" *(2026-11-06, commit c766c27; CI green still to be confirmed on GitHub)*
- [x] Move this plan into the repo as `.claude/PLAN.md` and leave a pointer here *(2026-11-06)*
- **Done when:** CI is green on an empty package.

### DS-2 · Core: finding model, walker, masking · ~1 d
- [ ] `Finding` (detector id, category, path, line/col, masked evidence, confidence, Act-section pointer) and `Inventory`
- [ ] File walker: honours `.gitignore`; skips binaries, vendored code (`node_modules`, `dist`, lockfiles) and files over a size cap
- [ ] A masking utility with its own tests. No code path may emit an unmasked value.
- **Done when:** a fixture repo walks deterministically and a test proves no raw value reaches any output.

### DS-3 · Validated value detectors · ~2 d
- [ ] Verhoeff and GSTIN checksum implementations, tested against published examples
- [ ] Detectors for the v0.1 identifier list, each with a context window (field/key names nearby raise confidence)
- [ ] A false-positive corpus: random 12-digit numbers, timestamps, order IDs, UUID fragments, phone-like numbers. Add known dummy/test values (sequences, documented test Aadhaar values) to a built-in allowlist.
- **Done when:** each detector's precision is measured on the corpus, and the numbers are recorded for DS-9.

### DS-4 · Schema and field-name classifier · ~2 d
- [ ] Parsers for SQL DDL/migrations, Prisma schema, and OpenAPI/JSON Schema properties
- [ ] Name lexicon covering English plus common Indian abbreviations and misspellings (`aadhar`, `adhaar`, `mobno`, `pincode`), mapped to inventory categories; table and column names roll up into the inventory
- **Done when:** run on bytesnapp's Prisma schema and scs's Sanity-backed APIs, it produces a sensible inventory. Those are our own repos; don't use client projects.

### DS-5 · Semgrep rule pack · ~2 d
- [ ] Port paranoid's Semgrep runner: the timeouts, process-tree kill, argv batching and degrade-if-missing behaviour
- [ ] Rules for JS/TS and Python first:
  - personal data in log calls;
  - personal data passed to analytics/telemetry SDKs;
  - DOB/age collection with no age-gate pattern nearby (a low-confidence S.9 signal)
- [ ] Rule tests (Semgrep `--test` fixtures)
- **Done when:** the rules fire on positive fixtures and stay quiet on negative ones; there are no crashes when Semgrep is absent.

### DS-6 · Outputs · ~1 d
**Depends on:** DS-2 → DS-5
- [ ] SARIF: port `to_sarif_uri` and the anchoring relative to `GITHUB_WORKSPACE`; rule metadata carries the Act section and a short remediation
- [ ] JSON inventory: categories, locations and counts, structured to seed a data map/RoPA later
- [ ] Markdown summary grouped by category, with the obligation each one touches
- **Done when:** SARIF validates against the 2.1.0 schema and uploads cleanly to GitHub code scanning on a test repo.

### DS-7 · Config, baseline, exit codes · ~0.5 d
- [ ] `.dpdp-scan.yml` (ignore paths, allowlist values by hash rather than plaintext, detector toggles)
- [ ] `--baseline` to write and compare, so existing findings don't fail CI
- [ ] `--fail-on` with a confidence or category threshold; document the exit codes

### DS-8 · GitHub Action + Docker image · ~1 d
**Depends on:** DS-6, DS-7
- [ ] Docker image with Semgrep included; `action.yml` modelled on paranoid's `action/`
- [ ] An example workflow that uploads SARIF
- [ ] Dogfood on scs, bytesnapp and paranoid, plus 3 public Indian OSS repos
- **Done when:** a real workflow run on GitHub shows findings in the Security tab.

### DS-9 · Benchmark · ~1 d
- [ ] A labelled fixture set (synthetic only, with no real identifiers): positives and hard negatives per detector
- [ ] `python -m dpdp_scan.bench` reports precision and recall per detector; the table goes in the README with the misses named
- **Done when:** the README states k/N per detector with the date and commit.

### DS-10 · Launch · ~1 d
**Depends on:** DS-8, DS-9, and the Gap Identifier being live
- [ ] Release v0.1.0 to PyPI and tag the Action
- [ ] A scs landing section and blog post (working title "Find Aadhaar in your codebase before the Board does"), plus a statecheck-docs article. Everything passes the legal check.
- [ ] Link from the Gap Identifier report: the "Security safeguards" and "Retention and erasure" gaps recommend running dpdp-scan
- [ ] A LinkedIn post and a newsletter issue

---

## Estimate and sequence

About **12 working days**. Start after Arsenal (10-29) and once the Gap Identifier's critical path is done; **target v0.1 in early December 2026**. DS-3, DS-4 and DS-5 are independent and can run in parallel sessions after DS-2.

## Open decisions (yours)

1. Name (`dpdp-scan` proposed)
2. Python (recommended, for paranoid reuse) or Go (single binary, like context-link)
3. Org: personal `theAstiv` or a StateCheck GitHub org. A StateCheck org makes it a brand asset.

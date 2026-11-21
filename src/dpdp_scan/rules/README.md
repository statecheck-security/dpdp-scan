# dpdp-scan Semgrep rules

Six Semgrep rules that flag code handling Indian personal data in ways the Digital Personal Data Protection Act, 2023 and the DPDP Rules, 2025 care about. They live in [`dpdpa.yml`](dpdpa.yml), run inside `dpdp-scan`, and also run on their own with plain Semgrep:

```bash
semgrep --config src/dpdp_scan/rules/dpdpa.yml path/to/code
```

The messages point engineers at a fix. They are not legal advice and not a compliance verdict.

| Rule | Languages | Flags | Act / Rules | Confidence |
|---|---|---|---|---|
| `pii-in-logs-python` | Python | a personal-data field (Aadhaar, PAN, email, phone, address, DOB, ...) passed to a `logging`/logger call or `print` | S.8(5), Rule 6(1)(a) | MEDIUM |
| `pii-in-logs-js` | JS, TS | the same, for `console.*` and logger calls | S.8(5), Rule 6(1)(a) | MEDIUM |
| `pii-to-analytics-python` | Python | a personal-data field sent to an analytics or telemetry SDK (Segment, Mixpanel, PostHog, Sentry, CleverTap, MoEngage, ...) | S.5, S.6, S.8(2) | MEDIUM |
| `pii-to-analytics-js` | JS, TS | the same, plus `gtag`, `fbq` and the GTM `dataLayer` | S.5, S.6, S.8(2) | MEDIUM |
| `dob-without-age-gate-python` | Python | a date of birth read from request input with no age check in the same function | S.9, Rule 10 | LOW |
| `dob-without-age-gate-js` | JS, TS | the same, for Express-style handlers | S.9, Rule 10 | LOW |

The rules match field *names* (`user.email`, `aadhaar_no`, `dateOfBirth`), not values, so they never need to see real data. The schema and value detectors in the rest of `dpdp-scan` cover values.

## Metadata

Every rule carries two sets of metadata keys.

**dpdp-scan's own keys:**

- `dpdp_category`: the inventory category the finding is filed under (`identity`, `age_dob`).
- `dpdpa`: the sections of the Act and Rules the finding engages.
- `label`: the short name shown in reports.

**[Semgrep Registry](https://semgrep.dev/r) keys:**

- `category`: `security` for the log and analytics rules, `best-practice` for the age-gate signal.
- `subcategory`: `audit`, because these are name-based heuristics, not dataflow.
- `cwe`, `owasp` and `vulnerability_class`: CWE-532 for logs, CWE-359 for analytics.
- `likelihood`, `impact` and `confidence`.
- `technology` and `references`.

These keys pass the registry's metadata schema and rule lints, so the same text can be submitted there.

## Tests

The fixtures are [`tests/semgrep/dpdpa.py`](../../../tests/semgrep/dpdpa.py) and [`dpdpa.js`](../../../tests/semgrep/dpdpa.js). A `ruleid:` comment marks a line a rule must flag; `ok:` marks a line it must not. Check them with:

```bash
mkdir -p /tmp/rt && cp src/dpdp_scan/rules/dpdpa.yml /tmp/rt/dpdpa.yaml && cp tests/semgrep/dpdpa.* /tmp/rt/
semgrep --test /tmp/rt
```

`tests/test_semgrep.py` also scans the fixtures through `dpdp-scan` when Semgrep is installed. It checks that every rule fires, and that each finding lands in the right inventory category with the right confidence.

## Licence

Apache-2.0, like the rest of this repository. If a copy of these rules is published in the Semgrep Registry, that copy is distributed under the registry's terms. This file is the canonical source, and it stays Apache-2.0.

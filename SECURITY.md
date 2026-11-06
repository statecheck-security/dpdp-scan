# Security policy

## What this tool handles

dpdp-scan reads repositories that may contain real personal data: Aadhaar numbers in
fixtures, PAN in test data, phone numbers in logs. The tool's first duty is not to move
that data anywhere.

- Every report, log line and SARIF snippet masks matched values. At most the last four
  characters are shown.
- The scanner makes no network requests. It reads the path you give it and writes the
  outputs you ask for.
- A test in `tests/` fails the build if any raw matched value reaches an output stream.

If you find a code path that emits an unmasked value, treat it as a security bug and
report it as below, not as a public issue.

## Reporting a vulnerability

Use the contact form at <https://statechecksecurity.com/#contact> (or the email address
published there) with the version, the input shape that triggers the problem (synthetic
data only, please) and the output you saw. We acknowledge within
three working days and aim to fix masking bugs in the next release.

Do not open a public issue for a leak, and do not attach real identifiers to any report.

## Supported versions

Only the latest release on PyPI receives fixes.

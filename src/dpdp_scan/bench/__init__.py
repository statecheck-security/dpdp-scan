"""Benchmark: precision and recall per detector on a labelled synthetic corpus.

The corpus is generated, never read from a file, so no real identifier can
end up in the repository. Positives are values that *are* the identifier
(checksums computed, handles from the known list) placed in the kinds of
context code has: a field assignment, a bare literal, a log line. Negatives
are the look-alikes each detector must refuse: wrong checksums, wrong holder
types, unknown handles, example domains, and the generic noise classes
(UUIDs, hashes, timestamps, order ids, random digit runs).

``python -m dpdp_scan.bench`` prints the table the README carries. Numbers
are reported as k/N with the misses named by class, so the README can say
"detects 198/200 Aadhaar positives; misses: bare value with ORD- prefix"
instead of "detects all Aadhaar numbers".
"""

from __future__ import annotations

import random
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from dpdp_scan.detectors import scan_text
from dpdp_scan.detectors.checksums import gstin_check_character, verhoeff_check_digit
from dpdp_scan.detectors.india import UPI_HANDLES

DEFAULT_SEED = 20261106
N_PER_CLASS = 200

# Contexts a positive can appear in. The first is the common case; the rest
# are harder. A positive counts as detected if the detector fires on the line
# at any confidence.
_POS_CONTEXTS = (
    "{field} = '{v}'",
    "'{v}'",
    "logger.info('kyc for %s', {v_q})",
    '{{"{field}": "{v}"}}',
    "# {field}: {v}",
)


@dataclass(slots=True)
class Sample:
    detector: str  # the detector expected to fire ("" for a pure negative)
    label: str  # class name for the report
    text: str
    positive: bool


@dataclass(slots=True)
class DetectorScore:
    detector: str
    tp: int = 0
    fn: int = 0
    fp: int = 0
    positives: int = 0
    negatives: int = 0
    missed: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    false_hits: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / self.positives if self.positives else 1.0


class Corpus:
    def __init__(self, seed: int = DEFAULT_SEED, n: int = N_PER_CLASS) -> None:
        self.rng = random.Random(seed)  # noqa: S311  (benchmark data, not security)
        self.n = n

    # ---- value generators (all synthetic) ----------------------------------

    def aadhaar(self) -> str:
        head = str(self.rng.randint(2, 9)) + "".join(self.rng.choices("0123456789", k=10))
        return head + verhoeff_check_digit(head)

    def aadhaar_bad_checksum(self) -> str:
        v = self.aadhaar()
        return v[:-1] + str((int(v[-1]) + self.rng.randint(1, 9)) % 10)

    def pan(self) -> str:
        return (
            "".join(self.rng.choices("ABCDEFGHJKLMNPQRSTUVWXYZ", k=3))
            + self.rng.choice("ABCFGHJLPT")
            + self.rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
            + "".join(self.rng.choices("0123456789", k=4))
            + self.rng.choice("ABCDEFGHJKLMNPQRSTUVWXYZ")
        )

    def pan_bad_holder(self) -> str:
        v = self.pan()
        return v[:3] + self.rng.choice("DEIKMNOQRSUVWXYZ") + v[4:]

    def gstin(self) -> str:
        first14 = f"{self.rng.randint(1, 37):02d}" + self.pan() + self.rng.choice("123456789") + "Z"
        return first14 + gstin_check_character(first14)

    def gstin_bad_check(self) -> str:
        v = self.gstin()
        alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return v[:-1] + alphabet[(alphabet.index(v[-1]) + self.rng.randint(1, 35)) % 36]

    def ifsc(self) -> str:
        return (
            "".join(self.rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=4))
            + "0"
            + "".join(self.rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=6))
        )

    def ifsc_bad_fifth(self) -> str:
        v = self.ifsc()
        return v[:4] + self.rng.choice("123456789") + v[5:]

    def upi(self) -> str:
        local = "".join(self.rng.choices("abcdefghijklmnopqrstuvwxyz", k=self.rng.randint(4, 10)))
        return f"{local}{self.rng.randint(1, 99)}@{self.rng.choice(sorted(UPI_HANDLES))}"

    def upi_unknown_handle(self) -> str:
        local = "".join(self.rng.choices("abcdefghijklmnopqrstuvwxyz", k=6))
        return f"{local}@{self.rng.choice(['gmail', 'yahoo', 'corp', 'mailer', 'internal'])}"

    def mobile(self) -> str:
        digits = self.rng.choice("6789") + "".join(self.rng.choices("0123456789", k=9))
        return self.rng.choice(
            [digits, f"+91 {digits[:5]} {digits[5:]}", f"+91-{digits}", f"0{digits}"]
        )

    def mobile_bad_first(self) -> str:
        return self.rng.choice("12345") + "".join(self.rng.choices("0123456789", k=9))

    def email(self) -> str:
        local = "".join(self.rng.choices("abcdefghijklmnopqrstuvwxyz", k=self.rng.randint(4, 9)))
        domain = "".join(self.rng.choices("abcdefghijklmnopqrstuvwxyz", k=self.rng.randint(4, 8)))
        return (
            f"{local}.{self.rng.randint(1, 99)}@{domain}.{self.rng.choice(['in', 'com', 'co.in'])}"
        )

    def email_example(self) -> str:
        domain = self.rng.choice(["example.com", "example.in", "test.com"])
        return f"user{self.rng.randint(1, 99)}@{domain}"

    def voter(self) -> str:
        return "".join(self.rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=3)) + "".join(
            self.rng.choices("0123456789", k=7)
        )

    def passport(self) -> str:
        return (
            self.rng.choice("ABCDEFGHJKLMNPRSTUVWY")
            + self.rng.choice("123456789")
            + "".join(self.rng.choices("0123456789", k=6))
        )

    def driving_licence(self) -> str:
        return (
            "".join(self.rng.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=2))
            + f"{self.rng.randint(1, 99):02d} "
            + str(self.rng.randint(1990, 2024))
            + "".join(self.rng.choices("0123456789", k=7))
        )

    # ---- noise ---------------------------------------------------------------

    def noise(self) -> list[tuple[str, str]]:
        r = self.rng
        out: list[tuple[str, str]] = []
        for _ in range(self.n):
            out.append(("uuid", str(uuid.UUID(int=r.getrandbits(128)))))
            out.append(("sha1", f"{r.getrandbits(160):040x}"))
            out.append(("epoch_ms", str(r.randint(1_600_000_000_000, 1_800_000_000_000))))
            out.append(
                (
                    "iso_datetime",
                    f"2026-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}"
                    f"T{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:00Z",
                )
            )
            out.append(("order_id_prefixed", f"ORD-{r.randint(10**11, 10**12 - 1)}"))
            out.append(("random_12_digits", str(r.randint(2 * 10**11, 10**12 - 1))))
            out.append(("random_10_digits", str(r.randint(10**9, 10**10 - 1))))
            out.append(("card_16_grouped", " ".join(str(r.randint(1000, 9999)) for _ in range(4))))
            out.append(
                (
                    "version_and_port",
                    f"v{r.randint(1, 9)}.{r.randint(0, 30)} on port {r.randint(1024, 65535)}",
                )
            )
            out.append(("sku", f"SKU{r.randint(10**7, 10**8 - 1)}X"))
        return out

    # ---- assembly ------------------------------------------------------------

    def build(self) -> list[Sample]:
        samples: list[Sample] = []
        positives = {
            "in_aadhaar": ("aadhaar_no", self.aadhaar),
            "in_pan": ("pan_number", self.pan),
            "in_gstin": ("gstin", self.gstin),
            "in_ifsc": ("ifsc_code", self.ifsc),
            "in_upi": ("upi_id", self.upi),
            "in_mobile": ("mobile", self.mobile),
            "email": ("email", self.email),
            "in_voter_epic": ("voter_id", self.voter),
            "in_passport": ("passport_no", self.passport),
            "in_driving_licence": ("dl_no", self.driving_licence),
        }
        for det, (fld, gen) in positives.items():
            for i in range(self.n):
                ctx = _POS_CONTEXTS[i % len(_POS_CONTEXTS)]
                v = gen()
                text = ctx.format(field=fld, v=v, v_q=repr(v))
                samples.append(
                    Sample(det, f"{det}:{ctx.split('{')[0].strip() or 'bare'}", text, True)
                )
        negatives = {
            "in_aadhaar": ("aadhaar_bad_checksum", self.aadhaar_bad_checksum),
            "in_pan": ("pan_bad_holder_type", self.pan_bad_holder),
            "in_gstin": ("gstin_bad_check_char", self.gstin_bad_check),
            "in_ifsc": ("ifsc_nonzero_fifth", self.ifsc_bad_fifth),
            "in_upi": ("upi_unknown_handle", self.upi_unknown_handle),
            "in_mobile": ("mobile_first_digit_1_5", self.mobile_bad_first),
            "email": ("email_example_domain", self.email_example),
        }
        for det, (label, gen) in negatives.items():
            for _ in range(self.n):
                samples.append(Sample(det, label, f"value = '{gen()}'", False))
        for label, v in self.noise():
            samples.append(Sample("", label, v, False))
        return samples


def run(seed: int = DEFAULT_SEED, n: int = N_PER_CLASS) -> dict[str, DetectorScore]:
    samples = Corpus(seed, n).build()
    scores: dict[str, DetectorScore] = {}

    def score(det: str) -> DetectorScore:
        return scores.setdefault(det, DetectorScore(det))

    for s in samples:
        fired = {f.detector_id for f in scan_text(s.text, "bench.txt")}
        if s.positive:
            sc = score(s.detector)
            sc.positives += 1
            if s.detector in fired:
                sc.tp += 1
            else:
                sc.fn += 1
                sc.missed[s.label] += 1
        else:
            if s.detector:
                score(s.detector).negatives += 1
            for det in fired:
                sc = score(det)
                sc.fp += 1
                sc.false_hits[s.label] += 1
    return dict(sorted(scores.items()))


def markdown(scores: dict[str, DetectorScore], *, date: str = "", commit: str = "") -> str:
    lines = []
    header = "Precision and recall on the synthetic benchmark"
    if date or commit:
        header += f" ({date}{', ' if date and commit else ''}{commit})"
    lines += [
        f"**{header}.** `python -m dpdp_scan.bench`, seed {DEFAULT_SEED}, {N_PER_CLASS} per class.",
        "",
    ]
    lines += [
        "| Detector | Recall (found / positives) | Precision (true / fired) "
        "| Misses | False hits |",
        "|---|---:|---:|---|---|",
    ]
    for det, sc in scores.items():
        missed = (
            ", ".join(f"{k.split(':', 1)[-1]} {v}" for k, v in sorted(sc.missed.items())) or "none"
        )
        false_hits = ", ".join(f"{k} {v}" for k, v in sorted(sc.false_hits.items())) or "none"
        lines.append(
            f"| `{det}` | {sc.tp}/{sc.positives} ({sc.recall:.0%}) | "
            f"{sc.tp}/{sc.tp + sc.fp} ({sc.precision:.0%}) | {missed} | {false_hits} |"
        )
    lines += [
        "",
        "Recall counts a positive as found at any confidence. Precision counts every firing on a "
        "negative as a false hit, including the ones the detector itself marks LOW. The random "
        "12-digit class is the irreducible Verhoeff floor: about one in ten passes the checksum.",
    ]
    return "\n".join(lines)

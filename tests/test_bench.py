from dpdp_scan.bench import Corpus, markdown, run
from dpdp_scan.bench.__main__ import main
from dpdp_scan.detectors.checksums import gstin_checksum_valid, verhoeff_valid

# Floors the benchmark must keep. Raise them when the detectors improve; never
# lower them silently.
MIN_RECALL = {
    "in_aadhaar": 0.95,
    "in_pan": 0.95,
    "in_gstin": 0.95,
    "in_ifsc": 0.95,
    "in_upi": 0.95,
    "in_mobile": 0.95,
    "email": 0.95,
    "in_voter_epic": 0.95,
    "in_passport": 0.95,
    "in_driving_licence": 0.95,
}
MIN_PRECISION = {
    "in_aadhaar": 0.80,  # the Verhoeff floor: random 12-digit and ORD- prefixed noise
    "in_pan": 0.97,
    "in_gstin": 0.97,
    "in_ifsc": 0.97,
    "in_upi": 0.97,
    "in_mobile": 0.65,  # shape only; random 10-digit noise is the cost
    "email": 0.97,
    "in_voter_epic": 0.97,
    "in_passport": 0.90,
    "in_driving_licence": 0.97,
}


def test_corpus_positives_are_valid_and_negatives_are_not() -> None:
    c = Corpus(1, 50)
    for _ in range(50):
        assert verhoeff_valid(c.aadhaar()) and not verhoeff_valid(c.aadhaar_bad_checksum())
        assert gstin_checksum_valid(c.gstin()) and not gstin_checksum_valid(c.gstin_bad_check())
        assert c.pan()[3] in "ABCFGHJLPT" and c.pan_bad_holder()[3] not in "ABCFGHJLPT"
        assert c.ifsc()[4] == "0" and c.ifsc_bad_fifth()[4] != "0"


def test_corpus_is_deterministic() -> None:
    a = [s.text for s in Corpus(7, 5).build()]
    b = [s.text for s in Corpus(7, 5).build()]
    assert a == b and len(a) == 10 * 5 + 7 * 5 + 10 * 5


def test_benchmark_floors() -> None:
    scores = run(n=100)
    assert set(MIN_RECALL) <= set(scores)
    for det, floor in MIN_RECALL.items():
        assert scores[det].recall >= floor, (det, scores[det].recall, dict(scores[det].missed))
    for det, floor in MIN_PRECISION.items():
        assert scores[det].precision >= floor, (
            det,
            scores[det].precision,
            dict(scores[det].false_hits),
        )
    # No detector fires on the pure-noise classes except the two documented floors.
    for det, sc in scores.items():
        for label in sc.false_hits:
            assert label in {
                "random_12_digits",
                "random_10_digits",
                "order_id_prefixed",
            } or label.startswith(
                ("aadhaar_", "pan_", "gstin_", "ifsc_", "upi_", "mobile_", "email_")
            ), (det, label)


def test_markdown_and_cli(capsys) -> None:
    md = markdown(run(n=20), date="2026-11-06", commit="abc1234")
    assert md.startswith("**Precision and recall") and "| `in_aadhaar` |" in md and "abc1234" in md
    assert main(["--n", "10"]) == 0
    assert "| Detector |" in capsys.readouterr().out
    assert main(["--n", "10", "--json"]) == 0
    assert '"in_pan"' in capsys.readouterr().out

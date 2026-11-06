"""``python -m dpdp_scan.bench [--seed N] [--n N] [--date D] [--commit C] [--json]``"""

from __future__ import annotations

import argparse
import json
import sys

from dpdp_scan.bench import DEFAULT_SEED, N_PER_CLASS, markdown, run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m dpdp_scan.bench")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--n", type=int, default=N_PER_CLASS, help="samples per class")
    parser.add_argument("--date", default="")
    parser.add_argument("--commit", default="")
    parser.add_argument("--json", action="store_true", help="machine-readable scores")
    args = parser.parse_args(argv)
    scores = run(args.seed, args.n)
    if args.json:
        out = {
            det: {
                "tp": sc.tp,
                "fn": sc.fn,
                "fp": sc.fp,
                "positives": sc.positives,
                "negatives": sc.negatives,
                "precision": round(sc.precision, 4),
                "recall": round(sc.recall, 4),
                "missed": dict(sc.missed),
                "false_hits": dict(sc.false_hits),
            }
            for det, sc in scores.items()
        }
        print(json.dumps(out, indent=2))
    else:
        print(markdown(scores, date=args.date, commit=args.commit))
    return 0


if __name__ == "__main__":
    sys.exit(main())

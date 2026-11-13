"""Set aside whole groups as an evaluation holdout before any training.

A group goes to the holdout when a hash of its id falls below the requested
fraction.  The assignment depends only on the group id and the seed, never on
labels, model output or the other rows, so

* it cannot be tuned towards a result,
* re-running it gives the same split, and
* adding new mail later never moves an existing group to the other side.

The holdout must not be used for feature design, model selection or threshold
choice.  ``promote_ml_verdict.py`` logs every evaluation made on it.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


def in_holdout(group_id: str, fraction: float, seed: str) -> bool:
    digest = hashlib.sha256(f"{seed}\n{group_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2 ** 64 < fraction


def split_rows(rows: list[dict], fraction: float, seed: str) -> tuple[list[dict], list[dict]]:
    if not 0 < fraction < 1:
        raise ValueError("fraction must be between 0 and 1")
    train, holdout = [], []
    for index, row in enumerate(rows, 1):
        group = str(row.get("group_id") or "").strip()
        if not group or row.get("label") not in (0, 1):
            raise ValueError(f"row {index}: group_id and a 0/1 label are required")
        target = holdout if in_holdout(group, fraction, seed) else train
        target.append({**row, "split": "test" if target is holdout else "train"})
    return train, holdout


def summarize(rows: list[dict]) -> dict:
    return {"rows": len(rows), "groups": len({str(row["group_id"]) for row in rows}),
            "labels": {str(key): value for key, value in sorted(Counter(row["label"] for row in rows).items())}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("train_output", type=Path)
    parser.add_argument("holdout_output", type=Path)
    parser.add_argument("--fraction", type=float, default=0.2, help="share of groups set aside (default 0.2)")
    parser.add_argument("--seed", default="dise-holdout-v1")
    args = parser.parse_args()
    base = args.manifest.resolve().parent
    rows = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    for row in rows:  # keep paths valid wherever the outputs are written
        for key in ("eml", "analysis_result"):
            if row.get(key):
                path = Path(row[key])
                row[key] = str((path if path.is_absolute() else base / path).resolve())
    train, holdout = split_rows(rows, args.fraction, args.seed)
    report = {"seed": args.seed, "fraction": args.fraction, "train": summarize(train), "holdout": summarize(holdout)}
    for name, part in (("train", train), ("holdout", holdout)):
        if set(report[name]["labels"]) != {"0", "1"}:
            raise SystemExit(f"{name} split does not contain both labels: {report[name]}. "
                             "Collect more groups or change --seed before any training has used the data.")
    for path, part in ((args.train_output, train), (args.holdout_output, holdout)):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in part),
                        encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

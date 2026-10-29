"""Combine the original corpus with an independently generated augmentation set."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter, defaultdict
from pathlib import Path


def read_rows(path: Path) -> list[dict]:
    base = path.resolve().parent
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    for index, row in enumerate(rows, 1):
        missing = {"eml", "label", "split", "group_id"} - row.keys()
        if missing:
            raise ValueError(f"{path}:{index}: missing {sorted(missing)}")
        eml = Path(row["eml"])
        eml = eml if eml.is_absolute() else base / eml
        row = dict(row)
        row["eml"] = str(eml.resolve())
        rows[index - 1] = row
    return rows


def validate(rows: list[dict], expected_rows: int) -> dict:
    if len(rows) != expected_rows:
        raise ValueError(f"expected {expected_rows} rows, got {len(rows)}")
    paths: set[str] = set()
    hashes: set[str] = set()
    group_splits: dict[str, set[str]] = defaultdict(set)
    group_labels: dict[str, set[int]] = defaultdict(set)
    labels: Counter[int] = Counter()
    splits: Counter[str] = Counter()
    for index, row in enumerate(rows, 1):
        path = Path(row["eml"])
        if not path.is_file():
            raise ValueError(f"row {index}: EML does not exist: {path}")
        canonical = str(path).casefold()
        if canonical in paths:
            raise ValueError(f"row {index}: duplicate path: {path}")
        paths.add(canonical)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in hashes:
            raise ValueError(f"row {index}: duplicate EML bytes: {path}")
        hashes.add(digest)
        label = int(row["label"])
        split = str(row["split"])
        group = str(row["group_id"])
        if label not in (0, 1) or split not in {"train", "validation", "test"} or not group:
            raise ValueError(f"row {index}: invalid label, split, or group")
        labels[label] += 1
        splits[split] += 1
        group_splits[group].add(split)
        group_labels[group].add(label)
    leaking = sorted(group for group, values in group_splits.items() if len(values) != 1)
    if leaking:
        raise ValueError(f"groups cross publisher splits: {leaking[:5]}")
    mixed = sorted(group for group, values in group_labels.items() if len(values) != 1)
    return {
        "rows": len(rows),
        "labels": {str(key): value for key, value in sorted(labels.items())},
        "splits": dict(sorted(splits.items())),
        "groups": len(group_splits),
        "duplicate_paths": 0,
        "duplicate_sha256": 0,
        "group_split_leakage": 0,
        # The original corpus intentionally puts both labels in a scenario
        # group so that group CV holds the complete scenario out together.
        "mixed_label_groups": len(mixed),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("original", type=Path)
    parser.add_argument("augmentation", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--expected-original", type=int, default=10_000)
    parser.add_argument("--expected-augmentation", type=int, default=1_000)
    args = parser.parse_args()
    original = read_rows(args.original)
    augmentation = read_rows(args.augmentation)
    if len(original) != args.expected_original:
        raise ValueError(f"original row count is {len(original)}, expected {args.expected_original}")
    if len(augmentation) != args.expected_augmentation:
        raise ValueError(f"augmentation row count is {len(augmentation)}, expected {args.expected_augmentation}")
    rows = original + augmentation
    report = validate(rows, args.expected_original + args.expected_augmentation)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    output_base = args.output.resolve().parent
    portable_rows = []
    for row in rows:
        portable = dict(row)
        portable["eml"] = Path(os.path.relpath(row["eml"], output_base)).as_posix()
        portable_rows.append(portable)
    content = "\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":"))
                         for row in portable_rows) + "\n"
    args.output.write_text(content, encoding="utf-8")
    report["manifest_sha256"] = hashlib.sha256(content.encode("utf-8")).hexdigest()
    report["original_rows"] = len(original)
    report["augmentation_rows"] = len(augmentation)
    report["path_mode"] = "manifest_relative_posix"
    report_path = args.output.with_suffix(".report.json")
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({**report, "output": str(args.output)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

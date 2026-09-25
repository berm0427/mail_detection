"""Safely unpack Korean Synthetic Phishing Email Dataset v1 for model training.

The generated manifest contains only paths, labels, the publisher-provided split,
and scenario groups. Dataset metadata is deliberately not copied into model
features because several fields reveal the label directly.
"""
from __future__ import annotations

import argparse
import io
import json
import zipfile
from pathlib import Path, PurePosixPath


EXPECTED_ROWS = 10_000


def safe_name(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe archive member: {name!r}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(args.archive) as outer:
        for info in outer.infolist():
            safe_name(info.filename)
            if info.flag_bits & 1:
                raise ValueError("encrypted archive members are not supported")
        jsonl_name = next(n for n in outer.namelist() if n.endswith(".jsonl"))
        eml_zip_name = next(n for n in outer.namelist() if n.endswith("_eml.zip"))
        metadata = [json.loads(line) for line in outer.read(jsonl_name).decode("utf-8").splitlines() if line.strip()]
        nested_bytes = outer.read(eml_zip_name)

    if len(metadata) != EXPECTED_ROWS:
        raise ValueError(f"expected {EXPECTED_ROWS} metadata rows, got {len(metadata)}")
    by_id = {str(row["id"]): row for row in metadata}
    if len(by_id) != EXPECTED_ROWS:
        raise ValueError("duplicate dataset IDs")

    eml_root = args.output / "eml"
    eml_root.mkdir(exist_ok=True)
    extracted = {}
    with zipfile.ZipFile(io.BytesIO(nested_bytes)) as nested:
        for info in nested.infolist():
            path = safe_name(info.filename)
            if info.is_dir():
                continue
            if path.suffix.lower() != ".eml":
                raise ValueError(f"unexpected nested file: {info.filename!r}")
            message_id = path.stem
            if message_id not in by_id or message_id in extracted:
                raise ValueError(f"unknown or duplicate EML ID: {message_id}")
            destination = eml_root / f"{message_id}.eml"
            destination.write_bytes(nested.read(info))
            extracted[message_id] = destination

    if set(extracted) != set(by_id):
        raise ValueError("metadata and EML IDs do not match")
    unexpected = {p.stem for p in eml_root.glob("*.eml")} - set(by_id)
    if unexpected:
        raise ValueError(f"output contains unexpected EML files: {len(unexpected)}")

    # A single empty result makes the first experiment text-only. This avoids
    # teaching the model synthetic SPF/DKIM/domain-generation shortcuts.
    empty_result = args.output / "empty_analysis_result.json"
    empty_result.write_text("{}\n", encoding="utf-8")
    manifest = args.output / "manifest_text_only.jsonl"
    split_counts = {"train": 0, "validation": 0, "test": 0}
    label_counts = {0: 0, 1: 0}
    with manifest.open("w", encoding="utf-8", newline="\n") as stream:
        for message_id in sorted(by_id):
            row = by_id[message_id]
            label = int(row["label_id"])
            split = str(row["split"])
            scenario = str(row["scenario_id"])
            if label not in (0, 1) or split not in split_counts or not scenario:
                raise ValueError(f"invalid metadata for {message_id}")
            item = {
                "eml": f"eml/{message_id}.eml",
                "analysis_result": empty_result.name,
                "label": label,
                "split": split,
                "group_id": scenario,
            }
            stream.write(json.dumps(item, ensure_ascii=False) + "\n")
            split_counts[split] += 1
            label_counts[label] += 1

    report = {
        "rows": len(metadata),
        "split_counts": split_counts,
        "label_counts": {str(k): v for k, v in label_counts.items()},
        "manifest": str(manifest),
        "feature_policy": "EML subject/body text only; label-revealing metadata and synthetic authentication/domain evidence excluded",
    }
    (args.output / "PREPARATION_REPORT.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

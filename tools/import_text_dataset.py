"""Turn a labelled text-only dataset (JSON Lines) into EML files and a manifest.

Public phishing corpora are often published as subject/body text with a label,
not as EML.  This tool writes one minimal EML per row (Subject and a plain-text
body, nothing else) and a manifest the retraining tools accept.

What such data can and cannot teach:

* It has no real headers, links-in-HTML or attachments, so only the semantic
  (text) model can learn from it.  Structural features stay at zero.
* The label must mean the same thing as in the rest of the training data.
  ``--label-definition`` is recorded on every row; do not mix "spam" data into
  a phishing model.
* Without ``--group-field`` every row becomes its own group.  Near-duplicate
  texts can then fall on both sides of a split; only exact duplicates are
  removed here.

No header is written that names the label, the split or the source.
"""
from __future__ import annotations

import argparse
from email.message import EmailMessage
import json
from pathlib import Path
import re
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_analyzer.mail_identity import mail_digest  # noqa: E402


def build_eml(title: str, text: str) -> bytes:
    message = EmailMessage()
    subject = " ".join(str(title or "").split())[:300]
    if subject:
        message["Subject"] = subject
    message.set_content(str(text or ""))
    return message.as_bytes()


def convert_rows(rows: list[dict], *, source: str, text_field: str, title_field: str | None, label_field: str,
                 positive: set[str], negative: set[str], label_definition: str,
                 group_field: str | None = None) -> tuple[list[dict], dict]:
    """Return (items, report); each item has the EML bytes and its manifest row without paths."""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", source):
        raise ValueError("source must be lowercase letters, digits, '-' or '_'")
    if positive & negative:
        raise ValueError("a label value cannot be both positive and negative")
    items, seen, duplicates, empty = [], {}, 0, 0
    conflicting = set()  # same text labelled both ways: neither label can be trusted
    for index, row in enumerate(rows, 1):
        value = str(row.get(label_field))
        if value not in positive | negative:
            raise ValueError(f"row {index}: label {value!r} is neither a positive nor a negative value")
        text = str(row.get(text_field) or "").strip()
        title = str(row.get(title_field) or "").strip() if title_field else ""
        if not text and not title:
            empty += 1
            continue
        raw = build_eml(title, text)
        digest = mail_digest(raw)
        label = int(value in positive)
        if digest in seen:
            if seen[digest] != label:
                conflicting.add(digest)
            duplicates += 1
            continue
        seen[digest] = label
        group = str(row.get(group_field) or "").strip() if group_field else ""
        if group_field and not group:
            raise ValueError(f"row {index}: empty {group_field!r}")
        items.append({"raw": raw, "row": {
            "eml": f"{source}-{len(items) + 1:06d}.eml", "label": label, "split": "train",
            "group_id": f"{source}:{group}" if group else f"{source}:{digest[:16]}",
            "sha256": digest, "source": source, "text_only": True, "label_definition": label_definition}})
    # Drop every copy of a text that carries contradictory labels, then renumber.
    items = [item for item in items if item["row"]["sha256"] not in conflicting]
    for number, item in enumerate(items, 1):
        item["row"]["eml"] = f"{source}-{number:06d}.eml"
    labels = [item["row"]["label"] for item in items]
    report = {"source": source, "label_definition": label_definition, "input_rows": len(rows),
              "written": len(items), "exact_duplicates_skipped": duplicates, "empty_skipped": empty,
              "conflicting_label_texts_dropped": len(conflicting),
              "labels": {"0": labels.count(0), "1": labels.count(1)},
              "groups": len({item["row"]["group_id"] for item in items}),
              "grouping": group_field or "one group per row (near-duplicates are not detected)"}
    return items, report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="JSON Lines file, one object per row")
    parser.add_argument("output_dir", type=Path, help="new folder for the EML files and manifest.jsonl")
    parser.add_argument("--source", required=True, help="short name for this dataset, e.g. hf-korean-samples")
    parser.add_argument("--label-definition", required=True, choices=("phishing", "spam", "other"),
                        help="what the positive label means in this dataset")
    parser.add_argument("--text-field", default="text")
    parser.add_argument("--title-field")
    parser.add_argument("--label-field", default="label")
    parser.add_argument("--positive-value", action="append", required=True)
    parser.add_argument("--negative-value", action="append", required=True)
    parser.add_argument("--group-field", help="field naming the campaign/source of each row, if the data has one")
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise SystemExit(f"{args.output_dir} is not empty; choose a new folder")
    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    items, report = convert_rows(
        rows, source=args.source, text_field=args.text_field, title_field=args.title_field,
        label_field=args.label_field, positive=set(args.positive_value), negative=set(args.negative_value),
        label_definition=args.label_definition, group_field=args.group_field)
    if not items:
        raise SystemExit("no rows were written")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for item in items:
        (args.output_dir / item["row"]["eml"]).write_bytes(item["raw"])
    (args.output_dir / "manifest.jsonl").write_text(
        "".join(json.dumps(item["row"], ensure_ascii=False, separators=(",", ":")) + "\n" for item in items),
        encoding="utf-8")
    (args.output_dir / "IMPORT_REPORT.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

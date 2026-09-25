"""Build a leakage-minimal training manifest from labeled JSONL and EML files."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=Path)
    parser.add_argument("eml_directory", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.metadata.read_text(encoding="utf-8").splitlines() if line.strip()]
    ids = set(); groups = {}; counts = {"train": 0, "validation": 0, "test": 0}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    empty = args.output.parent / "empty_analysis_result.json"
    empty.write_text("{}\n", encoding="utf-8")
    with args.output.open("w", encoding="utf-8", newline="\n") as stream:
        for line_no, row in enumerate(rows, 1):
            message_id = str(row.get("id", "")); split = str(row.get("split", ""))
            group = str(row.get("scenario_id", "")); label = row.get("label_id")
            if not message_id or message_id in ids or split not in counts or not group or label not in (0, 1):
                raise ValueError(f"invalid metadata row {line_no}")
            ids.add(message_id); groups.setdefault(group, set()).add(split); counts[split] += 1
            eml = (args.eml_directory / f"{message_id}.eml").resolve()
            if not eml.is_file():
                raise FileNotFoundError(eml)
            item = {"eml": str(eml), "analysis_result": str(empty.resolve()),
                    "label": int(label), "split": split, "group_id": group}
            stream.write(json.dumps(item, ensure_ascii=False) + "\n")
    leaked = [group for group, splits in groups.items() if len(splits) != 1]
    if leaked:
        args.output.unlink(missing_ok=True)
        raise ValueError(f"scenario groups cross splits: {len(leaked)}")
    print(json.dumps({"rows": len(rows), "splits": counts, "groups": len(groups),
                      "manifest": str(args.output)}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

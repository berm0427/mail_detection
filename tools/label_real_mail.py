"""Register one labelled real email for later retraining.

Run this soon after analysing the mail in the GUI, and pass the saved
``final_analysis_result.json`` of that session.  The saved result is what the
trainer will use, so observations of a destination that later disappears are
kept.  Nothing is copied or uploaded; the manifest stores local paths and lives
in ``mail_body/labelled/``, which is excluded from Git.

``--group`` must identify the campaign, sender organisation or template the
mail belongs to.  Mails of one group are always kept on the same side of every
train/evaluation split, so a careless group id leaks near-duplicates.

``--observation-label`` records whether a single engine observation was right,
for example ``attachment_antivirus_report=false_positive``.  These labels are
stored for later analysis; the current trainer does not read them.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for entry in (PROJECT_ROOT, PROJECT_ROOT / "tools"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from extract_synthetic_evidence import check_saved_analysis  # noqa: E402
DEFAULT_MANIFEST = PROJECT_ROOT / "mail_body" / "labelled" / "real_manifest.jsonl"
OBSERVATION_VERDICTS = ("correct", "false_positive", "unknown")


def parse_observation_labels(items):
    labels = {}
    for item in items or ():
        name, separator, verdict = item.partition("=")
        if not separator or not name.strip() or verdict not in OBSERVATION_VERDICTS:
            raise ValueError(f"--observation-label must be ID={'|'.join(OBSERVATION_VERDICTS)}: {item!r}")
        labels[name.strip()] = verdict
    return labels


def build_row(eml: Path, label: int, group: str, analysis_result: Path | None, observation_labels: dict,
              note: str = "") -> dict:
    if label not in (0, 1):
        raise ValueError("label must be 0 (normal) or 1 (phishing)")
    if not group.strip():
        raise ValueError("group must not be empty")
    eml = eml.resolve()
    if not eml.is_file():
        raise ValueError(f"EML not found: {eml}")
    row = {"eml": str(eml), "label": label, "split": "train", "group_id": group.strip(),
           "sha256": hashlib.sha256(eml.read_bytes()).hexdigest(), "source": "real",
           "labelled_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
    if analysis_result is not None:
        analysis_result = analysis_result.resolve()
        saved = json.loads(analysis_result.read_text(encoding="utf-8"))
        try:
            check_saved_analysis(saved, eml.read_bytes(), str(analysis_result))
        except RuntimeError as error:
            raise ValueError(str(error)) from error
        row["analysis_result"] = str(analysis_result)
    if observation_labels:
        row["observation_labels"] = observation_labels
    if note:
        row["note"] = note
    return row


def append_row(manifest: Path, row: dict) -> None:
    existing = [json.loads(line) for line in manifest.read_text(encoding="utf-8").splitlines()
                if line.strip()] if manifest.is_file() else []
    if any(item.get("sha256") == row["sha256"] for item in existing):
        raise ValueError("this EML is already in the manifest (same SHA-256)")
    if any(Path(item["eml"]).stem == Path(row["eml"]).stem for item in existing):
        raise ValueError("another manifest row has the same file name; rename the EML so names stay unique")
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("eml", type=Path)
    parser.add_argument("--label", type=int, choices=(0, 1), required=True, help="0 normal, 1 phishing")
    parser.add_argument("--group", required=True, help="campaign / sender organisation / template id")
    parser.add_argument("--analysis-result", type=Path,
                        help="final_analysis_result.json saved when the mail was analysed")
    parser.add_argument("--observation-label", action="append", metavar="ID=VERDICT")
    parser.add_argument("--note", default="")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()
    row = build_row(args.eml, args.label, args.group, args.analysis_result,
                    parse_observation_labels(args.observation_label), args.note)
    append_row(args.manifest, row)
    print(json.dumps({"manifest": str(args.manifest), "added": row}, ensure_ascii=False, indent=2))
    if "analysis_result" not in row:
        print("NOTE: no --analysis-result given. The mail will be analysed again at training time; "
              "a destination that has disappeared by then cannot be observed.")


if __name__ == "__main__":
    main()

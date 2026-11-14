"""Score the installed semantic model on an external labelled manifest.

The mails are scored exactly as the GUI's semantic engine scores them
(including translation of foreign-language text).  Only the semantic model is
evaluated: text-only datasets carry no headers, links or attachments, so the
verdict model's structural features cannot be exercised with them.

This is a check, not a tuning loop.  Every run is appended to
``models/holdout_usage.jsonl`` under an id computed from the mails, so repeated
looks at the same external set stay visible.  A set that has been used to make
modelling decisions is a development set and must not be reported as an
independent test.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for entry in (PROJECT_ROOT, PROJECT_ROOT / "tools"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from email_analyzer.mail_identity import combined_digest, mail_digest, strip_label_headers  # noqa: E402


def summarize(pairs: list[tuple[int, int | None]]) -> dict:
    counts = {"rows": len(pairs),
              "tn": sum(y == 0 and p == 0 for y, p in pairs), "fp": sum(y == 0 and p == 1 for y, p in pairs),
              "fn": sum(y == 1 and p == 0 for y, p in pairs), "tp": sum(y == 1 and p == 1 for y, p in pairs),
              "unscored": sum(p is None for _, p in pairs)}
    scored = counts["rows"] - counts["unscored"]
    counts["accuracy_of_scored"] = round((counts["tn"] + counts["tp"]) / scored, 4) if scored else None
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifest", type=Path, help="manifest.jsonl with eml, label and optionally source")
    parser.add_argument("report", type=Path)
    parser.add_argument("--semantic-artifact", type=Path, help="default: the installed semantic model")
    args = parser.parse_args()

    from email_analyzer.engines.semantic_ml import SemanticMLEngine, preload_semantic_encoder
    config = json.loads((PROJECT_ROOT / "engine_config.json").read_text(encoding="utf-8"))
    resolve = lambda value: Path(value) if Path(value).is_absolute() else PROJECT_ROOT / value
    artifact = (args.semantic_artifact or resolve(config["semantic_ml_model"])).resolve()
    translation = resolve(config["translation_model"]) if config.get("translation_model") else None
    base = args.manifest.resolve().parent
    rows = [json.loads(line) for line in args.manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not rows:
        raise SystemExit("the manifest is empty")
    model = json.loads(artifact.read_text(encoding="utf-8"))
    # Read every mail first: the set's identity is known before anything is scored,
    # so the look is logged even if scoring stops half-way.
    mails = []
    for row in rows:
        path = Path(row["eml"])
        raw = (path if path.is_absolute() else base / path).read_bytes()
        mails.append((row, path.name, raw))
    set_id = combined_digest(mail_digest(raw) for _, _, raw in mails)
    usage_path = PROJECT_ROOT / "models" / "holdout_usage.jsonl"
    previous = 0
    if usage_path.is_file():
        previous = sum(json.loads(line).get("holdout_id") == set_id
                       for line in usage_path.read_text(encoding="utf-8").splitlines() if line.strip())
    evaluated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    usage = {"holdout_id": set_id, "rows": len(rows), "evaluated_at": evaluated_at,
             "candidate": model.get("model_id"), "status": "semantic_external_check_failed",
             "decision": None, "installed": False}
    by_source, wrong = {}, []
    try:
        preload_semantic_encoder(artifact)
        engine = SemanticMLEngine(artifact, translation)
        for row, name, raw in mails:
            cleaned, _ = strip_label_headers(raw)
            result = asdict(engine.analyze(BytesParser(policy=policy.default).parsebytes(cleaned)))
            label = int(row["label"])
            prediction = int(result["score"] >= 0.5) if result.get("status") == "ok" else None
            by_source.setdefault(str(row.get("source") or "unspecified"), []).append((label, prediction))
            if prediction is not None and prediction != label:
                wrong.append({"eml": name, "label": label, "score": round(result["score"], 4)})
        usage["status"] = "semantic_external_check"
    finally:
        with usage_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(usage, ensure_ascii=False) + "\n")
    report = {
        "kind": "semantic_external_check",
        "evaluated_at": evaluated_at,
        "semantic_model_id": model.get("model_id"), "manifest": str(args.manifest),
        "set_id": set_id, "previous_evaluations_on_this_set": previous,
        "label_definitions": sorted({str(row.get("label_definition") or "unspecified") for row in rows}),
        "overall": summarize([pair for pairs in by_source.values() for pair in pairs]),
        "by_source": {name: summarize(pairs) for name, pairs in sorted(by_source.items())},
        "note": "Semantic (text) model only. Not an estimate of end-to-end verdict performance.",
        "wrong": wrong,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("semantic_model_id", "overall", "by_source",
                                                     "previous_evaluations_on_this_set")},
                     ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

"""Compare a candidate verdict model with the installed one on a holdout.

Both models score the same held-out mail exactly as the GUI would: the
semantic engine reads the EML (including translation) and the verdict model
reads the saved structural observations.  The candidate is promoted only when,
on the holdout, it has

* no more false positives than the installed model,
* no more false negatives,
* no more unscored mails, and
* strictly fewer errors in total.

There is no tunable threshold in this rule.  The holdout must be disjoint from
the candidate's training data by group id and by EML content; this is checked.
Every evaluation is appended to ``models/holdout_usage.jsonl`` under an id
computed from the holdout mails themselves, so repeated looks at the same
holdout stay visible whatever tag or path is used.

Without ``--apply`` nothing is changed.  With ``--apply`` and a passing result
the candidate files are installed under ``models/``, a promotion record is
written and ``engine_config.json`` is pointed at them.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for entry in (PROJECT_ROOT, PROJECT_ROOT / "tools"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def check_disjoint(training_rows: list[dict], holdout_rows: list[dict]) -> None:
    """The holdout may share neither a group nor an identical EML with training."""
    shared_groups = {str(row["group_id"]) for row in training_rows} & {str(row["group_id"]) for row in holdout_rows}
    if shared_groups:
        raise ValueError(f"holdout shares groups with training: {sorted(shared_groups)[:5]}")
    digest = lambda row: hashlib.sha256(Path(row["eml"]).read_bytes()).hexdigest()
    holdout_digests = set()
    for row in holdout_rows:
        # The evidence must have been observed from the file that is scored now.
        if not row.get("eml_sha256"):
            raise ValueError("holdout evidence has no eml_sha256; re-extract it with the current tool")
        if digest(row) != row["eml_sha256"]:
            raise ValueError(f"holdout EML changed since its evidence was extracted: {row['eml']}")
        holdout_digests.add(row["eml_sha256"])
    shared_mail = {digest(row) for row in training_rows} & holdout_digests
    if shared_mail:
        raise ValueError(f"holdout shares {len(shared_mail)} identical EML file(s) with training")


def holdout_identity(holdout_rows: list[dict]) -> str:
    """Depends only on which mails are in the holdout, not on paths, order or tags."""
    joined = "\n".join(sorted(row["eml_sha256"] for row in holdout_rows))
    return hashlib.sha256(joined.encode("ascii")).hexdigest()


def count_outcomes(labels: list[int], predictions: list[int | None]) -> dict:
    """``None`` is a mail the model could not score (shown as 'inconclusive' in the GUI)."""
    pairs = list(zip(labels, predictions))
    return {
        "rows": len(pairs),
        "tn": sum(y == 0 and p == 0 for y, p in pairs), "fp": sum(y == 0 and p == 1 for y, p in pairs),
        "fn": sum(y == 1 and p == 0 for y, p in pairs), "tp": sum(y == 1 and p == 1 for y, p in pairs),
        "unscored": sum(p is None for _, p in pairs),
    }


def promotion_decision(candidate: dict, incumbent: dict | None) -> dict:
    """Pure rule: non-worse on every error type and strictly better in total."""
    if incumbent is None:
        return {"promote": False, "reason": "installed model could not be evaluated on this holdout; "
                                            "decide manually"}
    worse = [name for name in ("fp", "fn", "unscored") if candidate[name] > incumbent[name]]
    if worse:
        return {"promote": False, "reason": f"candidate is worse on: {', '.join(worse)}"}
    total = lambda counts: counts["fp"] + counts["fn"] + counts["unscored"]
    if total(candidate) >= total(incumbent):
        return {"promote": False, "reason": "candidate is not strictly better in total errors"}
    return {"promote": True, "reason": "no error type is worse and total errors are lower"}


def score_holdout(evidence: list[dict], semantic_artifact: Path, verdict_artifact: Path,
                  translation_model) -> tuple[dict, list[dict]]:
    from email_analyzer.engines.semantic_ml import SemanticMLEngine, preload_semantic_encoder
    from email_analyzer.ml_verdict import analyze_ml_verdict
    from extract_synthetic_evidence import strip_label_headers
    preload_semantic_encoder(semantic_artifact)
    engine = SemanticMLEngine(semantic_artifact, translation_model)
    labels, predictions, rows = [], [], []
    for row in evidence:
        cleaned, _ = strip_label_headers(Path(row["eml"]).read_bytes())
        semantic = asdict(engine.analyze(BytesParser(policy=policy.default).parsebytes(cleaned)))
        prediction, score = None, None
        if semantic.get("status") == "ok":
            result = dict(row["analysis"])
            result["engine_results"] = {**(result.get("engine_results") or {}), "semantic_ml": semantic}
            verdict = analyze_ml_verdict(result, verdict_artifact, require_promoted=False)
            prediction, score = verdict["prediction"], verdict["score"]
        labels.append(int(row["label"]))
        predictions.append(prediction)
        rows.append({"eml": Path(row["eml"]).name, "group_id": row["group_id"], "label": int(row["label"]),
                     "prediction": prediction, "score": score})
    return count_outcomes(labels, predictions), rows


def install(candidate_semantic: Path, candidate_verdict: Path, record: dict, models_dir: Path,
            config_path: Path) -> dict:
    semantic = json.loads(candidate_semantic.read_text(encoding="utf-8"))
    verdict = json.loads(candidate_verdict.read_text(encoding="utf-8"))
    verdict["promoted_to_gui"] = True
    targets = {"semantic_ml_model": models_dir / f"{semantic['model_id']}.json",
               "ml_verdict_model": models_dir / f"{verdict['model_id']}.json"}
    record_path = models_dir / f"{verdict['model_id']}-promotion.json"
    for path in (*targets.values(), record_path):
        if path.exists():
            raise ValueError(f"refusing to overwrite an installed file: {path}")
    config = json.loads(config_path.read_text(encoding="utf-8"))
    relative = lambda path: path.relative_to(config_path.parent).as_posix()
    config.update({key: relative(path) for key, path in targets.items()})
    outputs = {"installed": {key: str(path) for key, path in targets.items()}, "promotion_record": str(record_path)}
    dump = lambda payload: json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    # Stage everything first; the config is switched last, so the GUI never
    # points at a model that is not completely written.  Undo on any failure.
    writes = [(targets["semantic_ml_model"], dump(semantic)), (targets["ml_verdict_model"], dump(verdict)),
              (record_path, dump({**record, **outputs})), (config_path, dump(config))]
    staged = []
    try:
        for path, content in writes:
            temporary = path.with_name(path.name + ".installing")
            temporary.write_text(content, encoding="utf-8")
            staged.append((temporary, path))
        placed = []
        try:
            for temporary, path in staged:
                os.replace(temporary, path)
                placed.append(path)
        except OSError:
            for path in placed:
                if path != config_path:
                    path.unlink(missing_ok=True)
            raise
    finally:
        for temporary, _ in staged:
            temporary.unlink(missing_ok=True)
    return outputs


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--candidate-semantic", type=Path, required=True)
    parser.add_argument("--candidate-verdict", type=Path, required=True)
    parser.add_argument("--training-manifest", type=Path, required=True)
    parser.add_argument("--holdout-evidence", type=Path, required=True,
                        help="output of extract_synthetic_evidence.py for the holdout manifest")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--apply", action="store_true", help="install the candidate when the rule passes")
    args = parser.parse_args()

    config_path = PROJECT_ROOT / "engine_config.json"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    resolve = lambda value: (Path(value) if Path(value).is_absolute() else PROJECT_ROOT / value) if value else None
    candidate = json.loads(args.candidate_verdict.read_text(encoding="utf-8"))
    training_raw = args.training_manifest.read_bytes()
    training_sha = hashlib.sha256(training_raw).hexdigest()
    if (candidate.get("semantic_input") or {}).get("manifest_sha256") != training_sha:
        raise SystemExit("--training-manifest is not the manifest this candidate was trained on")
    training_base = args.training_manifest.resolve().parent
    training_rows = read_jsonl(args.training_manifest)
    for row in training_rows:
        path = Path(row["eml"])
        row["eml"] = str(path if path.is_absolute() else training_base / path)
    evidence = read_jsonl(args.holdout_evidence)
    if {int(row["label"]) for row in evidence} != {0, 1}:
        raise SystemExit("the holdout must contain both normal and phishing mail")
    check_disjoint(training_rows, evidence)

    translation = resolve(config.get("translation_model"))
    candidate_counts, candidate_rows = score_holdout(
        evidence, args.candidate_semantic.resolve(), args.candidate_verdict.resolve(), translation)
    incumbent_counts, incumbent_rows, incumbent_error = None, [], None
    try:
        incumbent_counts, incumbent_rows = score_holdout(
            evidence, resolve(config["semantic_ml_model"]), resolve(config["ml_verdict_model"]), translation)
    except (ValueError, KeyError, OSError) as exc:  # e.g. a feature-schema change
        incumbent_error = f"{type(exc).__name__}: {exc}"
    decision = promotion_decision(candidate_counts, incumbent_counts)

    usage_path = PROJECT_ROOT / "models" / "holdout_usage.jsonl"
    holdout_id = holdout_identity(evidence)
    previous_uses = sum(entry.get("holdout_id") == holdout_id for entry in read_jsonl(usage_path)) \
        if usage_path.is_file() else 0
    record = {
        "model_id": candidate["model_id"],
        "semantic_model_id": (candidate.get("semantic_input") or {}).get("model_id"),
        "evaluated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "promoted_to_gui": bool(decision["promote"] and args.apply),
        "decision": decision,
        "holdout": {"evidence": str(args.holdout_evidence), "rows": len(evidence),
                    "groups": len({str(row["group_id"]) for row in evidence}),
                    "holdout_id": holdout_id,
                    "disjoint_from_training": True, "previous_evaluations_on_this_holdout": previous_uses,
                    "note": "The installed model may have been trained on mail in this holdout; "
                            "that can only favour the installed model."},
        "candidate": candidate_counts,
        "installed": {"semantic": config.get("semantic_ml_model"), "verdict": config.get("ml_verdict_model"),
                      "counts": incumbent_counts, "error": incumbent_error},
        "candidate_untrained_features": candidate.get("untrained_features"),
        "candidate_limitations": candidate.get("limitations"),
        "predictions": {"candidate": candidate_rows, "installed": incumbent_rows},
    }
    with usage_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"holdout_id": holdout_id, "rows": len(evidence),
                                 "evaluated_at": record["evaluated_at"], "candidate": candidate["model_id"],
                                 "decision": decision}, ensure_ascii=False) + "\n")
    if decision["promote"] and args.apply:
        record.update(install(args.candidate_semantic.resolve(), args.candidate_verdict.resolve(),
                              record, PROJECT_ROOT / "models", config_path))
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: record[key] for key in ("model_id", "decision", "candidate", "promoted_to_gui")}
                     | {"installed": incumbent_counts, "installed_error": incumbent_error,
                        "previous_evaluations_on_this_holdout": previous_uses}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

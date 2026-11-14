"""Compare a candidate verdict model with the installed one on a holdout.

Both models score the same held-out mail exactly as the GUI would: the
semantic engine reads the EML (including translation) and the verdict model
reads the saved structural observations.  The candidate is promoted only when,
on the holdout, it has

* no more false positives than the installed model,
* no more false negatives,
* no more unscored mails, and
* strictly fewer errors in total.

There is no tunable threshold in this rule.

Checks made before anything is scored:

* the training manifest is the one the candidate was trained on, and its mails
  are byte-for-byte (label headers aside) the mails the candidate was trained on;
* the semantic artifact is byte-for-byte the one written with the candidate;
* every holdout evidence row was observed from the mail that is scored now;
* the holdout shares no group id and no mail content with the training data;
* with ``--apply``, none of the files to be installed exists yet.

Every evaluation is appended to ``models/holdout_usage.jsonl`` under an id
computed from the holdout mails themselves, so repeated looks at the same
holdout stay visible whatever tag or path is used.

Without ``--apply`` nothing is installed.  With ``--apply`` and a passing result
the candidate files are written under ``models/``, a promotion record is
written and ``engine_config.json`` is switched last; any failure restores the
previous state.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
import json
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for entry in (PROJECT_ROOT, PROJECT_ROOT / "tools"):
    if str(entry) not in sys.path:
        sys.path.insert(0, str(entry))

from email_analyzer.mail_identity import combined_digest, mail_digest, strip_label_headers  # noqa: E402


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def file_digest(row: dict) -> str:
    return mail_digest(Path(row["eml"]).read_bytes())


def check_disjoint(training_rows: list[dict], holdout_rows: list[dict]) -> set[str]:
    """The holdout may share neither a group nor a mail with training.

    Returns the digests of the training mails as they are on disk now.
    """
    shared_groups = {str(row["group_id"]) for row in training_rows} & {str(row["group_id"]) for row in holdout_rows}
    if shared_groups:
        raise ValueError(f"holdout shares groups with training: {sorted(shared_groups)[:5]}")
    holdout_digests = set()
    for row in holdout_rows:
        # The evidence must have been observed from the mail that is scored now.
        if not row.get("eml_sha256"):
            raise ValueError("holdout evidence has no eml_sha256; re-extract it with the current tool")
        if file_digest(row) != row["eml_sha256"]:
            raise ValueError(f"holdout EML changed since its evidence was extracted: {row['eml']}")
        holdout_digests.add(row["eml_sha256"])
    training_digests = {file_digest(row) for row in training_rows}
    shared_mail = training_digests & holdout_digests
    if shared_mail:
        raise ValueError(f"holdout shares {len(shared_mail)} mail(s) with training (same content)")
    return training_digests


def holdout_identity(holdout_rows: list[dict]) -> str:
    """Depends only on which mails are in the holdout, not on paths, order or tags."""
    return combined_digest(row["eml_sha256"] for row in holdout_rows)


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
        return {"promote": False, "reason": "installed model cannot score the current feature schema; "
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


def install_targets(candidate_semantic: Path, candidate_verdict: Path, models_dir: Path) -> dict:
    semantic = json.loads(candidate_semantic.read_text(encoding="utf-8"))
    verdict = json.loads(candidate_verdict.read_text(encoding="utf-8"))
    return {"semantic_ml_model": models_dir / f"{semantic['model_id']}.json",
            "ml_verdict_model": models_dir / f"{verdict['model_id']}.json",
            "promotion_record": models_dir / f"{verdict['model_id']}-promotion.json"}


def check_install_targets_free(targets: dict) -> None:
    for path in targets.values():
        if path.exists():
            raise ValueError(f"refusing to overwrite an installed file: {path}")


def install(candidate_semantic: Path, candidate_verdict: Path, record: dict, models_dir: Path,
            config_path: Path) -> dict:
    """Install the candidate; on any failure leave models/ and the config as they were."""
    semantic_bytes = candidate_semantic.read_bytes()  # installed unchanged: these bytes were verified
    verdict = json.loads(candidate_verdict.read_text(encoding="utf-8"))
    verdict["promoted_to_gui"] = True
    targets = install_targets(candidate_semantic, candidate_verdict, models_dir)
    original_config = config_path.read_bytes()
    config = json.loads(original_config.decode("utf-8"))
    relative = lambda path: path.relative_to(config_path.parent).as_posix()
    config.update({key: relative(targets[key]) for key in ("semantic_ml_model", "ml_verdict_model")})
    outputs = {"installed": {key: str(targets[key]) for key in ("semantic_ml_model", "ml_verdict_model")},
               "promotion_record": str(targets["promotion_record"])}
    dump = lambda payload: json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    new_files = [(targets["semantic_ml_model"], semantic_bytes),
                 (targets["ml_verdict_model"], dump(verdict).encode("utf-8")),
                 (targets["promotion_record"],
                  dump({**record, "promoted_to_gui": True, **outputs}).encode("utf-8"))]
    created, config_switched = [], False
    staged_config = config_path.with_name(f"{config_path.name}.{os.getpid()}.installing")
    backup_config = config_path.with_name(f"{config_path.name}.{os.getpid()}.restore")
    try:
        backup_config.write_bytes(original_config)  # prepared before anything changes
        for path, content in new_files:
            # Exclusive creation: an existing file is never overwritten, even in a race.
            with path.open("xb") as handle:
                created.append(path)
                handle.write(content)
        # The config is switched last and atomically, so the GUI never points
        # at a model that is not completely written.
        staged_config.write_text(dump(config), encoding="utf-8")
        os.replace(staged_config, config_path)
        config_switched = True
        json.loads(config_path.read_text(encoding="utf-8"))  # final read-back before reporting success
    except BaseException as error:
        if config_switched:
            try:
                os.replace(backup_config, config_path)  # atomic restore, never a truncated config
            except OSError as restore_error:
                # The config still names the new models: keep them so the GUI stays usable.
                raise RuntimeError(f"install failed ({error}) and the previous engine_config.json could not "
                                   f"be restored ({restore_error}); new model files were kept") from error
        for path in created:
            path.unlink(missing_ok=True)
        raise
    finally:
        staged_config.unlink(missing_ok=True)
        backup_config.unlink(missing_ok=True)
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

    from email_analyzer.ml_verdict import SchemaMismatchError
    import hashlib
    config_path = PROJECT_ROOT / "engine_config.json"
    models_dir = PROJECT_ROOT / "models"
    config = json.loads(config_path.read_text(encoding="utf-8"))
    resolve = lambda value: (Path(value) if Path(value).is_absolute() else PROJECT_ROOT / value) if value else None
    candidate_semantic, candidate_verdict = args.candidate_semantic.resolve(), args.candidate_verdict.resolve()
    candidate = json.loads(candidate_verdict.read_text(encoding="utf-8"))
    if (candidate.get("semantic_input") or {}).get("manifest_sha256") != \
            hashlib.sha256(args.training_manifest.read_bytes()).hexdigest():
        raise SystemExit("--training-manifest is not the manifest this candidate was trained on")
    training_base = args.training_manifest.resolve().parent
    training_rows = read_jsonl(args.training_manifest)
    for row in training_rows:
        path = Path(row["eml"])
        row["eml"] = str(path if path.is_absolute() else training_base / path)
    evidence = read_jsonl(args.holdout_evidence)
    if {int(row["label"]) for row in evidence} != {0, 1}:
        raise SystemExit("the holdout must contain both normal and phishing mail")
    training_digests = check_disjoint(training_rows, evidence)
    if not candidate.get("training_mail_digest"):
        raise SystemExit("candidate has no training_mail_digest; retrain it with the current trainer")
    if combined_digest(training_digests) != candidate["training_mail_digest"]:
        raise SystemExit("training mails on disk differ from the mails this candidate was trained on")
    # The semantic model that is scored and installed must be the one written with this candidate.
    recorded_semantic = (candidate.get("semantic_input") or {}).get("artifact_sha256")
    if not recorded_semantic:
        raise SystemExit("candidate records no semantic artifact_sha256; retrain it with the current trainer")
    if hashlib.sha256(candidate_semantic.read_bytes()).hexdigest() != recorded_semantic:
        raise SystemExit("--candidate-semantic is not the semantic model written with this candidate")
    if args.apply:  # after the candidate files are verified, before the holdout is looked at
        check_install_targets_free(install_targets(candidate_semantic, candidate_verdict, models_dir))

    # Missing files, bad config or code errors stop the run.  Only a feature-schema
    # difference makes the installed model legitimately incomparable.
    translation = resolve(config.get("translation_model"))
    installed_semantic, installed_verdict = resolve(config["semantic_ml_model"]), resolve(config["ml_verdict_model"])
    for path in (installed_semantic, installed_verdict):
        if not path.is_file():
            raise SystemExit(f"installed model file is missing: {path}")
    usage_path = models_dir / "holdout_usage.jsonl"
    holdout_id = holdout_identity(evidence)
    previous_uses = sum(entry.get("holdout_id") == holdout_id for entry in read_jsonl(usage_path)) \
        if usage_path.is_file() else 0
    evaluated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    # From here on the holdout is being looked at.  Whatever happens next, even
    # a crash while scoring, is written to the usage log before the run ends.
    usage = {"holdout_id": holdout_id, "rows": len(evidence), "evaluated_at": evaluated_at,
             "candidate": candidate["model_id"], "status": "failed_before_decision", "decision": None,
             "installed": False}
    incumbent_counts, incumbent_error, install_error, record = None, None, None, None
    try:
        candidate_counts, candidate_rows = score_holdout(evidence, candidate_semantic, candidate_verdict, translation)
        incumbent_rows = []
        try:
            incumbent_counts, incumbent_rows = score_holdout(
                evidence, installed_semantic, installed_verdict, translation)
        except SchemaMismatchError as exc:
            incumbent_error = str(exc)
        decision = promotion_decision(candidate_counts, incumbent_counts)
        usage.update(status="evaluated", decision=decision)
        record = {
            "model_id": candidate["model_id"],
            "semantic_model_id": (candidate.get("semantic_input") or {}).get("model_id"),
            "evaluated_at": evaluated_at,
            "promoted_to_gui": False,
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
        if decision["promote"] and args.apply:
            try:
                record.update(install(candidate_semantic, candidate_verdict, record, models_dir, config_path))
                record["promoted_to_gui"] = True  # only after the install has completed
                usage.update(status="installed", installed=True)
            except (OSError, ValueError, RuntimeError) as exc:
                install_error = f"{type(exc).__name__}: {exc}"
                record["install_error"] = install_error
                usage.update(status="install_failed")
    finally:
        failing = sys.exc_info()[1]
        try:
            with usage_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(usage, ensure_ascii=False) + "\n")
            if record is not None:
                args.report.parent.mkdir(parents=True, exist_ok=True)
                args.report.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        except OSError as log_error:
            if failing is None:
                raise
            # Never let a logging failure replace the error that actually stopped the run.
            print(f"WARNING: could not write the usage log or report ({log_error}); "
                  f"original error follows", file=sys.stderr)
    print(json.dumps({key: record[key] for key in ("model_id", "decision", "candidate", "promoted_to_gui")}
                     | {"installed": incumbent_counts, "installed_error": incumbent_error,
                        "install_error": install_error,
                        "previous_evaluations_on_this_holdout": previous_uses}, ensure_ascii=False, indent=2))
    if install_error:
        raise SystemExit(f"promotion rule passed but the install failed: {install_error}")


if __name__ == "__main__":
    main()

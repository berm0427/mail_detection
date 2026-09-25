"""Evaluate a portable evidence model on an independent labeled manifest.

JSONL fields: eml, label (integer 0/1), and optionally analysis_result. Successful
inference on valid, unique inputs writes a report. Exit status 0 means the
promotion gate passed; status 2 means the model ran but failed the gate.
Invalid CLI criteria also exit 2 (argparse) but never write a report.
Invalid inputs, including repeated raw EML/nonempty normalized bodies, abort
without writing a report. This does not check overlap with training data.
Report paths that alias a model, manifest, or consumed input are rejected.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from email import policy
from email.parser import BytesParser
from itertools import groupby
from pathlib import Path

from email_analyzer.engines.evidence_ml import EvidenceMLEngine
from email_analyzer.manifest_independence import normalized_body_sha256


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject ambiguous JSON objects without exposing keys or values."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _finite_json_float(value: str) -> float:
    """Reject nonstandard constants and float overflow before feature clipping."""
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def binary_metrics(labels: list[int], scores: list[float]) -> dict:
    """Unweighted binary metrics at the existing 0.5 evaluation threshold.

    AUC is the fraction of positive/negative pairs ordered correctly, with
    half credit for tied scores. Sorting score groups keeps this O(n log n)
    without requiring the training-only NumPy/scikit-learn dependencies.
    """
    # bool and float compare equal to 0/1 in Python, but are not valid labels
    # under the manifest contract. Validate types before hashing or coercion.
    if any(type(label) is not int or label not in (0, 1) for label in labels):
        raise ValueError("evaluation labels must be integer 0 or 1")
    if len(labels) != len(scores) or set(labels) != {0, 1}:
        raise ValueError("evaluation set must contain both labels and matching scores")
    if any(not math.isfinite(score) or not 0 <= score <= 1 for score in scores):
        raise ValueError("evaluation scores must be finite probabilities")
    positives = sum(labels)
    negatives = len(labels) - positives
    negatives_below = 0
    concordant = 0.0
    for _, group in groupby(sorted(zip(scores, labels)), key=lambda item: item[0]):
        group_labels = [label for _, label in group]
        group_positives = sum(group_labels)
        group_negatives = len(group_labels) - group_positives
        concordant += group_positives * (negatives_below + 0.5 * group_negatives)
        negatives_below += group_negatives
    tp = sum(label == 1 and score >= .5 for label, score in zip(labels, scores))
    fp = sum(label == 0 and score >= .5 for label, score in zip(labels, scores))
    tn, fn = negatives - fp, positives - tp
    return {
        "rows": len(labels), "auc": concordant / (positives * negatives),
        "tn": tn, "fp": fp, "fn": fn, "tp": tp,
        "accuracy": (tp + tn) / len(labels),
        "fpr": fp / negatives, "recall": tp / positives,
    }


def resolve(base: Path, value: str) -> Path:
    path = Path(value)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def validate_report_destination(report: Path, inputs: list[Path]) -> None:
    """Reject lexical/symlink and hardlink aliases without disclosing paths."""
    destination = report.resolve()
    for source in inputs:
        if destination == source.resolve() or (report.exists() and report.samefile(source)):
            raise ValueError("report path aliases an evaluation input")


def _positive_row_count(value: str) -> int:
    count = int(value)
    if count < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return count


def _gate_probability(value: str) -> float:
    number = float(value)
    if not math.isfinite(number) or not 0 <= number <= 1:
        raise argparse.ArgumentTypeError("must be a finite probability between 0 and 1")
    return number


def main() -> None:
    parser = argparse.ArgumentParser(description="Independent evidence-model evaluation gate")
    parser.add_argument("model", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("report", type=Path)
    parser.add_argument("--min-rows", type=_positive_row_count, default=100)
    parser.add_argument("--min-auc", type=_gate_probability, default=.75)
    parser.add_argument("--max-fpr", type=_gate_probability, default=.15)
    parser.add_argument("--min-recall", type=_gate_probability, default=.65)
    args = parser.parse_args()

    base = args.manifest.resolve().parent
    rows = []
    # Split bytes first: Unicode separators inside valid JSON strings are not
    # JSONL record boundaries. Decode per line for safe, physical diagnostics.
    for line_no, raw_line in enumerate(args.manifest.read_bytes().splitlines(), 1):
        try:
            line = raw_line.decode("utf-8")
            if not line.strip():
                continue
            row = json.loads(line, object_pairs_hook=_unique_json_object,
                             parse_constant=_finite_json_float, parse_float=_finite_json_float)
        except ValueError:
            raise ValueError(f"invalid manifest JSON at line {line_no}") from None
        if not isinstance(row, dict):
            raise ValueError(f"manifest row must be a JSON object at line {line_no}")
        rows.append((line_no, row))
    if not rows:
        raise ValueError("empty evaluation manifest")
    engine = EvidenceMLEngine(args.model)
    input_paths = [args.model, args.manifest]
    labels, scores = [], []
    content_hashes = set()
    body_hashes = set()
    details = []
    for line_no, row in rows:
        if type(row.get("label")) is not int or row["label"] not in (0, 1):
            raise ValueError(f"invalid label at line {line_no}")
        if not isinstance(row.get("eml"), str) or not row["eml"].strip():
            raise ValueError(f"invalid eml at line {line_no}")
        try:
            eml = resolve(base, row["eml"])
            raw = eml.read_bytes()
        except (OSError, ValueError, RuntimeError):
            raise ValueError(f"invalid or unavailable eml at line {line_no}") from None
        input_paths.append(eml)
        digest = hashlib.sha256(raw).hexdigest()
        if digest in content_hashes:
            raise ValueError(f"duplicate EML content at line {line_no}")
        content_hashes.add(digest)
        # Match training: an explicit inline object, even {}, takes priority.
        # A malformed inline value must not silently become missing evidence.
        result = {}
        if "analysis" in row:
            if not isinstance(row["analysis"], dict):
                raise ValueError(f"invalid analysis at line {line_no}")
            result = row["analysis"]
        elif "analysis_result" in row:
            if not isinstance(row["analysis_result"], str) or not row["analysis_result"].strip():
                raise ValueError(f"invalid analysis_result at line {line_no}")
            try:
                analysis_path = resolve(base, row["analysis_result"])
                input_paths.append(analysis_path)
                result = json.loads(analysis_path.read_text(encoding="utf-8"),
                                    object_pairs_hook=_unique_json_object,
                                    parse_constant=_finite_json_float, parse_float=_finite_json_float)
                if not isinstance(result, dict):
                    raise ValueError("analysis must be an object")
            except (OSError, ValueError, RuntimeError):
                raise ValueError(f"invalid or unavailable analysis_result at line {line_no}") from None
        message = BytesParser(policy=policy.default).parsebytes(raw)
        body_hash = normalized_body_sha256(message)
        if body_hash is not None:
            if body_hash in body_hashes:
                raise ValueError(f"normalized body duplicate within external manifest at line {line_no}")
            body_hashes.add(body_hash)
        output = engine.analyze(message, result)
        if output.status != "ok" or output.score is None:
            raise RuntimeError(f"model inference failed at line {line_no}: {output.error}")
        score = float(output.score)
        prediction = int(score >= .5)
        labels.append(int(row["label"])); scores.append(score)
        details.append({"eml": str(row["eml"]), "label": int(row["label"]), "score": score,
                        "prediction": prediction, "correct": prediction == int(row["label"])})

    observed = binary_metrics(labels, scores)
    criteria = {"min_rows": args.min_rows, "min_auc": args.min_auc,
                "max_fpr": args.max_fpr, "min_recall": args.min_recall}
    passed = (observed["rows"] >= args.min_rows and observed["auc"] >= args.min_auc
              and observed["fpr"] <= args.max_fpr and observed["recall"] >= args.min_recall)
    model_data = json.loads(args.model.read_text(encoding="utf-8"))
    report = {
        "model_id": model_data.get("model_id"), "independent_gate_passed": passed,
        "criteria": criteria, "observed": observed, "predictions": details,
        "manifest_sha256": hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
        "promotion_allowed": passed,
        "limitations": "A small audit set can reject a model but cannot establish real-world performance.",
    }
    validate_report_destination(args.report, input_paths)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if not passed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()

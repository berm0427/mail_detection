"""Prepare and train a candidate model from the Korean synthetic dataset ZIP.

This command never promotes or edits the production model configuration.  It
validates the outer metadata against every EML in the nested archive, writes a
human-readable split/class directory tree, builds an inline evidence manifest,
and trains a candidate with the existing gated trainer.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

from tools.build_synthetic_evidence_manifest import profile


ALLOWED_SPLITS = {"train", "validation", "test"}
CLASS_DIR = {0: "normal", 1: "phishing"}


def safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe ZIP member: {name!r}")
    return path


def find_one(names: list[str], suffix: str) -> str:
    matches = [name for name in names if name.lower().endswith(suffix.lower())]
    if len(matches) != 1:
        raise ValueError(f"expected one {suffix} member, found {len(matches)}")
    return matches[0]


def read_metadata(outer: zipfile.ZipFile) -> tuple[str, list[dict]]:
    member = find_one(outer.namelist(), ".jsonl")
    rows = []
    for line_no, line in enumerate(outer.read(member).decode("utf-8-sig").splitlines(), 1):
        if not line.strip():
            continue
        row = json.loads(line)
        if row.get("label_id") not in (0, 1):
            raise ValueError(f"invalid label_id at metadata row {line_no}")
        if row.get("split") not in ALLOWED_SPLITS:
            raise ValueError(f"invalid split at metadata row {line_no}")
        if not row.get("id") or not row.get("scenario_id"):
            raise ValueError(f"missing id/scenario_id at metadata row {line_no}")
        rows.append(row)
    if len({row["id"] for row in rows}) != len(rows):
        raise ValueError("duplicate metadata ids")
    return member, rows


def prepare(zip_path: Path, dataset_dir: Path, include_synthetic_evidence: bool = False) -> tuple[Path, dict]:
    print(f"[1/5] ZIP 검사 시작: {zip_path}", flush=True)
    dataset_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path) as outer:
        names = outer.namelist()
        for name in names:
            safe_member(name)
        metadata_member, rows = read_metadata(outer)
        nested_member = find_one(names, "_eml.zip")
        nested_bytes = outer.read(nested_member)

    by_id = {row["id"]: row for row in rows}
    found: set[str] = set()
    digests: dict[str, str] = {}
    counts: Counter[str] = Counter()
    group_splits: dict[str, set[str]] = defaultdict(set)
    manifest_rows = []
    with zipfile.ZipFile(io.BytesIO(nested_bytes)) as inner:
        file_members = [item for item in inner.infolist() if not item.is_dir()]
        print(f"[2/5] EML {len(file_members):,}개 분리 시작", flush=True)
        for number, item in enumerate(file_members, 1):
            path = safe_member(item.filename)
            if path.suffix.lower() != ".eml":
                raise ValueError(f"unexpected nested member: {item.filename}")
            stem = path.stem
            row = by_id.get(stem)
            if row is None:
                raise ValueError(f"EML without metadata: {item.filename}")
            if stem in found:
                raise ValueError(f"duplicate EML id: {stem}")
            found.add(stem)
            label = int(row["label_id"]); split = str(row["split"])
            expected_source_class = "phishing" if label else "legitimate"
            if split not in path.parts or expected_source_class not in path.parts:
                raise ValueError(f"metadata/archive mismatch for {stem}")
            raw = inner.read(item)
            digest = hashlib.sha256(raw).hexdigest()
            if digest in digests:
                raise ValueError(f"duplicate EML content: {stem} and {digests[digest]}")
            digests[digest] = stem
            destination = dataset_dir / split / CLASS_DIR[label] / f"{stem}.eml"
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            counts[f"{split}_{CLASS_DIR[label]}"] += 1
            group = str(row["scenario_id"])
            group_splits[group].add(split)
            manifest_rows.append({
                "eml": str(destination.resolve()), "label": label, "split": split,
                "group_id": group,
                # Reserved .example domains and harmless attachment placeholders
                # are generator metadata, not real-world security evidence.
                "analysis": profile(row) if include_synthetic_evidence else {},
            })
            if number % 1000 == 0 or number == len(file_members):
                print(f"      {number:,}/{len(file_members):,}개 완료", flush=True)

    missing = sorted(set(by_id) - found)
    if missing:
        raise ValueError(f"metadata rows without EML: {len(missing)}")
    leaking = sorted(group for group, splits in group_splits.items() if len(splits) > 1)
    if leaking:
        raise ValueError(f"scenario groups cross splits: {len(leaking)}")
    if len(rows) < 30 or set(row["label_id"] for row in rows) != {0, 1}:
        raise ValueError("dataset is too small or has only one class")

    manifest = dataset_dir / "training_manifest.jsonl"
    manifest.write_text(
        "\n".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) for row in manifest_rows) + "\n",
        encoding="utf-8",
    )
    prepared = {
        "source_zip": str(zip_path.resolve()), "source_sha256": hashlib.sha256(zip_path.read_bytes()).hexdigest(),
        "metadata_member": metadata_member, "rows": len(rows), "unique_eml": len(digests),
        "counts": dict(sorted(counts.items())), "scenario_groups": len(group_splits),
        "manifest": str(manifest.resolve()), "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
        "test_emails_1_to_8_in_training": False,
        "training_use": "text_only" if not include_synthetic_evidence else "synthetic_evidence_experiment",
        "excluded_from_objective_evidence": [] if include_synthetic_evidence else [
            "reserved_.example_domains", "synthetic_urls", "synthetic_auth_results",
            "harmless_attachment_placeholders",
        ],
    }
    (dataset_dir / "PREPARATION_REPORT.json").write_text(
        json.dumps(prepared, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"[3/5] 데이터 검사 완료: {len(rows):,}개, 중복 0개", flush=True)
    return manifest, prepared


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    # Inherit the console so long-running training output is visible instead of
    # appearing only after the child process exits.
    return subprocess.run(command, text=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="Securely prepare a dataset ZIP and train a gated candidate")
    parser.add_argument("zip", type=Path)
    parser.add_argument("dataset_dir", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--model-id", default="dise-user-retrain-candidate")
    parser.add_argument("--regularization-c", type=float, default=.1)
    parser.add_argument("--text-bins", type=int, default=2048)
    parser.add_argument("--independent-manifest", type=Path)
    parser.add_argument("--independent-report", type=Path)
    parser.add_argument("--min-independent-rows", type=int, default=100)
    parser.add_argument("--semantic-model", type=Path,
                        help="use semantic embeddings plus scenario-group CV instead of character hashing")
    parser.add_argument("--semantic-folds", type=int, default=5)
    parser.add_argument("--include-synthetic-evidence", action="store_true",
                        help="experimental: use reserved-domain/auth/placeholder metadata as evidence")
    args = parser.parse_args()
    if not args.zip.is_file():
        parser.error(f"ZIP not found: {args.zip}")
    if args.regularization_c <= 0 or args.text_bins <= 0:
        parser.error("regularization and text bins must be positive")

    manifest, prepared = prepare(args.zip.resolve(), args.dataset_dir.resolve(), args.include_synthetic_evidence)
    args.candidate.parent.mkdir(parents=True, exist_ok=True)
    if args.semantic_model:
        if not args.semantic_model.is_dir():
            parser.error(f"semantic model not found: {args.semantic_model}")
        print("[4/6] 의미 임베딩 생성/캐시 확인 (첫 실행은 수분 소요)", flush=True)
        cache=args.dataset_dir.resolve()/"minilm_embeddings.npz"
        initial=args.candidate.with_name(args.candidate.stem+"-split-selection.json")
        embedding=run([sys.executable,"-m","email_analyzer.train_semantic_ml",str(manifest),
                       str(args.semantic_model.resolve()),str(initial),"--cache",str(cache),
                       "--model-id",args.model_id+"-split-selection"])
        if embedding.returncode==0:
            print("[5/6] 시나리오 그룹 교차검증 및 최종 후보 학습", flush=True)
            training=run([sys.executable,"-m","email_analyzer.train_semantic_group_cv",str(manifest),
                          str(cache),str(args.semantic_model.resolve()),str(args.candidate),
                          "--model-id",args.model_id,"--folds",str(args.semantic_folds)])
        else:
            training=embedding
        evaluation_module="email_analyzer.evaluate_semantic_ml"
        training_mode="semantic_group_cv"
    else:
        print("[4/5] 문자 해싱 후보 모델 학습 시작 (보통 30~90초)", flush=True)
        training = run([
            sys.executable, "-m", "email_analyzer.train_evidence_ml", str(manifest), str(args.candidate),
            "--model-id", args.model_id, "--regularization-c", str(args.regularization_c),
            "--text-bins", str(args.text_bins),
        ])
        evaluation_module="email_analyzer.evaluate_evidence_ml"
        training_mode="character_hashing"
    report = {"preparation": prepared, "training_exit_code": training.returncode,
              "candidate_written": args.candidate.is_file(), "promoted": False,
              "training_mode":training_mode}
    if training.returncode not in (0, 2):
        report["status"] = "training_error"
    elif training.returncode == 2:
        report["status"] = "synthetic_validation_gate_failed"
    elif args.independent_manifest:
        print("[6/6] 독립 평가 시작" if args.semantic_model else "[5/5] 독립 평가 시작", flush=True)
        independent_report = args.independent_report or args.candidate.with_suffix(".independent.json")
        evaluation = run([
            sys.executable, "-m", evaluation_module, str(args.candidate),
            str(args.independent_manifest), str(independent_report), "--min-rows", str(args.min_independent_rows),
        ])
        report.update({"status": "independent_gate_passed" if evaluation.returncode == 0 else "independent_gate_failed",
                       "independent_exit_code": evaluation.returncode,
                       "independent_report": str(independent_report.resolve())})
    else:
        report["status"] = "candidate_only_no_independent_evaluation"
    run_report = args.dataset_dir / "RETRAIN_REPORT.json"
    run_report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "report": str(run_report.resolve()),
                      "candidate": str(args.candidate.resolve()) if args.candidate.is_file() else None},
                     ensure_ascii=False, indent=2))
    if report["status"] not in ("independent_gate_passed", "candidate_only_no_independent_evaluation"):
        raise SystemExit(2)


if __name__ == "__main__":
    main()

"""Retrain the ML verdict model end to end and compare it with the installed one.

Steps, each a separate tool that can also be run by hand:

1. extract_synthetic_evidence.py  training manifest -> training evidence
2. (here)                         training manifest -> embedding cache
3. train_ml_verdict.py            nested group CV, candidate semantic + verdict models
4. extract_synthetic_evidence.py  holdout manifest -> holdout evidence
5. promote_ml_verdict.py          candidate vs installed model on the holdout

The candidate is written to ``models/candidates/<tag>/`` and is not used by the
GUI.  Nothing is installed unless ``--apply`` is given and the promotion rule
passes.  Create the two manifests first with ``split_holdout.py``.
"""
from __future__ import annotations

import argparse
from email import policy
from email.parser import BytesParser
import hashlib
import json
from pathlib import Path
import subprocess
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
TOOLS = PROJECT_ROOT / "tools"


def run(step: str, *arguments) -> None:
    print(f"\n=== {step}", flush=True)
    completed = subprocess.run([sys.executable, "-B", *map(str, arguments)], cwd=PROJECT_ROOT)
    if completed.returncode:
        raise SystemExit(f"{step} failed (exit {completed.returncode}); nothing was installed")


def serving_text(message, translation_model) -> str:
    """The text the GUI's semantic engine embeds: translated to Korean when the mail is foreign.

    A mail the GUI could not score (foreign language without a usable
    translation) has no serving-time embedding, so it cannot be a training row.
    """
    from email_analyzer.evidence_features import message_text
    from email_analyzer.text_translation import translate_context_to_korean
    translation = translate_context_to_korean(message_text(message), translation_model)
    if translation["source_language"] not in ("ko", "unknown") and not translation["translated"]:
        raise ValueError(f"cannot embed as the GUI would: {translation['status']} "
                         f"(language {translation['source_language']})")
    return translation["text"]


def build_embedding_cache(manifest: Path, embedding_model: Path, output: Path, translation_model=None,
                          batch_size: int = 64) -> None:
    """One L2-normalised embedding per manifest row, in manifest order, of the serving-time text."""
    import numpy as np
    from sentence_transformers import SentenceTransformer
    from email_analyzer.mail_identity import strip_label_headers
    base = manifest.resolve().parent
    raw = manifest.read_bytes()
    texts = []
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        path = Path(json.loads(line)["eml"])
        path = path if path.is_absolute() else base / path
        try:
            cleaned, _ = strip_label_headers(path.read_bytes())
            texts.append(serving_text(BytesParser(policy=policy.default).parsebytes(cleaned), translation_model))
        except ValueError as error:
            raise SystemExit(f"{path}: {error}. Remove the row or install the translation model.") from error
    encoder = SentenceTransformer(str(embedding_model), device="cpu")
    embeddings = encoder.encode(texts, batch_size=batch_size, convert_to_numpy=True,
                                normalize_embeddings=True, show_progress_bar=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(output, embeddings=embeddings,
                        manifest_sha256=np.asarray(hashlib.sha256(raw).hexdigest()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("train_manifest", type=Path)
    parser.add_argument("holdout_manifest", type=Path)
    parser.add_argument("--tag", required=True, help="version tag for the candidate, e.g. v5")
    parser.add_argument("--mode", choices=("offline", "live"), default="live",
                        help="how rows without a saved analysis are analysed (default live)")
    parser.add_argument("--outer-folds", type=int, default=10)
    parser.add_argument("--inner-folds", type=int, default=5)
    parser.add_argument("--apply", action="store_true", help="install the candidate if the promotion rule passes")
    args = parser.parse_args()

    config = json.loads((PROJECT_ROOT / "engine_config.json").read_text(encoding="utf-8"))
    installed_semantic = Path(config["semantic_ml_model"])
    installed_semantic = installed_semantic if installed_semantic.is_absolute() else PROJECT_ROOT / installed_semantic
    embedding_model = Path(json.loads(installed_semantic.read_text(encoding="utf-8"))["embedding_model_path"])
    out = PROJECT_ROOT / "models" / "candidates" / args.tag
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"{out} already has files; choose a new --tag")
    out.mkdir(parents=True, exist_ok=True)
    train_evidence, holdout_evidence = out / "train_evidence.jsonl", out / "holdout_evidence.jsonl"
    cache = out / "train_embeddings.npz"
    semantic, verdict = out / f"dise-multilingual-semantic-{args.tag}.json", out / f"dise-ml-verdict-{args.tag}.json"

    run("1/5 extract training evidence", TOOLS / "extract_synthetic_evidence.py",
        args.train_manifest, train_evidence, "--mode", args.mode)
    print("\n=== 2/5 build embedding cache", flush=True)
    translation_model = config.get("translation_model")
    if translation_model and not Path(translation_model).is_absolute():
        translation_model = PROJECT_ROOT / translation_model
    build_embedding_cache(args.train_manifest, embedding_model, cache, translation_model)
    run("3/5 nested group CV and candidate models", TOOLS / "train_ml_verdict.py",
        args.train_manifest, train_evidence, cache,
        "--outer-folds", args.outer_folds, "--inner-folds", args.inner_folds,
        "--metrics", out / "nested_cv.metrics.json", "--artifact", verdict, "--semantic-artifact", semantic,
        "--embedding-model", embedding_model,
        "--semantic-model-id", f"dise-multilingual-semantic-{args.tag}",
        "--verdict-model-id", f"dise-ml-verdict-{args.tag}")
    run("4/5 extract holdout evidence", TOOLS / "extract_synthetic_evidence.py",
        args.holdout_manifest, holdout_evidence, "--mode", args.mode)
    run("5/5 compare with the installed model", TOOLS / "promote_ml_verdict.py",
        "--candidate-semantic", semantic, "--candidate-verdict", verdict,
        "--training-manifest", args.train_manifest, "--holdout-evidence", holdout_evidence,
        "--report", out / "promotion_report.json", *(["--apply"] if args.apply else []))
    print(f"\nCandidate files and reports: {out}")


if __name__ == "__main__":
    main()

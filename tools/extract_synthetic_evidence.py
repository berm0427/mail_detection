"""Re-extract synthetic training evidence with the production analyzer.

The earlier ``build_synthetic_evidence_manifest.py`` derived structural
evidence from generator metadata, so its features did not match what the live
analyzer computes.  This tool runs ``IntegratedAnalyzer`` itself on every EML.

* Dataset bookkeeping headers (``X-Dataset-*``, ``X-Synthetic-Data``) carry the
  label and split; they are removed before analysis and their absence in the
  parsed message is asserted.
* Network access, Razor and attachment scanning are disabled: the corpus uses
  reserved ``.example`` domains and placeholder attachments, so these engines
  can only return constant "no match / clean" results.
* The semantic and HTML-pair engines are skipped here; semantic probabilities
  are supplied later as out-of-fold predictions from the embedding cache.

Two modes exist so that labelled real mail can teach the features that the
synthetic corpus cannot:

``--mode offline`` (default)  network, Razor, attachment scanning and the
    HTML-pair engine are off.  Use it for synthetic ``.example`` mail.
``--mode live``  network, Razor, attachment scanning and the HTML-pair engine
    run exactly as in the GUI, so authentication, official-site, HTML,
    antivirus and Razor observations are real.  Use it for labelled real mail.

A manifest row may carry ``analysis_result``: the path of a
``final_analysis_result.json`` saved when the mail was first analysed.  That
saved result is reused instead of re-running the analyzer, because phishing
destinations disappear quickly and a later run could no longer observe them.
The semantic engine is skipped in both modes; its score is always replaced by
an out-of-fold prediction during training.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_analyzer.mail_identity import mail_digest, strip_label_headers  # noqa: F401  (re-exported)
from email_analyzer.ml_verdict_features import SCHEMA_VERSION

RUNTIME_OPTIONS = {
    "disable_network": True,
    "disable_attachment_scan": True,
    "engine_config_override": {"razor_command": [], "semantic_ml_model": "", "html_pair_ml_model": ""},
}
LIVE_RUNTIME_OPTIONS = {"engine_config_override": {"semantic_ml_model": ""}}
MODES = {"offline": RUNTIME_OPTIONS, "live": LIVE_RUNTIME_OPTIONS}


def slim(result: dict) -> dict:
    """Keep only the observations consumed by the ML verdict features."""
    return {
        "verdict_status": "error" if result.get("verdict") == "error" else "ok",
        "error": result.get("error"),
        "engine_results": _engine_observations(result),
        "rule_result": {"auth_summary": (result.get("rule_result") or {}).get("auth_summary") or {}},
        "link_evidence": result.get("link_evidence") or {},
        "reference_evidence": result.get("reference_evidence") or {},
        "page_analysis": result.get("page_analysis") or {},
        "attachments": [{"malware_scan": {"status": (item.get("malware_scan") or {}).get("status")}}
                        for item in result.get("attachments") or []],
    }


def _engine_observations(result: dict) -> dict:
    """Razor and HTML-pair outputs feed ML features; the semantic score never does."""
    engines = result.get("engine_results") or {}
    kept = {}
    razor = engines.get("razor") or {}
    if razor:
        kept["razor"] = {"status": razor.get("status"),
                         "details": {"catalogue_match": (razor.get("details") or {}).get("catalogue_match")}}
    pair = engines.get("html_pair_ml") or {}
    if pair:
        details = pair.get("details") or {}
        kept["html_pair_ml"] = {"status": pair.get("status"), "score": pair.get("score"),
                                "details": {key: details.get(key) for key in
                                            ("predicted_label", "validation_gate", "highest_risk_pair")}}
    return kept


def _leaked_label_headers(result: dict) -> list[str]:
    return [name for name in (result.get("metadata") or {})
            if name.lower().startswith(("x-dataset", "x-synthetic"))]


def _evidence_row(row: dict, result: dict, removed: int, mode: str, raw: bytes) -> dict:
    return {"eml": row["eml"], "label": row["label"], "split": row["split"],
            "feature_schema": SCHEMA_VERSION, "extraction_mode": mode,
            # Identity of the mail this evidence was observed from (label headers excluded).
            "eml_sha256": mail_digest(raw),
            "group_id": row["group_id"], "removed_label_headers": removed, "analysis": slim(result)}


def reuse_saved_analysis(row: dict) -> dict:
    """Use the analysis captured when the mail was first analysed."""
    result = json.loads(Path(row["analysis_result"]).read_text(encoding="utf-8"))
    raw = Path(row["eml"]).read_bytes()
    check_saved_analysis(result, raw, row["analysis_result"])
    return _evidence_row(row, result, 0, "saved_live", raw)


def check_saved_analysis(result: dict, raw: bytes, source: str) -> None:
    """A saved result is usable only if it is for this mail and for the current features."""
    if result.get("verdict") == "error":
        raise RuntimeError(f"saved analysis is an error result: {source}")
    leaked = _leaked_label_headers(result)
    if leaked:
        raise RuntimeError(f"saved analysis contains label headers: {leaked}")
    if result.get("ml_feature_schema") != SCHEMA_VERSION:
        raise RuntimeError(
            f"saved analysis was produced under feature schema {result.get('ml_feature_schema')!r}, "
            f"not {SCHEMA_VERSION!r}; analyse the mail again or drop analysis_result: {source}")
    # Bound by content: a matching Message-ID or Date is not enough, because
    # mails of one campaign can share them while the body differs.
    if result.get("eml_sha256") != mail_digest(raw):
        raise RuntimeError(f"saved analysis was not produced from this mail (content differs): {source}")


def analyze_one(row: dict, mode: str = "offline") -> dict:
    if row.get("analysis_result"):
        return reuse_saved_analysis(row)
    logging.disable(logging.CRITICAL)
    from email_analyzer.integration import IntegratedAnalyzer
    work = Path(tempfile.mkdtemp(prefix="dise-extract-"))
    try:
        raw = Path(row["eml"]).read_bytes()
        cleaned, removed = strip_label_headers(raw)
        source = work / "input.eml"
        source.write_bytes(cleaned)
        analyzer = IntegratedAnalyzer(result_dir=work / "result", attachments_dir=work / "attachments",
                                      runtime_options=MODES[mode])
        result = analyzer.analyze_email(source)
        leaked = _leaked_label_headers(result)
        if leaked:
            raise RuntimeError(f"label header survived stripping: {leaked}")
        return _evidence_row(row, result, removed, mode, raw)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--mode", choices=sorted(MODES), default="offline")
    parser.add_argument("--workers", type=int)
    args = parser.parse_args()
    # Live extraction talks to the network and to local scanners; run it serially by default.
    workers = args.workers or (1 if args.mode == "live" else max(1, (os.cpu_count() or 2) - 1))
    manifest_base = args.training_manifest.resolve().parent
    rows = [json.loads(line) for line in args.training_manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    for row in rows:
        eml = Path(row["eml"])
        row["eml"] = str((eml if eml.is_absolute() else manifest_base / eml).resolve())
        if row.get("analysis_result"):
            saved = Path(row["analysis_result"])
            row["analysis_result"] = str((saved if saved.is_absolute() else manifest_base / saved).resolve())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    errors = 0
    modes = {}
    # Written under a temporary name: an interrupted run never leaves a
    # partial evidence file where a complete one is expected.
    partial = args.output.with_name(args.output.name + ".partial")
    with ProcessPoolExecutor(max_workers=workers) as pool, \
            partial.open("w", encoding="utf-8") as handle:
        for index, item in enumerate(pool.map(analyze_one, rows, [args.mode] * len(rows),
                                              chunksize=16 if args.mode == "offline" else 1), 1):
            modes[item["extraction_mode"]] = modes.get(item["extraction_mode"], 0) + 1
            errors += item["analysis"]["verdict_status"] == "error"
            handle.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
            if index % 500 == 0 or index == len(rows):
                print(f"[{index}/{len(rows)}] errors={errors}", flush=True)
    print(json.dumps({"rows": len(rows), "errors": errors, "output": str(args.output),
                      "extraction_modes": modes, "runtime_options": MODES[args.mode]}, ensure_ascii=False))
    if errors:
        partial.unlink(missing_ok=True)
        raise SystemExit(f"{errors} analyses failed")
    os.replace(partial, args.output)


if __name__ == "__main__":
    main()

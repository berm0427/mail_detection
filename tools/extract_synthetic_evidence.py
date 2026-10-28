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
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_analyzer.ml_verdict_features import SCHEMA_VERSION

LABEL_HEADERS = re.compile(rb"(?im)^(?:X-Dataset-[^:\r\n]*|X-Synthetic-Data):[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*\r?\n")
RUNTIME_OPTIONS = {
    "disable_network": True,
    "disable_attachment_scan": True,
    "engine_config_override": {"razor_command": [], "semantic_ml_model": "", "html_pair_ml_model": ""},
}


def strip_label_headers(raw: bytes) -> tuple[bytes, int]:
    match = re.search(rb"\r?\n\r?\n", raw)
    if not match:
        raise ValueError("EML has no header/body separator")
    head, rest = raw[:match.start() + 1], raw[match.start() + 1:]
    cleaned, removed = LABEL_HEADERS.subn(b"", head)
    return cleaned + rest, removed


def slim(result: dict) -> dict:
    """Keep only the observations consumed by the ML verdict features."""
    return {
        "verdict_status": "error" if result.get("verdict") == "error" else "ok",
        "error": result.get("error"),
        "engine_results": {},
        "rule_result": {"auth_summary": (result.get("rule_result") or {}).get("auth_summary") or {}},
        "link_evidence": result.get("link_evidence") or {},
        "reference_evidence": result.get("reference_evidence") or {},
        "page_analysis": result.get("page_analysis") or {},
        "attachments": [{"malware_scan": {"status": (item.get("malware_scan") or {}).get("status")}}
                        for item in result.get("attachments") or []],
    }


def analyze_one(row: dict) -> dict:
    logging.disable(logging.CRITICAL)
    from email_analyzer.integration import IntegratedAnalyzer
    work = Path(tempfile.mkdtemp(prefix="dise-extract-"))
    try:
        cleaned, removed = strip_label_headers(Path(row["eml"]).read_bytes())
        source = work / "input.eml"
        source.write_bytes(cleaned)
        analyzer = IntegratedAnalyzer(result_dir=work / "result", attachments_dir=work / "attachments",
                                      runtime_options=RUNTIME_OPTIONS)
        result = analyzer.analyze_email(source)
        leaked = [name for name in (result.get("metadata") or {})
                  if name.lower().startswith(("x-dataset", "x-synthetic"))]
        if leaked:
            raise RuntimeError(f"label header survived stripping: {leaked}")
        return {"eml": row["eml"], "label": row["label"], "split": row["split"],
                "feature_schema": SCHEMA_VERSION,
                "group_id": row["group_id"], "removed_label_headers": removed, "analysis": slim(result)}
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.training_manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    errors = 0
    with ProcessPoolExecutor(max_workers=args.workers) as pool, \
            args.output.open("w", encoding="utf-8") as handle:
        for index, item in enumerate(pool.map(analyze_one, rows, chunksize=16), 1):
            errors += item["analysis"]["verdict_status"] == "error"
            handle.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")) + "\n")
            if index % 500 == 0 or index == len(rows):
                print(f"[{index}/{len(rows)}] errors={errors}", flush=True)
    print(json.dumps({"rows": len(rows), "errors": errors, "output": str(args.output),
                      "runtime_options": RUNTIME_OPTIONS}, ensure_ascii=False))
    if errors:
        raise SystemExit(f"{errors} analyses failed")


if __name__ == "__main__":
    main()

"""Re-run the eight user-held emails and record parallel fusion outputs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

_DLL_HANDLES = []


def prepare_runtime():
    os.chdir(PROJECT_ROOT)
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
        torch_lib = Path(sys.prefix) / "Lib" / "site-packages" / "torch" / "lib"
        if torch_lib.is_dir():
            _DLL_HANDLES.append(os.add_dll_directory(str(torch_lib)))


def main():
    prepare_runtime()
    config = json.loads((PROJECT_ROOT / "engine_config.json").read_text(encoding="utf-8"))
    semantic_model = PROJECT_ROOT / config["semantic_ml_model"]
    from email_analyzer.engines.semantic_ml import preload_semantic_encoder
    preload_semantic_encoder(semantic_model)
    from email_analyzer.integration import IntegratedAnalyzer
    from email_analyzer.learned_fusion import analyze_learned_fusion

    source_manifest = PROJECT_ROOT / "mail_body" / "test_data" / "user_real8_manifest.jsonl"
    rows = [json.loads(line) for line in source_manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    output_root = PROJECT_ROOT / "analysis_result" / "fusion-real8-v1"
    artifact = PROJECT_ROOT / "models" / "dise-fusion-logistic-v1-experimental.json"
    output_rows = []
    for index, row in enumerate(rows, 1):
        email_path = (source_manifest.parent / row["eml"]).resolve()
        result_dir = output_root / row["id"]
        analyzer = IntegratedAnalyzer(result_dir=result_dir, attachments_dir=result_dir / "attachments")
        result = analyzer.analyze_email(email_path)
        result["experimental_learned_fusion"] = analyze_learned_fusion(result, artifact)
        final_path = result_dir / "final_analysis_result.json"
        final_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        output_rows.append({
            "id": row["id"], "eml": str(email_path), "label": row["label"],
            "group_id": row["group_id"], "analysis_result": str(final_path.resolve()),
        })
        print(f"[{index}/{len(rows)}] {row['id']} production={result.get('verdict')} "
              f"learned={result['experimental_learned_fusion']['prediction']} "
              f"score={result['experimental_learned_fusion']['score']:.4f}", flush=True)
    manifest = output_root / "manifest.jsonl"
    manifest.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in output_rows) + "\n",
                        encoding="utf-8")
    print(manifest)


if __name__ == "__main__":
    main()

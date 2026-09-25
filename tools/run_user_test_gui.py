"""Visible GUI launcher for user acceptance testing.

This wrapper prepares the existing local analysis runtime and then starts the
real PyQt GUI. It intentionally does not switch Qt to offscreen mode.
"""

from __future__ import annotations

import os
import sys
import json
from pathlib import Path

_DLL_HANDLES = []


def configure_environment(project_root: Path) -> None:
    work_root = Path(r"C:\Users\berm0\Documents\Codex\2026-09-11\x20\work")
    os.chdir(project_root)
    project_root_text = str(project_root)
    if project_root_text not in sys.path:
        sys.path.insert(0, project_root_text)

    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    # PyTorch must see its bundled DLL directory before other native packages
    # are imported on Windows. Keep the directory handle alive for the process.
    if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
        torch_lib = Path(sys.prefix) / "Lib" / "site-packages" / "torch" / "lib"
        if torch_lib.is_dir():
            _DLL_HANDLES.append(os.add_dll_directory(str(torch_lib)))

    if os.environ.get("QT_QPA_PLATFORM", "").lower() == "offscreen":
        del os.environ["QT_QPA_PLATFORM"]


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    configure_environment(project_root)

    # Load PyTorch/MiniLM before the header and GUI modules. Importing other
    # native libraries first can make c10.dll initialization fail on Windows.
    from email_analyzer.engines.semantic_ml import preload_semantic_encoder
    config = json.loads((project_root / "engine_config.json").read_text(encoding="utf-8"))
    artifact = Path(config["semantic_ml_model"])
    if not artifact.is_absolute():
        artifact = project_root / artifact
    preload_semantic_encoder(artifact)

    # Load the remaining analyzer after the native ML runtime is initialized.
    from email_analyzer import integration  # noqa: F401
    from main_gui import main as gui_main

    gui_main()


if __name__ == "__main__":
    main()

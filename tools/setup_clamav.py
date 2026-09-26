"""Prepare the pinned portable ClamAV runtime used by DISE."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from email_analyzer.clamav_bootstrap import (  # noqa: E402
    database_ready, default_install_dir, ensure_clamav, runtime_ready,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="inspect without downloading or updating")
    parser.add_argument("--no-update", action="store_true")
    args = parser.parse_args()
    root = default_install_dir()
    if args.check:
        state = {"runtime": runtime_ready(root), "database": database_ready(root), "path": str(root)}
        print(json.dumps(state, ensure_ascii=False))
        return 0 if state["runtime"] and state["database"] else 4
    print("[ClamAV] Preparing the official portable runtime and signature database...")
    if runtime_ready(root):
        print("[ClamAV] Existing runtime found; download skipped.")
    else:
        print("[ClamAV] First run downloads the pinned official runtime (about 215 MB).")
    print("[ClamAV] Checking official signature database updates...")
    try:
        def report(received, total):
            downloaded = received / (1024 * 1024)
            if total:
                print(f"[ClamAV] Downloaded {downloaded:.0f}/{total / (1024 * 1024):.0f} MB")
            else:
                print(f"[ClamAV] Downloaded {downloaded:.0f} MB")
        installed = ensure_clamav(update=not args.no_update, progress=report)
    except Exception as exc:
        print(f"[ClamAV] Preparation failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    print(f"[ClamAV] Ready: {installed}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

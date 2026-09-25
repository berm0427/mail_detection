"""Create a validated local manifest copy without changing source data.

Uses only the standard library. No basename search, downloading, or training.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath

from email_analyzer.manifest_independence import _load_manifest


def port_manifest(source: Path, output: Path, *, source_root: str,
                  local_root: Path, role: str = "training") -> dict:
    """Map an explicit absolute root, validate every input, then create a copy.

    Relative paths are interpreted beside the source manifest. Every resolved
    input must stay inside local_root, including symlink targets. Output paths
    are relative to the new manifest, not the current working directory.
    """
    if role not in ("training", "external"):
        raise ValueError("invalid manifest role")
    windows = bool(PureWindowsPath(source_root).drive)
    path_type = PureWindowsPath if windows else PurePosixPath
    old_root = path_type(source_root)
    if not old_root.is_absolute() or ".." in old_root.parts:
        raise ValueError("source root must be absolute without parent traversal")
    try:
        root = local_root.resolve(strict=True)
        if not root.is_dir():
            raise ValueError("local root must be a directory")
        if output.exists() or output.is_symlink():
            raise ValueError("output already exists; choose a new file")
        output_base = output.parent.resolve(strict=True)
        source_base = source.resolve(strict=True).parent
    except (OSError, RuntimeError):
        raise ValueError("cannot access manifest location or local root") from None
    rows, source_digest = _load_manifest(source, role)
    analysis_checked = set()
    rewritten = []
    counts = {"eml": 0, "analysis_result": 0}

    def resolve_input(value, field, line_no):
        error = f"invalid or unavailable {field} at {role} line {line_no}"
        if not isinstance(value, str) or not value.strip() or "\x00" in value:
            raise ValueError(error)
        win_path = PureWindowsPath(value)
        if win_path.drive or value.startswith("\\"):
            # Reject drive-relative/root-relative Windows paths and mismatched
            # source formats rather than interpreting them as Linux filenames.
            if not windows or not win_path.is_absolute():
                raise ValueError(error)
            foreign = win_path
        elif PurePosixPath(value).is_absolute():
            foreign = PurePosixPath(value)
        else:
            foreign = None
        try:
            if foreign is not None:
                relative = foreign.relative_to(old_root)
                if ".." in relative.parts or any(":" in part for part in relative.parts):
                    raise ValueError(error)
                target = root.joinpath(*relative.parts)
            else:
                # Both common manifest separator styles are supported.
                target = source_base.joinpath(*PurePosixPath(value.replace("\\", "/")).parts)
            target = target.resolve(strict=True)
            target.relative_to(root)
            if not target.is_file():
                raise ValueError(error)
            if field == "analysis_result":
                if target not in analysis_checked:
                    data = json.loads(target.read_text(encoding="utf-8"))
                    if not isinstance(data, dict):
                        raise ValueError(error)
                    analysis_checked.add(target)
            else:
                with target.open("rb") as stream:
                    stream.read(1)
            result = Path(os.path.relpath(target, output_base)).as_posix()
        except (OSError, ValueError, UnicodeError, RuntimeError):
            raise ValueError(error) from None
        counts[field] += 1
        return result

    for line_no, row in rows:
        item = dict(row)
        item["eml"] = resolve_input(row["eml"], "eml", line_no)
        if "analysis" in row and not isinstance(row["analysis"], dict):
            raise ValueError(f"invalid analysis at {role} line {line_no}")
        if "analysis_result" in row:
            item["analysis_result"] = resolve_input(row["analysis_result"], "analysis_result", line_no)
        elif role == "training" and not isinstance(row.get("analysis"), dict):
            raise ValueError(f"missing analysis input at training line {line_no}")
        rewritten.append(item)
    payload = ("\n".join(json.dumps(row, ensure_ascii=False) for row in rewritten) + "\n").encode("utf-8")
    try:
        # Exclusive creation also prevents races from overwriting an existing
        # file. No output is opened until all rows and inputs have passed.
        with output.open("xb") as stream:
            stream.write(payload)
    except OSError:
        raise ValueError("cannot create output; choose a new writable file") from None
    return {"passed": True, "role": role, "rows": len(rows),
            "validated_paths": counts, "source_manifest_sha256": source_digest,
            "output_manifest_sha256": hashlib.sha256(payload).hexdigest()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--local-root", required=True, type=Path)
    parser.add_argument("--role", choices=("training", "external"), default="training")
    args = parser.parse_args()
    try:
        report = port_manifest(args.source, args.output, source_root=args.source_root,
                               local_root=args.local_root, role=args.role)
    except ValueError as exc:
        print(json.dumps({"passed": False, "error": str(exc)}))
        raise SystemExit(2) from None
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

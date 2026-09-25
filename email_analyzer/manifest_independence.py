"""Offline cross-manifest leakage check; never emits message text or paths."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
from email import policy
from email.message import Message
from email.parser import BytesParser
from pathlib import Path

from email_analyzer.evidence_features import message_text


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict:
    """Reject ambiguous keys at every object depth without echoing input."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _finite_json_float(value: str) -> float:
    """Match evaluation's finite-number contract before training can start."""
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _load_manifest(path: Path, role: str) -> tuple[list, str]:
    try:
        raw = path.read_bytes()
    except OSError:
        raise ValueError(f"cannot read {role} manifest") from None
    rows = []
    # Match standalone evaluation: Unicode separators inside JSON strings
    # are data, not record boundaries. Decode per physical byte line.
    for line_no, raw_line in enumerate(raw.splitlines(), 1):
        try:
            line = raw_line.decode("utf-8")
            if not line.strip():
                continue
            row = json.loads(line, object_pairs_hook=_unique_json_object,
                             parse_constant=_finite_json_float, parse_float=_finite_json_float)
        except ValueError:
            raise ValueError(f"invalid JSON in {role} manifest at line {line_no}") from None
        if (not isinstance(row, dict)
                or not isinstance(row.get("eml"), str) or not row["eml"].strip()
                or type(row.get("label")) is not int or row["label"] not in (0, 1)):
            raise ValueError(f"invalid {role} manifest row at line {line_no}")
        group = row.get("group_id")
        if "group_id" in row and (not isinstance(group, str) or not group.strip()):
            raise ValueError(f"invalid {role} group_id at line {line_no}")
        if role == "training" and (group is None or row.get("split") not in ("train", "validation", "test")):
            raise ValueError(f"invalid training split/group_id at line {line_no}")
        rows.append((line_no, row))
    if not rows:
        raise ValueError(f"empty {role} manifest")
    return rows, hashlib.sha256(raw).hexdigest()


def normalized_body_sha256(message: Message) -> str | None:
    """Fingerprint a full nonempty body without altering inference input.

    Ignore the subject and transport headers. A shallow copy is sufficient:
    deleting a header replaces the copy's header list; MIME parts are read only.
    """
    body_message = copy.copy(message)
    del body_message["Subject"]
    body = message_text(body_message, limit=None)
    return hashlib.sha256(body.encode("utf-8")).hexdigest() if body else None


def _fingerprints(base: Path, row: dict, role: str, line_no: int) -> tuple[str, str | None]:
    try:
        raw = (base / row["eml"]).read_bytes()
        message = BytesParser(policy=policy.default).parsebytes(raw)
        body_hash = normalized_body_sha256(message)
    except (OSError, ValueError, UnicodeError):
        raise ValueError(f"cannot read/parse {role} EML at line {line_no}") from None
    # No truncation: a shared long prefix is not an exact duplicate. Empty or
    # attachment-only messages are checked by raw bytes/group, not empty text.
    return hashlib.sha256(raw).hexdigest(), body_hash


def check_independence(training_manifest: Path, external_manifest: Path) -> dict:
    """Reject overlap with ANY training-manifest split, independent of labels.

    External group_id is optional for legacy manifests. Missing group coverage
    is reported, not mistaken for proof that campaign groups are independent.
    Repeated external content is rejected, not counted as independent samples.
    """
    training, training_digest = _load_manifest(training_manifest, "training")
    external, external_digest = _load_manifest(external_manifest, "external")
    groups, raw_hashes, body_hashes = set(), set(), set()
    for line_no, row in training:
        groups.add(row["group_id"].strip())
        raw_hash, body_hash = _fingerprints(training_manifest.parent, row, "training", line_no)
        raw_hashes.add(raw_hash)
        if body_hash is not None:
            body_hashes.add(body_hash)
    missing_groups = 0
    external_raw_hashes, external_body_hashes = set(), set()
    for line_no, row in external:
        group = row.get("group_id")
        missing_groups += group is None
        if group is not None and group.strip() in groups:
            raise ValueError(f"group_id overlap with training manifest at external line {line_no}")
        raw_hash, body_hash = _fingerprints(external_manifest.parent, row, "external", line_no)
        if raw_hash in raw_hashes:
            raise ValueError(f"raw EML overlap with training manifest at external line {line_no}")
        if body_hash is not None and body_hash in body_hashes:
            raise ValueError(f"normalized body overlap with training manifest at external line {line_no}")
        if raw_hash in external_raw_hashes:
            raise ValueError(f"raw EML duplicate within external manifest at line {line_no}")
        if body_hash is not None and body_hash in external_body_hashes:
            raise ValueError(f"normalized body duplicate within external manifest at line {line_no}")
        external_raw_hashes.add(raw_hash)
        if body_hash is not None:
            external_body_hashes.add(body_hash)
    return {
        "passed": True,
        "training_rows": len(training), "external_rows": len(external),
        "external_rows_without_group_id": missing_groups,
        "training_manifest_sha256": training_digest,
        "external_manifest_sha256": external_digest,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Check training/external manifest independence offline")
    parser.add_argument("training_manifest", type=Path)
    parser.add_argument("external_manifest", type=Path)
    args = parser.parse_args()
    try:
        report = check_independence(args.training_manifest, args.external_manifest)
    except ValueError as exc:
        print(json.dumps({"passed": False, "error": str(exc)}))
        raise SystemExit(2) from None
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

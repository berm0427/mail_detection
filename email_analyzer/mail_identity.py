"""One definition of "the same mail" for analysis, training and evaluation.

Dataset bookkeeping headers (``X-Dataset-*``, ``X-Synthetic-Data``) carry the
label and split.  They are removed before anything reads a mail, and the mail's
identity is the SHA-256 of what remains.  Two files that differ only in those
headers are therefore the same mail, and a saved analysis, an evidence row or a
holdout entry can be tied to exact content rather than to a path or a
Message-ID.
"""
from __future__ import annotations

import hashlib
import re

LABEL_HEADERS = re.compile(rb"(?im)^(?:X-Dataset-[^:\r\n]*|X-Synthetic-Data):[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*\r?\n")
# Same headers, but the last line may end at end-of-input instead of a line break.
_LABEL_HEADERS_TO_END = re.compile(
    rb"(?im)^(?:X-Dataset-[^:\r\n]*|X-Synthetic-Data):[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*(?:\r?\n|\Z)")


def strip_label_headers(raw: bytes) -> tuple[bytes, int]:
    match = re.search(rb"\r?\n\r?\n", raw)
    if not match:
        raise ValueError("EML has no header/body separator")
    # Keep the complete line break that ends the last header (1 byte for LF,
    # 2 for CRLF); otherwise a label header in last position is not matched.
    end = match.start() + (2 if raw[match.start():match.start() + 2] == b"\r\n" else 1)
    head, rest = raw[:end], raw[end:]
    cleaned, removed = LABEL_HEADERS.subn(b"", head)
    return cleaned + rest, removed


def mail_digest(raw: bytes) -> str:
    """SHA-256 of the mail with dataset bookkeeping headers removed."""
    try:
        cleaned, _ = strip_label_headers(raw)
    except ValueError:
        # No header/body separator: the whole input is the header block.  Label
        # headers are removed the same way so identity does not depend on them.
        cleaned = _LABEL_HEADERS_TO_END.sub(b"", raw)
    return hashlib.sha256(cleaned).hexdigest()


def combined_digest(digests) -> str:
    """Identity of a set of mails, independent of order and of file paths."""
    return hashlib.sha256("\n".join(sorted(digests)).encode("ascii")).hexdigest()

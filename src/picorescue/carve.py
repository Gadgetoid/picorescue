"""Carve Python source out of raw flash regions.

Filesystem-agnostic recovery: most rescue targets are small UTF-8 text files
(MicroPython scripts). When a file is deleted or its directory entry is gone,
the *content* usually still sits in flash until that block is erased and
rewritten. We scan for printable text runs and score them for "Python-ness".
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

# Bytes we treat as "text": printable ASCII + tab/newline/carriage-return.
_TEXT = bytes(range(0x20, 0x7F)) + b"\t\n\r"
_TEXT_SET = set(_TEXT)

# Strong Python/MicroPython signals.
_KEYWORDS = re.compile(
    rb"\b(?:import|from|def|class|return|self|print|lambda|async|await|"
    rb"machine|micropython|const|while|for|if|elif|else|try|except|with|"
    rb"yield|raise|global|nonlocal)\b"
)
_ASSIGN = re.compile(rb"^\s*[A-Za-z_][A-Za-z0-9_]*\s*=", re.MULTILINE)
_DEF_OR_IMPORT = re.compile(rb"^\s*(?:def |class |import |from )", re.MULTILINE)


@dataclass
class Candidate:
    offset: int          # offset within the scanned region
    data: bytes
    score: float
    sha1: str

    @property
    def text(self) -> str:
        return self.data.decode("utf-8", "replace")

    @property
    def line_count(self) -> int:
        return self.data.count(b"\n") + 1

    def suggested_name(self) -> str:
        """Guess a filename from a shebang, module docstring, or first def/class."""
        head = self.data[:512]
        m = re.search(rb"^#\s*([\w.\-/]+\.py)\b", head, re.MULTILINE)
        if m:
            return m.group(1).decode("ascii", "replace").replace("/", "_")
        m = re.search(rb"^\s*class\s+([A-Za-z_]\w*)", head, re.MULTILINE)
        if m:
            return m.group(1).decode("ascii", "replace") + ".py"
        m = re.search(rb"^\s*def\s+([A-Za-z_]\w*)", head, re.MULTILINE)
        if m:
            return m.group(1).decode("ascii", "replace") + ".py"
        return "unknown.py"


def _text_runs(data: bytes, min_len: int):
    """Yield (offset, bytes) for maximal runs of text bytes >= min_len."""
    start = None
    for i, b in enumerate(data):
        if b in _TEXT_SET:
            if start is None:
                start = i
        else:
            if start is not None and i - start >= min_len:
                yield start, data[start:i]
            start = None
    if start is not None and len(data) - start >= min_len:
        yield start, data[start:]


def score(run: bytes) -> float:
    """Heuristic 0..~ score that a text run is Python source."""
    if not run:
        return 0.0
    s = 0.0
    kw = len(_KEYWORDS.findall(run))
    s += kw * 2.0
    s += len(_DEF_OR_IMPORT.findall(run)) * 4.0
    s += len(_ASSIGN.findall(run)) * 1.0
    # Reward multi-line, indented structure.
    lines = run.split(b"\n")
    if len(lines) >= 3:
        s += 2.0
    if any(ln.startswith((b"    ", b"\t")) for ln in lines):
        s += 2.0
    # Penalise runs that look like a single long blob (no newlines).
    if b"\n" not in run and len(run) > 200:
        s -= 3.0
    # Normalise lightly by length so a giant blob with one keyword doesn't win.
    return s


def carve(data: bytes, min_len: int = 40, min_score: float = 6.0,
          known_hashes: set[str] | None = None) -> list[Candidate]:
    """Return scored Python-source candidates found in ``data``."""
    known_hashes = known_hashes or set()
    out = []
    seen: set[str] = set()
    for offset, run in _text_runs(data, min_len):
        sc = score(run)
        if sc < min_score:
            continue
        # Trim leading/trailing junk to whole lines.
        trimmed = run.strip(b"\x00").strip()
        if not trimmed:
            continue
        sha1 = hashlib.sha1(trimmed).hexdigest()
        if sha1 in known_hashes or sha1 in seen:
            continue
        seen.add(sha1)
        out.append(Candidate(offset=offset, data=trimmed, score=sc, sha1=sha1))
    out.sort(key=lambda c: c.score, reverse=True)
    return out

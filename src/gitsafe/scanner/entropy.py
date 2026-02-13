"""Shannon entropy calculator and candidate extraction."""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import List, Tuple

# Tokenization: split on whitespace, quotes, = signs, colons, semicolons, commas
_TOKEN_RE = re.compile(r"""[^\s=:;,'"<>(){}\[\]]+""")


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy (bits per character) of string *s*.

    H = -Σ p(c) · log₂(p(c))  over unique characters c.
    """
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def extract_candidates(line: str, min_length: int = 16) -> List[str]:
    """Extract candidate secret strings from a line of text.

    Splits on whitespace, quotes, assignment operators and punctuation,
    then filters by *min_length*.
    """
    tokens = _TOKEN_RE.findall(line)
    # Also split on = and : within tokens
    candidates: List[str] = []
    for tok in tokens:
        # Strip leading/trailing quotes if partially captured
        tok = tok.strip("'\"")
        if len(tok) >= min_length:
            candidates.append(tok)
    return candidates


def find_high_entropy(
    line: str,
    min_entropy: float = 4.0,
    min_length: int = 16,
) -> List[Tuple[str, float]]:
    """Return (candidate, entropy) pairs from *line* that exceed thresholds."""
    results: List[Tuple[str, float]] = []
    for candidate in extract_candidates(line, min_length):
        h = shannon_entropy(candidate)
        if h >= min_entropy:
            results.append((candidate, h))
    return results

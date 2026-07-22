"""Lightweight deterministic code embeddings.

This is a stand-in for a real code embedding model (e.g. sentence-transformers).
Instead of downloading gigabytes of weights, we use the classic "hashing trick":
tokens and character n-grams are hashed into a fixed-width bag-of-features vector
which is then L2-normalised. Cosine similarity over these vectors is a genuine
lexical similarity measure -- close enough to prove the pgvector search path works
end to end, and swappable for a real model later without touching the query code.
"""

import hashlib
import re

import numpy as np

# Must match the Vector(...) column width in db.py.
EMBEDDING_DIM = 256

# Identifiers, numbers and standalone operators/punctuation.
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+|[^\sA-Za-z0-9_]")

_NGRAM_SIZE = 3
_NGRAM_WEIGHT = 0.25

# Purely lexical features are not enough for security code: a parameterised query
# and a concatenated one share nearly every token, yet only one is exploitable.
# These markers encode the *shape* of the dataflow and are weighted heavily so
# they dominate cosine similarity. A learned code model would infer this itself;
# here we extract it explicitly.
_MARKER_WEIGHT = 6.0

_TAINT_SOURCE_RE = re.compile(
    r"req\.(query|body|params)|request\.(args|form|json|get)|process\.argv"
    r"|sys\.argv|\binput\s*\(|getparameter|location\.(search|hash)"
)
_SAFE_SINK_RE = re.compile(
    r"console\.(log|debug|info|warn)|logger\.|logging\.|\btextcontent\b"
    r"|\binnertext\b|\bprint\s*\("
)
_DANGEROUS_SINK_RE = re.compile(
    r"\binnerhtml\b|\bouterhtml\b|document\.write|dangerouslysetinnerhtml"
    r"|\beval\s*\(|new\s+function|os\.system|shell\s*=\s*true|child_process"
    r"|\.popen|\bexecsync\b"
)
_QUERY_CALL_RE = re.compile(r"(query|execute|executemany)\s*\(")
_PLACEHOLDER_RE = re.compile(r"\$\d+|%s\b|:\w+\b")
_CONCAT_RE = re.compile(r"['\"]\s*\+|\+\s*(req|request|params|input)|\$\{|f['\"]")


def _markers(lowered: str) -> list[str]:
    """Extract weighted security-semantic features from a snippet."""
    feats: list[str] = []

    tainted = bool(_TAINT_SOURCE_RE.search(lowered))
    safe_sink = bool(_SAFE_SINK_RE.search(lowered))
    dangerous_sink = bool(_DANGEROUS_SINK_RE.search(lowered))

    if tainted:
        feats.append("taint_source")
    if safe_sink:
        feats.append("sink_safe")
    if dangerous_sink:
        feats.append("sink_dangerous")

    # The combination is what actually decides exploitability.
    if tainted and dangerous_sink:
        feats.append("flow_taint_to_dangerous_sink")
    if tainted and safe_sink and not dangerous_sink:
        feats.append("flow_taint_to_safe_sink")

    if _QUERY_CALL_RE.search(lowered):
        concatenated = bool(_CONCAT_RE.search(lowered))
        if concatenated:
            feats.append("sql_string_concatenation")
            if tainted:
                feats.append("flow_taint_to_sql_concat")
        elif _PLACEHOLDER_RE.search(lowered):
            feats.append("sql_parameter_binding")

    return feats


def _bucket(feature: str) -> int:
    digest = hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % EMBEDDING_DIM


def tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall(text.lower())


def embed(text: str) -> list[float]:
    """Turn a code snippet into a unit-length EMBEDDING_DIM vector."""
    vec = np.zeros(EMBEDDING_DIM, dtype=np.float32)

    tokens = tokenize(text)
    for token in tokens:
        vec[_bucket(f"tok:{token}")] += 1.0

    for marker in _markers(text.lower()):
        vec[_bucket(f"mark:{marker}")] += _MARKER_WEIGHT

    # Character n-grams keep near-identical snippets close together even when a
    # variable has been renamed.
    squashed = " ".join(tokens)
    for i in range(len(squashed) - _NGRAM_SIZE + 1):
        gram = squashed[i : i + _NGRAM_SIZE]
        vec[_bucket(f"ng:{gram}")] += _NGRAM_WEIGHT

    norm = float(np.linalg.norm(vec))
    if norm > 0.0:
        vec /= norm

    return vec.tolist()


def cosine_similarity(a: list[float], b: list[float]) -> float:
    va, vb = np.asarray(a, dtype=np.float32), np.asarray(b, dtype=np.float32)
    denom = float(np.linalg.norm(va) * np.linalg.norm(vb))
    return 0.0 if denom == 0.0 else float(np.dot(va, vb) / denom)

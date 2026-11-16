"""Sentinel AI Triage Layer.

Receives findings from the C++ analysis worker and decides whether each one is
worth showing a human, by searching a pgvector store of previously-dismissed
findings for a mathematically similar snippet.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import text

from db import FalsePositive, SessionLocal, TriageLog, init_db
from seed import seed
from vectorizer import embed

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger("triage")


def _threshold_from_env(default: float) -> float:
    """SUPPRESSION_THRESHOLD from the environment, if it is a usable value.

    A threshold outside (0, 1] would suppress everything or nothing, and a
    typo should not silently do either, so anything else refuses to start.
    """
    raw = os.getenv("SUPPRESSION_THRESHOLD")
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise SystemExit(f"SUPPRESSION_THRESHOLD={raw!r} is not a number") from None
    if not 0.0 < value <= 1.0:
        raise SystemExit(f"SUPPRESSION_THRESHOLD={raw!r} must be in (0, 1]")
    return value


# Cosine similarity above which we treat a finding as a repeat of a known
# false positive. Tuned by hand for the hashing vectorizer.
SUPPRESSION_THRESHOLD = _threshold_from_env(0.85)

# The worker sends one source line per finding. This bound is far above that;
# it exists so a single request cannot make the vectorizer chew on megabytes.
MAX_SNIPPET_CHARS = 20_000


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    inserted = seed()
    if inserted:
        log.info("seeded %d known false positives into pgvector", inserted)
    log.info("ready (suppression threshold %.2f)", SUPPRESSION_THRESHOLD)
    yield


app = FastAPI(title="Sentinel AI Triage Layer", lifespan=lifespan)


class Finding(BaseModel):
    repository: str = Field(max_length=1024)
    file: str = Field(max_length=4096)
    vulnerability_type: str = Field(max_length=256)
    snippet: str = Field(max_length=MAX_SNIPPET_CHARS)
    line: int = 0


class Match(BaseModel):
    snippet: str
    vulnerability_type: str
    reason: str
    similarity: float


class TriageResponse(BaseModel):
    suppress: bool
    confidence: float
    reason: str
    nearest_match: Match | None = None


# A plain `def`, not `async def`: the handler does blocking database I/O, and
# FastAPI runs sync handlers in a thread pool. As a coroutine it would hold the
# event loop for the length of every query and serialise all requests.
@app.post("/api/v1/triage", response_model=TriageResponse)
def triage_finding(finding: Finding) -> TriageResponse:
    log.info(
        "%s in %s:%d (%s)",
        finding.vulnerability_type, finding.file, finding.line, finding.repository,
    )

    query_vector = embed(finding.snippet)
    session = SessionLocal()
    try:
        # pgvector cosine distance: 0 == identical, 2 == opposite.
        distance = FalsePositive.embedding.cosine_distance(query_vector)
        row = (
            session.query(FalsePositive, distance.label("distance"))
            .order_by(distance)
            .limit(1)
            .first()
        )

        if row is None:
            response = TriageResponse(
                suppress=False,
                confidence=0.0,
                reason="No false-positive history in pgvector yet; escalating.",
            )
        else:
            candidate, dist = row
            similarity = 1.0 - float(dist)
            match = Match(
                snippet=candidate.snippet,
                vulnerability_type=candidate.vulnerability_type,
                reason=candidate.reason,
                similarity=round(similarity, 4),
            )

            if similarity >= SUPPRESSION_THRESHOLD:
                response = TriageResponse(
                    suppress=True,
                    confidence=round(similarity, 4),
                    reason=(
                        f"Cosine similarity {similarity:.3f} to a dismissed "
                        f"{candidate.vulnerability_type} finding: {candidate.reason}"
                    ),
                    nearest_match=match,
                )
            else:
                response = TriageResponse(
                    suppress=False,
                    confidence=round(similarity, 4),
                    reason=(
                        f"Nearest known false positive is only {similarity:.3f} "
                        f"similar (threshold {SUPPRESSION_THRESHOLD}); escalating."
                    ),
                    nearest_match=match,
                )

        session.add(
            TriageLog(
                # Clipped to the column widths in db.py: an unusually long path
                # must not turn a verdict into a database error.
                repository=finding.repository[:256],
                file=finding.file[:512],
                vulnerability_type=finding.vulnerability_type[:128],
                suppressed=str(response.suppress).lower(),
                confidence=f"{response.confidence:.4f}",
                reason=response.reason,
            )
        )
        session.commit()
    finally:
        session.close()

    verdict = "SUPPRESSED" if response.suppress else "ESCALATED"
    log.info("-> %s (confidence %.3f)", verdict, response.confidence)
    return response


@app.get("/health")
def health():
    session = SessionLocal()
    try:
        session.execute(text("SELECT 1"))
        known = session.query(FalsePositive).count()
        return {
            "status": "AI Triage Layer is active",
            "database": "connected",
            "known_false_positives": known,
        }
    except Exception:
        # 503, so a health check that only reads the status code sees the
        # outage. The cause goes to the log, not to whoever asked: a driver
        # error can carry the connection string.
        log.exception("health check could not reach the database")
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", "database": "unreachable"},
        )
    finally:
        session.close()

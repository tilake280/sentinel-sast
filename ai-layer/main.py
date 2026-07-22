"""Sentinel AI Triage Layer.

Receives findings from the C++ analysis worker and decides whether each one is
worth showing a human, by searching a pgvector store of previously-dismissed
findings for a mathematically similar snippet.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import text

from db import FalsePositive, SessionLocal, TriageLog, init_db
from seed import seed
from vectorizer import embed

# Cosine similarity above which we treat a finding as a repeat of a known
# false positive. Tuned by hand for the hashing vectorizer.
SUPPRESSION_THRESHOLD = 0.85


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    inserted = seed()
    if inserted:
        print(f"[startup] Seeded {inserted} known false positives into pgvector.")
    print("[startup] AI Triage Layer ready.")
    yield


app = FastAPI(title="Sentinel AI Triage Layer", lifespan=lifespan)


class Finding(BaseModel):
    repository: str
    file: str
    vulnerability_type: str
    snippet: str
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


@app.post("/api/v1/triage", response_model=TriageResponse)
async def triage_finding(finding: Finding) -> TriageResponse:
    print(
        f"[triage] {finding.vulnerability_type} in {finding.file}"
        f":{finding.line} ({finding.repository})"
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
                repository=finding.repository,
                file=finding.file,
                vulnerability_type=finding.vulnerability_type,
                suppressed=str(response.suppress).lower(),
                confidence=f"{response.confidence:.4f}",
                reason=response.reason,
            )
        )
        session.commit()
    finally:
        session.close()

    verdict = "SUPPRESSED" if response.suppress else "ESCALATED"
    print(f"[triage] -> {verdict} (confidence {response.confidence:.3f})")
    return response


@app.get("/health")
def health() -> dict:
    session = SessionLocal()
    try:
        session.execute(text("SELECT 1"))
        known = session.query(FalsePositive).count()
        return {
            "status": "AI Triage Layer is active",
            "database": "connected",
            "known_false_positives": known,
        }
    except Exception as exc:  # pragma: no cover - surfaced via /health only
        return {"status": "degraded", "database": f"error: {exc}"}
    finally:
        session.close()

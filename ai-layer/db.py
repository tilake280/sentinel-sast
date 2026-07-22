"""Database wiring for the pgvector-backed false-positive memory."""

import os

from pgvector.sqlalchemy import Vector
from sqlalchemy import Column, DateTime, Integer, String, Text, create_engine, func, text
from sqlalchemy.orm import declarative_base, sessionmaker

from vectorizer import EMBEDDING_DIM

DATABASE_URL = os.getenv(
    "SENTINEL_DATABASE_URL",
    "postgresql+psycopg2://sentinel:password@localhost:5432/sentinel_db",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, future=True)

Base = declarative_base()


class FalsePositive(Base):
    """A finding a human previously dismissed, kept as a vector for recall."""

    __tablename__ = "false_positives"

    id = Column(Integer, primary_key=True)
    vulnerability_type = Column(String(128), nullable=False)
    snippet = Column(Text, nullable=False)
    reason = Column(Text, nullable=False)
    embedding = Column(Vector(EMBEDDING_DIM), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class TriageLog(Base):
    """Every verdict we hand back, so the decisions are auditable."""

    __tablename__ = "triage_log"

    id = Column(Integer, primary_key=True)
    repository = Column(String(256), nullable=False)
    file = Column(String(512), nullable=False)
    vulnerability_type = Column(String(128), nullable=False)
    suppressed = Column(String(8), nullable=False)
    confidence = Column(String(32), nullable=False)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


def init_db() -> None:
    """Enable pgvector and create tables. Safe to call repeatedly."""
    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
        conn.commit()
    Base.metadata.create_all(engine)

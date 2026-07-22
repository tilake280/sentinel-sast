"""Seed the pgvector store with previously-dismissed findings.

In production these rows accumulate from analysts clicking "dismiss" in the UI.
For the prototype we preload a representative corpus so similarity search has
something to match against.
"""

from db import FalsePositive, SessionLocal, init_db
from vectorizer import embed

KNOWN_FALSE_POSITIVES = [
    (
        "XSS",
        "console.log('user input was: ' + req.query.name);",
        "Tainted value only reaches a logging sink, not the DOM.",
    ),
    (
        "XSS",
        "console.log(`debug: ${req.body.comment}`);",
        "Template-literal logging of request data; no rendering involved.",
    ),
    (
        "SQL Injection",
        "db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);",
        "Parameterised query -- the driver escapes the bound value.",
    ),
    (
        "SQL Injection",
        "cursor.execute('SELECT * FROM logs WHERE level = %s', (level,))",
        "psycopg2 parameter binding, not string concatenation.",
    ),
    (
        "Command Injection",
        "subprocess.run(['git', 'status'], cwd=repo_path, check=True)",
        "Argument vector form with a constant binary; no shell involved.",
    ),
    (
        "Path Traversal",
        "open(os.path.join(FIXTURES_DIR, 'sample.json')) # test helper",
        "Path is built from a test fixture constant, not user input.",
    ),
    (
        "Hardcoded Secret",
        "API_KEY = 'test-key-placeholder-do-not-use' # unit test stub",
        "Placeholder credential inside a test file.",
    ),
    (
        "XSS",
        "element.textContent = req.query.title;",
        "textContent assignment does not parse HTML, so it cannot execute script.",
    ),
]


def seed(force: bool = False) -> int:
    """Insert the corpus if the table is empty. Returns rows inserted."""
    init_db()
    session = SessionLocal()
    try:
        if force:
            session.query(FalsePositive).delete()
            session.commit()
        elif session.query(FalsePositive).count() > 0:
            return 0

        for vuln_type, snippet, reason in KNOWN_FALSE_POSITIVES:
            session.add(
                FalsePositive(
                    vulnerability_type=vuln_type,
                    snippet=snippet,
                    reason=reason,
                    embedding=embed(snippet),
                )
            )
        session.commit()
        return len(KNOWN_FALSE_POSITIVES)
    finally:
        session.close()


if __name__ == "__main__":
    inserted = seed(force=True)
    print(f"Seeded {inserted} known false positives into pgvector.")

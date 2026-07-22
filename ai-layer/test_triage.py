"""End-to-end check of the pgvector suppression logic.

Run against a live postgres:  ./venv/bin/python test_triage.py
"""

import sys

from db import FalsePositive, SessionLocal
from main import SUPPRESSION_THRESHOLD
from seed import seed
from vectorizer import embed

# (label, snippet, expect_suppressed)
CASES = [
    ("near-dup of logging FP", "console.log('user input was: ' + req.query.email);", True),
    ("parameterised pg query", "db.query('SELECT * FROM accounts WHERE id = $1', [req.params.id]);", True),
    ("psycopg2 binding", "cursor.execute('SELECT * FROM events WHERE kind = %s', (kind,))", True),
    ("safe textContent sink", "element.textContent = req.query.subtitle;", True),
    ("real SQL injection", "db.query('SELECT * FROM users WHERE id = ' + req.query.id);", False),
    ("real XSS sink", "element.innerHTML = req.query.title;", False),
    ("real command injection", 'os.system("ping " + request.args.get("host"))', False),
    ("real eval RCE", "eval(req.body.expression);", False),
    ("shell=True subprocess", 'subprocess.run(cmd, shell=True)  # cmd from req.query', False),
]


def nearest(session, snippet):
    distance = FalsePositive.embedding.cosine_distance(embed(snippet))
    candidate, dist = (
        session.query(FalsePositive, distance.label("d")).order_by(distance).limit(1).first()
    )
    return candidate, 1.0 - float(dist)


def main() -> int:
    seed(force=True)
    session = SessionLocal()
    failures = 0
    try:
        for label, snippet, expect_suppressed in CASES:
            candidate, similarity = nearest(session, snippet)
            suppressed = similarity >= SUPPRESSION_THRESHOLD
            ok = suppressed == expect_suppressed
            failures += not ok
            status = "PASS" if ok else "FAIL"
            verdict = "SUPPRESS" if suppressed else "ESCALATE"
            print(f"[{status}] {verdict} sim={similarity:.3f}  {label}")
            if not ok:
                print(f"         expected {'SUPPRESS' if expect_suppressed else 'ESCALATE'}")
                print(f"         nearest: {candidate.snippet[:70]}")
    finally:
        session.close()

    print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

"""Checks of the triage service around the verdict: limits, audit log, health.

Run against a live postgres:  ./venv/bin/python test_api.py

test_triage.py checks which snippets are suppressed; this checks the service
around that decision. It calls the request model and handlers directly rather
than over HTTP, so it needs nothing started beyond postgres and no HTTP client
installed.
"""

import sys

from pydantic import ValidationError
from sqlalchemy.exc import OperationalError

import main
from db import init_db
from seed import seed

FINDING = {
    "repository": "acme/web",
    "file": "src/routes/users.js",
    "vulnerability_type": "SQL Injection",
    "snippet": "db.query('SELECT * FROM users WHERE id = ' + req.query.id);",
    "line": 7,
}


def rejected(payload: dict) -> bool:
    """Whether request validation refuses the payload (FastAPI answers 422)."""
    try:
        main.Finding(**payload)
    except ValidationError:
        return True
    return False


def run() -> int:
    results: list[tuple[bool, str]] = []

    def check(condition: bool, label: str, detail: object = "") -> None:
        results.append((bool(condition), label))
        print(f"[{'PASS' if condition else 'FAIL'}] {label}"
              + (f"\n         {detail}" if detail and not condition else ""))

    init_db()
    seed(force=True)

    health = main.health()
    check(isinstance(health, dict) and health["database"] == "connected",
          "health reports the database connected", health)

    verdict = main.triage_finding(main.Finding(**FINDING))
    check(verdict.suppress is False, "a real SQL injection is escalated", verdict)

    # The worker sends fields this service does not model yet.
    check(not rejected({**FINDING, "rule_id": "js.sqli", "trace": []}),
          "unknown fields from the worker are accepted")

    long_path = main.triage_finding(main.Finding(**{**FINDING, "file": "a/" * 600 + "x.js"}))
    check(long_path.reason != "", "a path longer than the audit column still gets a verdict")

    check(rejected({**FINDING, "snippet": "x" * (main.MAX_SNIPPET_CHARS + 1)}),
          "an oversized snippet is rejected")
    check(not rejected({**FINDING, "snippet": "x" * main.MAX_SNIPPET_CHARS}),
          "a snippet exactly at the limit is accepted")
    check(rejected({"repository": "acme/web"}), "a finding with fields missing is rejected")

    # Database down: /health must say so in its status code, and must not
    # repeat the driver's message (which can include the connection URL).
    real_session = main.SessionLocal

    class DownSession:
        def execute(self, *_args, **_kwargs):
            raise OperationalError("SELECT 1", {}, Exception("secret-dsn@db:5432 refused"))

        def close(self):
            pass

    main.SessionLocal = DownSession
    try:
        down = main.health()
    finally:
        main.SessionLocal = real_session
    status = getattr(down, "status_code", 200)
    text = down.body.decode() if hasattr(down, "body") else str(down)
    check(status == 503, "health is 503 with the database down", status)
    check("secret-dsn" not in text and "unreachable" in text,
          "health does not leak the database error", text)

    passed = sum(ok for ok, _ in results)
    print(f"\n{passed}/{len(results)} passed")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(run())

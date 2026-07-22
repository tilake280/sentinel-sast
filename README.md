# Sentinel SAST

Static analysis pipeline with AI-based false-positive suppression.

```
webhook -> gateway (Go) --X   RabbitMQ -> worker (C++) -> triage (Python) -> pgvector
                          ^
              not wired up yet; publish jobs with scripts/publish_test_job.py
```

| Component  | Stack            | Role                                                       | Status |
|------------|------------------|------------------------------------------------------------|--------|
| `gateway/` | Go + Fiber       | Webhook ingestion, queues scan jobs                         | Accepts webhooks and returns 202, but does **not** publish to RabbitMQ yet — signature validation and the DB insert are still TODO |
| `worker/`  | C++17            | Tree-sitter AST + taint analysis, calls the AI layer        | Working |
| `ai-layer/`| Python + FastAPI | pgvector similarity search against dismissed findings       | Working |
| `frontend/`| Next.js          | UI                                                          | Scaffold only, not connected to the backend |

The worker → triage → pgvector half of the pipeline runs end to end. The two ends
(gateway publishing, frontend display) are not connected yet.

## Analysis engine

`worker/src/analyzer.cpp` parses each file with **Tree-sitter** and runs taint
analysis over the real syntax tree. Supported languages: **JavaScript, Python,
Go** — chosen by file extension, grammars vendored in `worker/third_party/`.

How it works:

1. Parse to a concrete syntax tree with the language's grammar.
2. Extract assignments and calls by AST node type and field (not by regex), so
   comments, docstrings and string literals cannot produce findings.
3. Propagate taint from attacker-controlled sources **to a fixpoint**, so flows
   are found regardless of statement order.
4. Report calls and property writes where a tainted value reaches a sink.

Sources and sinks per language are declared in `worker/src/languages.cpp` —
that's the file to edit to add a rule or a language.

Known limits: analysis is **intraprocedural** (taint is not tracked across
function boundaries), there is no sanitizer modelling, and rules are C++ over
the AST rather than Datalog.

### What is still a prototype

**The embeddings** (`ai-layer/vectorizer.py`) use the hashing trick plus
hand-extracted security markers instead of a learned code model — no gigabytes
of weights to download. The pgvector storage and cosine search are real; only
the vectors are cheap.

## Setup

One-time system dependencies for the C++ worker:

```bash
sudo apt-get install -y librabbitmq-dev libcurl4-openssl-dev nlohmann-json3-dev
```

Tree-sitter itself needs no system package — the runtime and all three grammars
are vendored and built by the Makefile. If `worker/third_party/` is empty:

```bash
cd worker/third_party && for r in tree-sitter tree-sitter-javascript tree-sitter-python tree-sitter-go; do git clone --depth 1 https://github.com/tree-sitter/$r.git $r; done
```

Python dependencies live in `ai-layer/venv` (already installed: `fastapi`,
`uvicorn`, `psycopg2-binary`, `pgvector`, `sqlalchemy`, `numpy`, `pika`).

## Running

**1. Infrastructure** (postgres/pgvector, rabbitmq, redis):

```bash
docker compose up -d
```

**2. AI triage layer** — creates tables, enables the `vector` extension and
seeds the false-positive corpus on startup:

```bash
cd ai-layer && ./venv/bin/uvicorn main:app --reload --port 8000
```

**3. Analysis worker:**

```bash
cd worker && make && ./build/sentinel-worker
```

**4. Publish a test scan job:**

```bash
./ai-layer/venv/bin/python scripts/publish_test_job.py
```

The worker log shows each finding, then `SUPPRESSED` or `ESCALATED` per the AI
verdict:

```
[worker] parsing AST + running taint query: internal/api/handlers.go
[worker]   FINDING SQL Injection at internal/api/handlers.go:10
[worker]     db.Query("SELECT * FROM users WHERE name = '" + name + "'")
[worker]     ESCALATED (0.2831) Nearest known false positive is only 0.283 similar
[worker]   FINDING SQL Injection at src/routes/safe.js:2
[worker]     db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
[worker]     SUPPRESSED (0.9084) Cosine similarity to a dismissed finding:
             Parameterised query -- the driver escapes the bound value.
[worker] job b96dbdc2 complete: 9 findings, 2 suppressed by AI, 7 escalated
```

## Tests

Analyzer — 18 tests across all three languages, no broker or database needed:

```bash
cd worker && make test
```

Triage — 9 tests, requires postgres up (re-seeds the corpus):

```bash
cd ai-layer && ./venv/bin/python test_triage.py
```

## Configuration

The worker reads `RABBITMQ_HOST`, `RABBITMQ_PORT`, `RABBITMQ_USER`,
`RABBITMQ_PASSWORD`, `SCAN_QUEUE`, and `TRIAGE_URL`. The AI layer reads
`SENTINEL_DATABASE_URL`. All default to the local Docker services.

Suppression threshold: `SUPPRESSION_THRESHOLD` in `ai-layer/main.py` (0.85).

## Version control

This directory is not a git repo yet. Before `git init`, note that
`worker/third_party/` holds four cloned grammar repos (each with its own
`.git/`); a `.gitignore` is included that excludes them along with build output
and the venv. If you'd rather pin the grammars, add them as submodules instead.

## Next steps

- **Wire the gateway to RabbitMQ** so real webhooks trigger scans; today only
  `scripts/publish_test_job.py` publishes.
- **Interprocedural taint** — the biggest analysis gap. A source passed into a
  helper that reaches a sink is currently missed.
- **Sanitizer modelling** — `escape(userInput)` is still treated as tainted.
- **Type-aware sink matching** — sinks match on the last dotted segment, so any
  `.exec(` matches regardless of receiver type.
- **Real embeddings** — swap `vectorizer.py` for a code embedding model; the
  pgvector query path stays the same.
- **Feed the UI and close the loop** so analyst dismissals write new rows into
  `false_positives`, which is what makes suppression improve over time.

# Sentinel SAST

Static analysis pipeline with AI-based false-positive suppression.

```
webhook -> gateway (Go) -> RabbitMQ -> worker (C++) -> triage (Python) -> pgvector
              ^                           |
              |                           v
frontend <- Postgres <- gateway <- RabbitMQ (results)
```

| Component  | Stack            | Role                                                                 | Status  |
|------------|------------------|----------------------------------------------------------------------|---------|
| `gateway/` | Go + Fiber       | Validates webhooks, queues scan jobs, stores results, serves the read API | Working |
| `worker/`  | C++23            | Tree-sitter AST + taint analysis, calls the AI layer                 | Working |
| `ai-layer/`| Python + FastAPI | pgvector similarity search against dismissed findings                | Working |
| `frontend/`| Next.js          | Lists scans and shows each finding with its triage verdict           | Working |

A signed push webhook produces a scan end to end: the gateway records it and
queues the changed files, the worker analyses them and asks the triage layer
about each finding, and the result is stored and shown in the UI.

## Analysis engine

`worker/src/analyzer.cpp` parses each file with **Tree-sitter** and runs taint
analysis over the real syntax tree. Supported languages: **JavaScript, Python,
Go** — chosen by file extension, grammars vendored in `worker/third_party/`.

How it works:

1. Parse to a concrete syntax tree with the language's grammar.
2. Extract assignments and calls by AST node type and field (not by regex), so
   comments, docstrings and string literals cannot produce findings.
3. Summarise each function — which parameters reach a sink, which flow back out
   — to a fixpoint over the call graph, so a sink several helpers away from the
   request is still found.
4. Propagate taint from attacker-controlled sources **to a fixpoint**, so flows
   are found regardless of statement order.
5. Report calls and property writes where a tainted value reaches a sink,
   unless a sanitizer for that vulnerability class was applied on the way.

It detects 14 vulnerability classes. Eight are covered in all three languages:
SQL injection, command injection, cross-site scripting, path traversal, SSRF,
code injection, open redirect and insecure deserialization. `sentinel-worker
--rules` prints the full class-by-language matrix.

Sources, sinks and sanitizers per language are declared in
`worker/src/languages.cpp` — that's the file to edit to add a rule or a
language. See `worker/README.md` for the engine in detail.

Known limits: analysis is **per file** (a request read in one file and used in
a query in another is not connected), there is no field sensitivity, calls are
matched to functions by name, and rules are C++ over the AST rather than
Datalog.

### What is still a prototype

**The embeddings** (`ai-layer/vectorizer.py`) use the hashing trick plus
hand-extracted security markers instead of a learned code model — no gigabytes
of weights to download. The pgvector storage and cosine search are real; only
the vectors are cheap.

**The false-positive store** holds 8 seeded examples. Nothing yet writes an
analyst's dismissal back into it, so on unfamiliar code the triage layer has
little to match against.

## Benchmark

`scripts/run_benchmark.py` scans 659 source files from 12 public repositories
pinned to fixed commits — deliberately vulnerable teaching apps and ordinary
projects (express, flask, gin) — and reports what was found.

| | |
|---|---|
| Files scanned | 659 (205 JavaScript, 201 Python, 253 Go) |
| Findings | 76, in 11 classes |
| Precision on a labelled sample of 50 | 64% |
| Precision among high- and medium-confidence findings in that sample | 20 of 21 |

Read `benchmark/NOTES.md` before quoting these. The precision figure is
measured on a corpus the rules were also adjusted against, recall is not
measured, and the triage layer suppressed none of the 76.

```bash
python3 scripts/fetch_corpus.py
python3 scripts/run_benchmark.py
```

## Setup

One-time system dependencies for the C++ worker (GCC 13 or later):

```bash
sudo apt-get install -y librabbitmq-dev libcurl4-openssl-dev nlohmann-json3-dev
```

Tree-sitter itself needs no system package — the runtime and all three grammars
are vendored and built by the Makefile. If `worker/third_party/` is empty:

```bash
cd worker/third_party && for r in tree-sitter tree-sitter-javascript tree-sitter-python tree-sitter-go; do git clone --depth 1 https://github.com/tree-sitter/$r.git $r; done
```

Python dependencies live in `ai-layer/venv` (`fastapi`, `uvicorn`,
`psycopg2-binary`, `pgvector`, `sqlalchemy`, `numpy`, `pika`). The gateway
needs Go 1.22 or later; the frontend needs Node 20 and pnpm.

## Running

**1. Infrastructure** (postgres/pgvector, rabbitmq, redis):

```bash
docker compose up -d
```

If something else already uses port 5432, copy `.env.example` to `.env`, set
`POSTGRES_PORT`, and point `SENTINEL_DATABASE_URL` and `DATABASE_URL` at it.

**2. AI triage layer** — creates tables, enables the `vector` extension and
seeds the false-positive corpus on startup:

```bash
cd ai-layer && ./venv/bin/uvicorn main:app --reload --port 8000
```

**3. Analysis worker:**

```bash
cd worker && make && ./build/sentinel-worker
```

**4. Gateway** — set `GITHUB_WEBHOOK_SECRET` first; with no secret it refuses
every webhook rather than accepting unsigned ones:

```bash
cd gateway && GITHUB_WEBHOOK_SECRET=<secret> go run .
```

**5. Frontend:**

```bash
cd frontend && pnpm install && pnpm dev
```

Point a GitHub push webhook at `POST /api/v1/webhook` on the gateway, or queue
a sample job directly:

```bash
./ai-layer/venv/bin/python scripts/publish_test_job.py
```

The worker log shows each finding, then `SUPPRESSED` or `ESCALATED` per the AI
verdict, and the scan appears in the frontend at `http://localhost:3000`:

```
[worker] parsed internal/api/handlers.go (go, 3 function(s), 1.2ms)
[worker]   CRITICAL SQL Injection at internal/api/handlers.go:10
[worker]     db.Query("SELECT * FROM users WHERE name = '" + name + "'")
[worker]     ESCALATED (0.2831) Nearest known false positive is only 0.283 similar
[worker]   LOW Log Injection at src/routes/user.js:6
[worker]     console.log('search term was: ' + req.query.term);
[worker]     SUPPRESSED (0.9607) Cosine similarity 0.961 to a dismissed XSS finding
[worker] job b96dbdc2 complete: 4 file(s), 8 finding(s), 1 suppressed by AI, 7 escalated
```

## Tests

Analyzer — 621 assertions in 32 suites across all three languages, no broker or
database needed:

```bash
cd worker && make test
```

Triage — 9 tests, requires postgres up (re-seeds the corpus):

```bash
cd ai-layer && ./venv/bin/python test_triage.py
```

Gateway — 27 tests against the real handlers; set `GATEWAY_TEST_DATABASE_URL`
to also run the Postgres store test:

```bash
cd gateway && go test ./...
```

End to end — starts its own gateway, worker and triage layer, posts a signed
webhook and checks the scan completes with findings and verdicts. Needs the
infrastructure up and the worker built:

```bash
./ai-layer/venv/bin/python scripts/e2e_webhook.py
```

## Configuration

All of these default to the local Docker services; `.env.example` lists them.

| Variable | Read by | Purpose |
|---|---|---|
| `RABBITMQ_HOST`, `RABBITMQ_PORT`, `RABBITMQ_USER`, `RABBITMQ_PASSWORD` | worker, gateway | Broker connection |
| `SCAN_QUEUE`, `RESULTS_QUEUE` | worker, gateway | Job and result queue names |
| `TRIAGE_URL` | worker | AI triage endpoint |
| `SENTINEL_DATABASE_URL` | AI layer | Postgres (SQLAlchemy URL) |
| `DATABASE_URL` | gateway | Postgres (scans and findings) |
| `GITHUB_WEBHOOK_SECRET` | gateway | Shared secret for `X-Hub-Signature-256` |
| `GITHUB_RAW_BASE_URL`, `GITHUB_TOKEN` | gateway | Where changed files are fetched from; token for private repos |
| `GATEWAY_ADDR` | gateway | Listen address (default `:3001`) |
| `GATEWAY_URL` | frontend | Gateway base URL (default `http://localhost:3001`) |

Suppression threshold: `SUPPRESSION_THRESHOLD` in `ai-layer/main.py` (0.85).

## Next steps

- **Cross-file analysis** — the biggest analysis gap. A source in one module
  reaching a sink in another is missed.
- **Field sensitivity** — tainting `user.name` currently taints all of `user`.
- **Close the triage loop** so analyst dismissals in the UI write new rows into
  `false_positives`, which is what makes suppression improve over time.
- **Real embeddings** — swap `vectorizer.py` for a code embedding model; the
  pgvector query path stays the same.

# Benchmark notes

What the numbers in `results/` mean, and how far they can be trusted.

## Reproducing

```bash
python3 scripts/fetch_corpus.py      # clone the 12 pinned repositories (needs network)
cd worker && make && cd ..
python3 scripts/run_benchmark.py     # prints the summary, saves results/
```

The triage layer must be running for verdicts (`cd ai-layer && ./venv/bin/uvicorn main:app --port 8000`).
Without it the run still completes and reports every finding as UNTRIAGED.

## The corpus

12 public repositories at fixed commits (`corpus.json`): 9 deliberately vulnerable
teaching applications and 3 ordinary maintained projects (express, flask, gin).
659 source files after exclusions: 205 JavaScript, 201 Python, 253 Go.

Excluded: `static/`, `bower_components/` and Django `migrations/` directories,
`*.min.js`, plus what the worker skips by itself (`node_modules`, `vendor`, `dist`,
`build`). One minified bundle that the name-based exclusions missed is skipped by
the worker's own minified-file check and counted separately.

## Two runs

| | Before fixes | After fixes |
|---|---|---|
| Summary | `results/summary-before-fixes.txt` | `results/summary.txt` |
| Findings | 97 | 76 |
| Precision on the 50-finding sample | 48% (24 of 50) | 64% (32 of 50) |

"Before" is the engine as it stood when the benchmark was first run. Reading that
sample turned up eight causes of false positives that were bugs or over-broad
rules rather than judgement calls, and they were fixed:

1. A setting inside a nested literal was reported twice, once per enclosing entry.
2. Source patterns matched by substring: `r.Format` matched the source `r.Form`.
3. Arguments to a Go prepared statement (`stmt.QueryRow(name)`) were treated as SQL text.
4. A Sequelize `find({ where: ... })` was reported as NoSQL injection.
5. `Math.random()` / `random.random()` were reported wherever they appeared, not only
   where the value needs to be unpredictable.
6. `loads()` on any object was reported as insecure deserialization.
7. A flaw reported as a taint flow was reported again by a pattern rule on the same call.
8. Input from argv or the environment scored the same confidence as input from a request.

Each has a regression test in `worker/tests/test_analyzer.cpp`
(`benchmark_regression_suite`). Every finding the fixes removed was checked: all
were labelled false positives, duplicates of one, or the same false positive on a
neighbouring line. No labelled true positive was lost.

**The "after" figure is optimistic.** It is measured on the same corpus whose
findings were used to decide what to fix. On code the rules have not been adjusted
against, expect precision somewhere between the two figures.

## Precision by the engine's own confidence (after fixes)

| Confidence | True positive | False positive | Precision |
|---|---|---|---|
| HIGH | 5 | 1 | 83% |
| MEDIUM | 15 | 0 | 100% |
| LOW | 12 | 17 | 41% |

The confidence score separates the findings well: 20 of 21 sampled HIGH or MEDIUM
findings were real, and 17 of the 18 false positives were LOW.

## What the remaining false positives are

From the reasons in `labels.csv`, for the 18 in the final sample:

- Certificate verification disabled in test code talking to a local test server
  or proxy (7).
- A database error logged, where taint arrived through the return value of a call
  the engine has no model of (4).
- Environment variables or argv read by a CLI or build script (3). These are now
  capped at LOW confidence rather than dropped.
- A redirect or file read that is safe for a reason the engine cannot see (3).
  Two come from tainting a whole object when one field is assigned
  (`req.user.name = ...` taints all of `req`): the engine has no field
  sensitivity. One is an `http.FileSystem` that confines the path itself.
- SHA-1 used as the digest inside an HMAC (1). This is the one false positive
  the engine rated HIGH confidence.

## What this does not show

- **Recall.** Nothing here counts vulnerabilities the analyzer missed, and it
  misses many. Analysis is per file, so a request read in one file and used in a
  query in another is not connected: `vulpy` (63 files, full of deliberate SQL
  injection in a separate data layer) yields 1 finding, and NodeGoat's NoSQL
  injection is not found for the same reason.
- **Triage effectiveness.** The triage layer ruled on every finding and suppressed
  none. Its store holds 8 seeded examples and no real analyst dismissals, so on
  this corpus it had nothing similar to match.
- **Independent review.** The labels are one reviewer's reading and have not been
  checked by a second person. The `reason` column is there so each can be.

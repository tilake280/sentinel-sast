# Sentinel analysis worker

AST-based taint analysis for JavaScript, Python and Go. 8,244 lines of C++23,
no runtime dependency beyond Tree-sitter for the analysis core.

```bash
make                       # build build/sentinel-worker
make test                  # 621 assertions in 32 suites, no broker or database
./build/sentinel-worker --rules
```

## Two modes

```bash
sentinel-worker                              # consume scan jobs from RabbitMQ
sentinel-worker --scan path/to/repo          # scan locally, no infrastructure
```

The local mode is what makes the engine usable in CI and demonstrable without
standing anything up. `demo/run-demo.sh` in the repository root drives it
through twelve sections.

### Scan options

| Flag | Effect |
|---|---|
| `--scan <path>` | File or directory to analyse |
| `--format <fmt>` | `text` (default), `sarif`, `line`, `json`, `report` (every finding with its triage verdict, plus per-file records) |
| `--exclude <pattern>` | Skip a directory or file by name, or by suffix with a leading `*` (`*.min.js`). Repeatable |
| `--output <file>` | Write the report to a file |
| `--fail-on <sev>` | Exit 1 if a finding is at or above `info`/`low`/`medium`/`high`/`critical` |
| `--no-triage` | Skip the AI triage layer |
| `--rules` | Print ruleset statistics and exit |
| `--quiet`, `--no-color` | Output control |

Exit codes: `0` clean, `1` a finding met `--fail-on`, `2` configuration or
connection error.

## What it detects

14 vulnerability classes, 424 rules across three languages. Twelve require
dataflow; hardcoded secrets use entropy plus provider formats, and weak
cryptography is a direct pattern match.

SQL Injection · Command Injection · Remote Code Execution · Insecure
Deserialization · Cross-Site Scripting · Path Traversal · SSRF · NoSQL
Injection · Prototype Pollution · XPath Injection · Hardcoded Secret · Open
Redirect · Weak Cryptography · Log Injection

Run `--rules` for the full table with CWE identifiers, baseline severities and
a class-by-language coverage matrix read off the rule tables. The eight core
classes (SQL injection, command injection, XSS, path traversal, SSRF, code
injection, open redirect, insecure deserialization) are covered in all three
languages; in total JavaScript detects 13 classes, Python 13 and Go 11. Go has
no `eval`, so its code-injection sinks are template parsing, embedded
interpreters and the plugin loader.

## How the analysis works

Ten stages per file, all driven by the per-language tables in `languages.cpp`.
The engine itself does not know what JavaScript is.

| # | Stage | Module |
|---|---|---|
| 1 | Parse to a concrete syntax tree | `ast.cpp` |
| 2 | Collect inline suppressions | `suppress.cpp` |
| 3 | Infer receiver types | `types.cpp` |
| 4 | Extract function definitions | `interproc.cpp` |
| 5 | Index lexical scopes | `analyzer.cpp` |
| 6 | Compute function summaries to a fixpoint | `interproc.cpp` |
| 7 | Propagate taint to a fixpoint, per scope, per class | `analyzer.cpp`, `taint.cpp` |
| 8 | Match sinks with type guards and sanitizer masks | `analyzer.cpp` |
| 9 | Score severity and confidence separately | `severity.cpp` |
| 10 | Emit SARIF, text, JSON or line format | `sarif.cpp` |

### Taint is a lattice, not a boolean

A value carries where it entered, the path it took, and a per-class mask of
what it has been sanitised for. That is what lets the engine be right about
this pair, which a boolean model cannot distinguish:

```js
el.innerHTML = escapeHtml(req.query.name);              // safe, not reported
const email = escapeHtml(req.query.email);
db.query("SELECT ... email = '" + email + "'");        // still SQL injection
```

`parseInt`, `int()` and `strconv.Atoi` are marked *total* — a number cannot
carry a payload into any sink, so their mask covers every class.

### Interprocedural via summaries

Each function gets a summary describing its boundary behaviour: which
parameters reach a sink and for which class, which flow out through the return
value and for which classes they are still dangerous, and whether it returns
attacker data outright. The per-class part is what lets a wrapper around
`escapeHtml` clear XSS while still reporting SQL injection.

Summaries are computed to a fixpoint over the call graph, so a caller's summary
depends on its callee's: a sink three helpers away is found, and the trace
names the function that actually holds it. Callees are summarised first, so an
acyclic file settles in one pass and only recursion iterates. Recursion
terminates because facts are only added, never retracted.

### Receiver types

Sinks can require a receiver type, which is what stops every `.exec(` being
reported as command injection:

```js
USERNAME_PATTERN.exec(req.query.username);   // receiver → regex, not reported
child_process.exec('ping ' + req.query.host); // receiver → child-process, reported
```

An unresolved receiver still fires the rule — a scanner that only reports what
it fully understands misses real bugs — but the finding's confidence drops.

### Scoring is two-dimensional

Severity answers "how bad if real", confidence answers "how sure it is real".
Both are attached to every finding along with the factors that produced them,
so a reviewer can see why something sorted where it did. Severity takes
evidence-quality adjustments first and reachability last, so a test-path
finding always scores below the same flow in a request handler.

### Inline suppressions

```js
// sentinel:ignore sql-injection -- table name is from an internal allowlist
db.query('SELECT * FROM ' + INTERNAL_TABLES[key]);
```

Forms: bare `sentinel:ignore`, a comma-separated class list, `-next-line`,
`-file`, and `-- reason`. The directive must sit on the flagged line or
directly above it. Suppressions are tracked rather than silently applied:
unused ones are reported as stale and unexplained ones are reported too. A
typo'd class slug narrows the suppression to nothing rather than widening it to
everything.

## Tests

621 assertions over 515 analysed inputs, across 32 suites. The analysis core
has no I/O dependencies, so the suite needs no broker, database or network. The
binary reports its own counts, so the figure is checkable rather than asserted.
These inputs are small test programs; for results on real repositories see
`benchmark/NOTES.md`.

```bash
make test
```

| Suite | Assertions |
|---|---|
| Class x language matrix (live / comment / string) | 72 |
| Unit: entropy, taint lattice, metadata | 40 |
| Regressions found by the benchmark corpus | 34 |
| Sanitizer matrix (both directions) | 33 |
| Additional sink coverage | 32 |
| Secret provider formats | 32 |
| Source coverage: JavaScript | 29 |
| Go: strict receiver guards | 24 |
| Sanitizers behind user-defined wrappers | 24 |
| True negatives: safe code | 24 |
| Propagation through real code shapes | 23 |
| Configuration rule coverage | 21 |
| Robustness and edge cases | 19 |
| Regression: original 18 behaviours | 18 |
| Source coverage: Python | 18 |
| Source coverage: Go | 18 |
| Inline suppressions | 17 |
| Interprocedural taint: chains of helpers | 17 |
| Scan result serialisation | 16 |
| SARIF and report formatting | 15 |
| Scan job parsing | 13 |
| Vulnerability class coverage | 12 |
| Sanitizer modelling (sink-specific) | 11 |
| Receiver-type inference | 9 |
| Hardcoded secret detection | 9 |
| Interprocedural taint (summaries) | 8 |
| Summary fixpoint: ordering and recomputation | 7 |
| Taint traces and scoring | 6 |
| Lexical scoping | 6 |
| Configuration rules (no dataflow) | 6 |
| Scan aggregation | 4 |
| Known limits (asserted so they stay visible) | 4 |

Robustness cases include 500 nested blocks (the walker is iterative, so deep
trees do not blow the stack), malformed syntax, CRLF checkouts, multi-byte
Unicode, 2,000-character minified lines and empty files.

## Known limits

- **No type checker.** Receiver inference is pattern-based. It resolves the
  common constructor shapes; anything else falls back to name matching.
- **Path-insensitive.** A sink guarded by a validating `if` is still reported.
  Validators lower confidence rather than suppressing, because proving the
  guard holds needs path sensitivity this engine does not have.
- **Single file.** Summaries are per file; a source in one module reaching a
  sink in another is missed. Cross-file analysis needs a whole-program call
  graph and a symbol resolver. This is the main cause of missed findings on
  real applications that separate routes from their data layer.
- **Calls are matched by name.** `a.save()` and `b.save()` are the same
  function to the engine, and same-named definitions share one summary.
- **Callbacks are not followed.** A function passed as a value is summarised,
  but the call that eventually invokes it is not connected to it.
- **Receiver types are per file, not per scope.** Two functions using one
  parameter name for different types share whichever type resolved.
- **Minified files are skipped**, and reported as skipped. They are build
  output, and one 90 KB bundle costs more to analyse than a whole repository.
- **Local input is low confidence.** Flows from argv or the environment are
  reported, but capped at low confidence: the operator controls them.
- **No field sensitivity.** Taint is per variable name, so tainting `user.name`
  taints `user`.
- **Secret detection is heuristic.** Provider-format matches are exact;
  entropy matches are not.

## Build requirements

```bash
sudo apt-get install -y librabbitmq-dev libcurl4-openssl-dev nlohmann-json3-dev
```

GCC 13 or later for C++23. Tree-sitter needs no system package — the runtime
and all three grammars are vendored under `third_party/` and built by the
Makefile. `make test` links only the analysis core, so it needs neither
RabbitMQ nor curl.

#!/usr/bin/env bash
#
# Sentinel SAST — guided demo.
#
# Walks through what the engine does, one capability at a time, against the
# corpus in demo/vulnerable-app. Needs no broker, no database and no network:
# everything here runs against the local binary.
#
#   ./demo/run-demo.sh              full walkthrough, pauses between sections
#   ./demo/run-demo.sh --fast       no pauses
#   ./demo/run-demo.sh --section 3  jump to one section

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKER="$ROOT/worker/build/sentinel-worker"
CORPUS="$ROOT/demo/vulnerable-app"

BOLD=$'\033[1m'; DIM=$'\033[2m'; RESET=$'\033[0m'
CYAN=$'\033[36m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'

FAST=0
ONLY_SECTION=""

# Scratch directories, created lazily by the sections that need them. Declared
# up front and cleaned up once, so running a single section with --section does
# not trip the trap on a variable an earlier section would have set.
TMP=""; TMP2=""; TMP3=""; TMP4=""
cleanup() { rm -rf "$TMP" "$TMP2" "$TMP3" "$TMP4" 2>/dev/null || true; }
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast) FAST=1; shift ;;
    --section) ONLY_SECTION="$2"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

pause() {
  [[ $FAST -eq 1 ]] && return 0
  printf '\n%s' "${DIM}  ── press enter to continue ──${RESET}"
  read -r _ || true
  printf '\n'
}

section() {
  local number="$1" title="$2"
  if [[ -n "$ONLY_SECTION" && "$ONLY_SECTION" != "$number" ]]; then
    return 1
  fi
  printf '\n%s\n' "${BOLD}${CYAN}══ ${number}. ${title}${RESET}"
  printf '%s\n\n' "${DIM}$(printf '─%.0s' {1..70})${RESET}"
  return 0
}

note() { printf '%s\n' "${DIM}  $*${RESET}"; }
run()  { printf '%s\n\n' "${GREEN}  \$ $*${RESET}"; eval "$@"; }

if [[ ! -x "$WORKER" ]]; then
  printf '%s\n' "${RED}worker binary not found at $WORKER${RESET}"
  printf '%s\n' "build it first:  cd worker && make"
  exit 2
fi

printf '\n%s\n' "${BOLD}Sentinel SAST — analysis engine walkthrough${RESET}"
printf '%s\n' "${DIM}AST-based taint analysis for JavaScript, Python and Go${RESET}"

# ---------------------------------------------------------------------------
if section 1 "The ruleset"; then
  note "Every rule is data, not code. The engine in analyzer.cpp does not know"
  note "what JavaScript is — languages.cpp supplies the node types and rules."
  printf '\n'
  run "$WORKER --rules"
  pause
fi

# ---------------------------------------------------------------------------
if section 2 "Scanning a repository"; then
  note "26 findings across three languages, sorted highest-priority first."
  note "Severity is the class baseline adjusted for reachability; confidence is"
  note "computed separately from how well corroborated the flow is."
  printf '\n'
  run "$WORKER --scan '$CORPUS' --no-triage --format line"
  pause
fi

# ---------------------------------------------------------------------------
if section 3 "Taint traces — the source-to-sink path"; then
  note "A finding is not just a line number. The engine carries provenance"
  note "through propagation, so every finding shows how the data got there."
  printf '\n'
  run "$WORKER --scan '$CORPUS/src/routes/users.js' --no-triage --format text 2>/dev/null | head -40"
  pause
fi

# ---------------------------------------------------------------------------
if section 4 "Interprocedural analysis"; then
  note "Neither function below contains a source-to-sink flow on its own."
  note "An intraprocedural engine reports nothing here — this is the single"
  note "most common shape of real vulnerability, and the README's biggest gap."
  printf '\n'
  cat <<'EOF'
  function runReport(sql) {
    return db.query(sql);          // <- the sink lives here
  }

  router.get('/report', (req, res) => {
    runReport('SELECT ... ' + req.query.owner);   // <- the source lives here
  });

EOF
  run "$WORKER --scan '$CORPUS/src/routes/users.js' --no-triage --format text 2>/dev/null | grep -A6 'line 69' || true"
  pause
fi

# ---------------------------------------------------------------------------
if section 5 "Sanitizers are sink-specific"; then
  note "html.escape() makes a value safe to render and does nothing for SQL."
  note "A boolean taint model cannot express that, so the old engine had to"
  note "ignore sanitizers entirely. Getting this wrong in either direction is"
  note "costly: over-suppress and you hide real bugs, under-suppress and the"
  note "developer stops reading the tool."
  printf '\n'
  TMP="$(mktemp -d)"

  cat > "$TMP/sanitizers.js" <<'EOF'
const db = mysql.createConnection({});
const el = document.getElementById('out');

// SAFE: escaped for the sink it actually reaches.
el.innerHTML = escapeHtml(req.query.name);

// VULNERABLE: HTML-escaped, then spliced into SQL. Same call, wrong sink.
const email = escapeHtml(req.query.email);
db.query("SELECT * FROM users WHERE email = '" + email + "'");

// SAFE: numeric coercion is total — a number carries no payload anywhere.
const page = parseInt(req.query.page, 10);
db.query('SELECT * FROM users LIMIT 20 OFFSET ' + page);
EOF
  cat "$TMP/sanitizers.js"
  printf '\n'
  run "$WORKER --scan '$TMP/sanitizers.js' --no-triage --format text --no-color"
  pause
fi

# ---------------------------------------------------------------------------
if section 6 "Receiver-type inference"; then
  note "The README's third gap: sinks matched on the last dotted segment, so"
  note "every .exec( was command injection — including RegExp.exec."
  printf '\n'
  TMP2="$(mktemp -d)"

  cat > "$TMP2/receivers.js" <<'EOF'
const child_process = require('child_process');

// SAFE: RegExp.exec is a pattern match, not a shell.
const USERNAME = /^[a-z0-9_]{3,20}$/;
USERNAME.exec(req.query.username);

// VULNERABLE: the same method name on a child_process receiver.
child_process.exec('ping -c 1 ' + req.query.host);
EOF
  cat "$TMP2/receivers.js"
  printf '\n'
  run "$WORKER --scan '$TMP2/receivers.js' --no-triage --format text --no-color"
  pause
fi

# ---------------------------------------------------------------------------
if section 7 "Lexical scoping"; then
  note "Two functions each declaring a local called 'name'. Analysing the file"
  note "as one flat scope made the sanitizer in the second appear not to apply."
  note "This was a real bug found by running the scanner on this demo corpus."
  printf '\n'
  TMP3="$(mktemp -d)"

  cat > "$TMP3/scoping.js" <<'EOF'
const fs = require('fs');

function unsafe(req) {
  const name = req.query.file;              // tainted
  fs.readFile('/data/' + name);             // VULNERABLE
}

function safe(req) {
  const name = path.basename(req.query.file);  // sanitized
  fs.readFileSync('/data/' + name);            // SAFE
}
EOF
  cat "$TMP3/scoping.js"
  printf '\n'
  run "$WORKER --scan '$TMP3/scoping.js' --no-triage --format text --no-color"
  pause
fi

# ---------------------------------------------------------------------------
if section 8 "Inline suppressions"; then
  note "Every SAST tool people keep enabled has an escape hatch. Without one,"
  note "the team's options are to disable the rule globally or ignore the tool."
  note "Suppressions are tracked, not silently applied: unexplained ones and"
  note "stale ones are both reported."
  printf '\n'
  run "grep -B2 -A2 'sentinel:ignore' '$CORPUS/src/routes/users.js'"
  printf '\n'
  run "$WORKER --scan '$CORPUS' --no-triage --format line 2>&1 | tail -3"
  pause
fi

# ---------------------------------------------------------------------------
if section 9 "SARIF output for CI"; then
  note "SARIF 2.1.0 is what GitHub code scanning, Azure DevOps and VS Code"
  note "consume. The taint trace becomes a clickable code flow in the UI."
  printf '\n'
  run "$WORKER --scan '$CORPUS' --no-triage --format sarif --quiet 2>/dev/null | head -45"
  pause
fi

# ---------------------------------------------------------------------------
if section 10 "CI gating"; then
  note "--fail-on turns the scanner into a build gate. Exit 1 means a finding"
  note "at or above the threshold; exit 0 means the build may proceed."
  printf '\n'
  printf '%s\n' "${GREEN}  \$ $WORKER --scan $CORPUS --fail-on critical${RESET}"
  set +e
  "$WORKER" --scan "$CORPUS" --no-triage --fail-on critical --format line --quiet >/dev/null 2>&1
  CRITICAL_EXIT=$?
  set -e
  printf '  exit code: %s%s%s  %s\n' "$RED" "$CRITICAL_EXIT" "$RESET" \
    "${DIM}(critical findings present — build fails)${RESET}"

  printf '\n%s\n' "${GREEN}  \$ $WORKER --scan <clean file> --fail-on critical${RESET}"
  TMP4="$(mktemp -d)"

  printf 'const x = 1;\n' > "$TMP4/clean.js"
  set +e
  "$WORKER" --scan "$TMP4/clean.js" --no-triage --fail-on critical --quiet >/dev/null 2>&1
  CLEAN_EXIT=$?
  set -e
  printf '  exit code: %s%s%s  %s\n' "$GREEN" "$CLEAN_EXIT" "$RESET" \
    "${DIM}(nothing at or above threshold — build proceeds)${RESET}"
  pause
fi

# ---------------------------------------------------------------------------
if section 11 "The test suite"; then
  note "174 assertions across 13 suites. No broker, no database, no network —"
  note "the analysis core has no I/O dependencies, which is what makes the"
  note "suite runnable on a clean checkout."
  printf '\n'
  run "cd '$ROOT/worker' && make test 2>&1 | tail -32"
  pause
fi

# ---------------------------------------------------------------------------
if section 12 "Performance"; then
  note "Parsing and AST traversal is the CPU-bound part, which is why the"
  note "worker is C++ calling Tree-sitter's C API with no translation layer."
  printf '\n'
  run "$WORKER --scan '$CORPUS' --no-triage --format line --quiet 2>&1 | wc -l"
  printf '\n'
  for _ in 1 2 3; do
    "$WORKER" --scan "$CORPUS" --no-triage --format line >/dev/null 2>/tmp/sentinel-timing
    grep -o 'in [0-9.]*ms' /tmp/sentinel-timing | head -1
  done
  rm -f /tmp/sentinel-timing
  pause
fi

printf '\n%s\n' "${BOLD}${GREEN}Demo complete.${RESET}"
printf '%s\n\n' "${DIM}Engine: $(find "$ROOT/worker/src" -name '*.cpp' -o -name '*.hpp' | xargs wc -l | tail -1 | awk '{print $1}') lines of C++23 across $(find "$ROOT/worker/src" -name '*.cpp' -o -name '*.hpp' | wc -l) files${RESET}"

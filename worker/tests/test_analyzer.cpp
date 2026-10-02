// Behavioural tests for the Sentinel analysis engine.
//
//   make test
//
// Needs no broker, no database and no network -- the analysis core has no I/O
// dependencies, which is the property that makes this suite runnable anywhere.

#include <algorithm>
#include <cstdint>
#include <format>
#include <initializer_list>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "../src/analyzer.hpp"
#include "../src/interproc.hpp"
#include "../src/job.hpp"
#include "../src/sarif.hpp"
#include "../src/secrets.hpp"
#include "../src/suppress.hpp"
#include "../src/version.hpp"
#include "harness.hpp"

using namespace sentinel;

namespace {

// Counts every distinct file the suite pushes through the engine, so the
// coverage claim is reported by the binary rather than asserted in prose.
int& scan_count() {
    static int count = 0;
    return count;
}

FileReport scan_detailed(const std::string& repository, const SourceFile& file) {
    ++scan_count();
    return analyze_file_detailed(repository, file);
}

FileReport scan(const std::string& path, const std::string& code) {
    return scan_detailed("test/repo", {path, code});
}

std::vector<Finding> analyze(const std::string& path, const std::string& code) {
    return scan(path, code).findings;
}

std::string describe(const std::vector<Finding>& findings) {
    if (findings.empty()) return "(no findings)";
    std::string out;
    for (const auto& finding : findings) {
        out += std::format("[{} @{} {}/{}] ", finding.vulnerability_type, finding.line,
                           to_string(finding.severity), to_string(finding.confidence));
    }
    return out;
}

// ---- Assertions -----------------------------------------------------------

void expect_finding(std::string_view label, const std::string& path, const std::string& code,
                    VulnClass expected, int expected_line) {
    const auto findings = analyze(path, code);
    const bool matched = std::any_of(findings.begin(), findings.end(), [&](const Finding& f) {
        return f.vulnerability == expected && f.line == expected_line;
    });
    harness::check(matched, label,
                   matched ? "" : std::format("expected {} on line {}, got: {}",
                                              metadata_for(expected).name, expected_line,
                                              describe(findings)));
}

void expect_class(std::string_view label, const std::string& path, const std::string& code,
                  VulnClass expected) {
    const auto findings = analyze(path, code);
    const bool matched = std::any_of(findings.begin(), findings.end(),
                                     [&](const Finding& f) { return f.vulnerability == expected; });
    harness::check(matched, label,
                   matched ? "" : std::format("expected a {} finding, got: {}",
                                              metadata_for(expected).name, describe(findings)));
}

void expect_none(std::string_view label, const std::string& path, const std::string& code) {
    const auto findings = analyze(path, code);
    harness::check(findings.empty(), label,
                   findings.empty() ? "" : std::format("expected none, got: {}",
                                                       describe(findings)));
}

void expect_not_class(std::string_view label, const std::string& path, const std::string& code,
                      VulnClass unwanted) {
    const auto findings = analyze(path, code);
    const bool present = std::any_of(findings.begin(), findings.end(),
                                     [&](const Finding& f) { return f.vulnerability == unwanted; });
    harness::check(!present, label,
                   present ? std::format("did not expect {}, got: {}",
                                         metadata_for(unwanted).name, describe(findings))
                           : "");
}

void expect_confidence(std::string_view label, const std::string& path, const std::string& code,
                       VulnClass id, Confidence expected) {
    const auto findings = analyze(path, code);
    const auto it = std::find_if(findings.begin(), findings.end(),
                                 [&](const Finding& f) { return f.vulnerability == id; });
    if (it == findings.end()) {
        harness::fail(label, std::format("no {} finding at all; got: {}",
                                         metadata_for(id).name, describe(findings)));
        return;
    }
    harness::check(it->confidence == expected, label,
                   it->confidence == expected
                       ? ""
                       : std::format("expected confidence {}, got {}", to_string(expected),
                                     to_string(it->confidence)));
}

void expect_severity_at_least(std::string_view label, const std::string& path,
                              const std::string& code, VulnClass id, Severity floor) {
    const auto findings = analyze(path, code);
    const auto it = std::find_if(findings.begin(), findings.end(),
                                 [&](const Finding& f) { return f.vulnerability == id; });
    if (it == findings.end()) {
        harness::fail(label, std::format("no {} finding; got: {}", metadata_for(id).name,
                                         describe(findings)));
        return;
    }
    const bool ok = static_cast<int>(it->severity) >= static_cast<int>(floor);
    harness::check(ok, label,
                   ok ? "" : std::format("expected at least {}, got {}", to_string(floor),
                                         to_string(it->severity)));
}

void expect_trace_mentions(std::string_view label, const std::string& path,
                           const std::string& code, VulnClass id, std::string_view needle) {
    const auto findings = analyze(path, code);
    const auto it = std::find_if(findings.begin(), findings.end(),
                                 [&](const Finding& f) { return f.vulnerability == id; });
    if (it == findings.end()) {
        harness::fail(label, std::format("no {} finding; got: {}", metadata_for(id).name,
                                         describe(findings)));
        return;
    }
    bool found = false;
    for (const auto& step : it->trace) {
        if (step.description.find(needle) != std::string::npos) found = true;
    }
    harness::check(found, label,
                   found ? "" : std::format("trace did not mention '{}' ({} steps)", needle,
                                            it->trace.size()));
}

// ===========================================================================
// Suites
// ===========================================================================

void regression_suite() {
    harness::section("Regression: original 18 behaviours");

    expect_finding("js: direct source into SQL sink", "src/a.js",
                   "const db = mysql.createConnection({});\n"
                   "db.query('SELECT * FROM users WHERE n = ' + req.query.name);\n",
                   VulnClass::SqlInjection, 2);

    expect_finding("js: taint through a variable", "src/b.js",
                   "const db = mysql.createConnection({});\n"
                   "const name = req.query.name;\n"
                   "db.query('SELECT * FROM users WHERE n = ' + name);\n",
                   VulnClass::SqlInjection, 3);

    expect_finding("js: taint two hops", "src/c.js",
                   "const db = mysql.createConnection({});\n"
                   "const a = req.query.name;\n"
                   "const b = a;\n"
                   "db.query('SELECT ' + b);\n",
                   VulnClass::SqlInjection, 4);

    expect_finding("js: eval is RCE", "src/d.js", "eval(req.query.code);\n",
                   VulnClass::RemoteCodeExecution, 1);

    // The fixpoint's reason for existing: the flow is found even though the
    // assignments appear in reverse dependency order.
    expect_finding("js: taint defined after use site", "src/e.js",
                   "const db = mysql.createConnection({});\n"
                   "function run() { db.query('SELECT ' + c); }\n"
                   "const c = b;\n"
                   "const b = a;\n"
                   "const a = req.query.x;\n",
                   VulnClass::SqlInjection, 2);

    expect_none("js: untainted constant query", "src/f.js",
                "const db = mysql.createConnection({});\n"
                "db.query('SELECT * FROM users');\n");

    expect_none("js: source with no sink", "src/g.js", "const name = req.query.name;\n");

    // The AST guarantee: comments and string literals are not call nodes.
    expect_none("js: commented-out vulnerability", "src/h.js",
                "// db.query('SELECT ' + req.query.name);\n");

    expect_none("js: vulnerability inside a string literal", "src/i.js",
                "const doc = \"call db.query('SELECT ' + req.query.name) carefully\";\n");

    expect_finding("py: os.system command injection", "src/a.py",
                   "import os\n"
                   "os.system('ping ' + request.args.get('host'))\n",
                   VulnClass::CommandInjection, 2);

    expect_finding("py: path traversal via open()", "src/b.py",
                   "name = request.args.get('f')\n"
                   "open('/data/' + name)\n",
                   VulnClass::PathTraversal, 2);

    expect_finding("py: cursor.execute SQL injection", "src/c.py",
                   "import psycopg2\n"
                   "cursor = conn.cursor()\n"
                   "cursor.execute('SELECT * FROM t WHERE id = ' + request.args['id'])\n",
                   VulnClass::SqlInjection, 3);

    expect_none("py: docstring mentioning os.system", "src/d.py",
                "def f():\n"
                "    \"\"\"Never call os.system(request.args['x']) here.\"\"\"\n"
                "    return 1\n");

    expect_finding("go: SQL injection via URL query", "src/a.go",
                   "package main\n"
                   "func h(w http.ResponseWriter, r *http.Request) {\n"
                   "  name := r.URL.Query().Get(\"name\")\n"
                   "  db.Query(\"SELECT * FROM users WHERE n = '\" + name + \"'\")\n"
                   "}\n",
                   VulnClass::SqlInjection, 4);

    expect_finding("go: command injection via FormValue", "src/b.go",
                   "package main\n"
                   "func h(w http.ResponseWriter, r *http.Request) {\n"
                   "  host := r.FormValue(\"host\")\n"
                   "  exec.Command(\"ping\", host)\n"
                   "}\n",
                   VulnClass::CommandInjection, 4);

    // r.URL.Query() shares its last segment with the db.Query() sink. Sources
    // are checked first so it is not reported as a SQL sink calling itself.
    expect_none("go: URL.Query source not mistaken for SQL sink", "src/c.go",
                "package main\n"
                "func h(w http.ResponseWriter, r *http.Request) {\n"
                "  _ = r.URL.Query().Get(\"name\")\n"
                "}\n");

    expect_none("go: constant query", "src/d.go",
                "package main\n"
                "func h() { db.Query(\"SELECT 1\") }\n");

    expect_none("unsupported extension is skipped", "README.md",
                "db.query('SELECT ' + req.query.name)\n");
}

void interprocedural_suite() {
    harness::section("Interprocedural taint (function summaries)");

    // The canonical miss for an intraprocedural engine: neither function
    // contains a source-to-sink flow on its own.
    expect_class("js: source and sink in different functions", "src/ip1.js",
                 "const db = mysql.createConnection({});\n"
                 "function runQuery(sql) {\n"
                 "  return db.query(sql);\n"
                 "}\n"
                 "app.get('/u', (req, res) => {\n"
                 "  runQuery('SELECT * FROM u WHERE id = ' + req.query.id);\n"
                 "});\n",
                 VulnClass::SqlInjection);

    expect_none("js: helper called with a constant is not a finding", "src/ip2.js",
                "const db = mysql.createConnection({});\n"
                "function runQuery(sql) {\n"
                "  return db.query(sql);\n"
                "}\n"
                "runQuery('SELECT * FROM users');\n");

    // A pass-through helper propagates taint out through its return value.
    expect_class("js: taint flows out through a returning helper", "src/ip3.js",
                 "const db = mysql.createConnection({});\n"
                 "function wrap(value) {\n"
                 "  return 'SELECT * FROM u WHERE id = ' + value;\n"
                 "}\n"
                 "app.get('/u', (req, res) => {\n"
                 "  db.query(wrap(req.query.id));\n"
                 "});\n",
                 VulnClass::SqlInjection);

    expect_class("py: source and sink across functions", "src/ip4.py",
                 "import os\n"
                 "def run(cmd):\n"
                 "    os.system(cmd)\n"
                 "def handler():\n"
                 "    run('ping ' + request.args.get('host'))\n",
                 VulnClass::CommandInjection);

    expect_class("go: source and sink across functions", "src/ip5.go",
                 "package main\n"
                 "func runQuery(q string) {\n"
                 "  db.Query(q)\n"
                 "}\n"
                 "func handler(w http.ResponseWriter, r *http.Request) {\n"
                 "  runQuery(\"SELECT * FROM u WHERE n = \" + r.FormValue(\"n\"))\n"
                 "}\n",
                 VulnClass::SqlInjection);

    // A recursive function must not hang the summary fixpoint.
    expect_none("js: recursion terminates without a finding", "src/ip6.js",
                "function countdown(n) {\n"
                "  if (n <= 0) return 0;\n"
                "  return countdown(n - 1);\n"
                "}\n"
                "countdown(10);\n");

    // Mutual recursion, same requirement.
    expect_none("js: mutual recursion terminates", "src/ip7.js",
                "function even(n) { return n === 0 ? true : odd(n - 1); }\n"
                "function odd(n) { return n === 0 ? false : even(n - 1); }\n"
                "even(4);\n");

    expect_trace_mentions("js: interprocedural trace names the callee", "src/ip8.js",
                          "const db = mysql.createConnection({});\n"
                          "function runQuery(sql) {\n"
                          "  return db.query(sql);\n"
                          "}\n"
                          "app.get('/u', (req, res) => {\n"
                          "  runQuery('SELECT ' + req.query.id);\n"
                          "});\n",
                          VulnClass::SqlInjection, "runQuery");
}

void sanitizer_suite() {
    harness::section("Sanitizer modelling (sink-specific)");

    // Numeric coercion is total -- a number cannot carry a payload anywhere.
    expect_none("js: parseInt clears taint entirely", "src/s1.js",
                "const db = mysql.createConnection({});\n"
                "const id = parseInt(req.query.id, 10);\n"
                "db.query('SELECT * FROM u WHERE id = ' + id);\n");

    expect_none("py: int() clears taint entirely", "src/s2.py",
                "cursor = conn.cursor()\n"
                "uid = int(request.args['id'])\n"
                "cursor.execute('SELECT * FROM u WHERE id = ' + str(uid))\n");

    expect_none("go: strconv.Atoi clears taint", "src/s3.go",
                "package main\n"
                "func h(w http.ResponseWriter, r *http.Request) {\n"
                "  id, _ := strconv.Atoi(r.FormValue(\"id\"))\n"
                "  db.Query(fmt.Sprintf(\"SELECT * FROM u WHERE id = %d\", id))\n"
                "}\n");

    // HTML escaping fixes rendering.
    expect_not_class("js: escapeHtml clears XSS", "src/s4.js",
                     "const el = document.getElementById('x');\n"
                     "el.innerHTML = escapeHtml(req.query.name);\n",
                     VulnClass::CrossSiteScripting);

    // ...but the same call does nothing for SQL. This is the case a boolean
    // taint model cannot express, and getting it wrong hides a real bug.
    expect_class("js: escapeHtml does NOT clear SQL injection", "src/s5.js",
                 "const db = mysql.createConnection({});\n"
                 "const name = escapeHtml(req.query.name);\n"
                 "db.query('SELECT * FROM u WHERE n = ' + name);\n",
                 VulnClass::SqlInjection);

    expect_class("py: html.escape does NOT clear command injection", "src/s6.py",
                 "import os, html\n"
                 "cmd = html.escape(request.args['host'])\n"
                 "os.system('ping ' + cmd)\n",
                 VulnClass::CommandInjection);

    expect_not_class("py: shlex.quote clears command injection", "src/s7.py",
                     "import os, shlex\n"
                     "os.system('ping ' + shlex.quote(request.args['host']))\n",
                     VulnClass::CommandInjection);

    expect_class("py: shlex.quote does NOT clear XSS", "src/s8.py",
                 "import shlex\n"
                 "from flask import Markup\n"
                 "Markup(shlex.quote(request.args['name']))\n",
                 VulnClass::CrossSiteScripting);

    expect_not_class("py: secure_filename clears path traversal", "src/s9.py",
                     "from werkzeug.utils import secure_filename\n"
                     "open('/data/' + secure_filename(request.args['f']))\n",
                     VulnClass::PathTraversal);

    expect_not_class("go: filepath.Base clears path traversal", "src/s10.go",
                     "package main\n"
                     "func h(w http.ResponseWriter, r *http.Request) {\n"
                     "  os.Open(\"/data/\" + filepath.Base(r.FormValue(\"f\")))\n"
                     "}\n",
                     VulnClass::PathTraversal);

    // The trace should say why a partial sanitizer did not help.
    expect_trace_mentions("js: trace explains the wrong-sink sanitizer", "src/s11.js",
                          "const db = mysql.createConnection({});\n"
                          "const name = escapeHtml(req.query.name);\n"
                          "db.query('SELECT * FROM u WHERE n = ' + name);\n",
                          VulnClass::SqlInjection, "does not protect");
}

void scoping_suite() {
    harness::section("Lexical scoping");

    // The bug this suite exists for: two functions each declaring a local
    // called `name`. Analysing the file as one flat scope made the sanitizer in
    // the second function appear not to apply, because the first function's
    // tainted `name` leaked into it.
    expect_not_class("js: a sibling function's local does not leak", "src/sc1.js",
                     "const fs = require('fs');\n"
                     "function unsafe(req) {\n"
                     "  const name = req.query.file;\n"
                     "  fs.readFile('/data/' + name);\n"
                     "}\n"
                     "function safe(req) {\n"
                     "  const name = path.basename(req.query.file);\n"
                     "  fs.readFileSync('/data/' + name);\n"
                     "}\n",
                     VulnClass::CrossSiteScripting);

    {
        // The unsafe one is still reported; only the safe one is spared.
        const auto findings = analyze("src/sc2.js",
                                      "const fs = require('fs');\n"
                                      "function unsafe(req) {\n"
                                      "  const name = req.query.file;\n"
                                      "  fs.readFile('/data/' + name);\n"
                                      "}\n"
                                      "function safe(req) {\n"
                                      "  const name = path.basename(req.query.file);\n"
                                      "  fs.readFileSync('/data/' + name);\n"
                                      "}\n");
        const int traversals = static_cast<int>(std::count_if(
            findings.begin(), findings.end(),
            [](const Finding& f) { return f.vulnerability == VulnClass::PathTraversal; }));
        harness::check(traversals == 1,
                       "js: exactly one of two same-named locals is reported",
                       std::format("expected 1 path traversal, got {} — {}", traversals,
                                   describe(findings)));
    }

    expect_none("go: sanitized local is not tainted by a sibling's local", "src/sc3.go",
                "package main\n"
                "func Unsafe(w http.ResponseWriter, r *http.Request) {\n"
                "  id, _ := strconv.Atoi(r.FormValue(\"id\"))\n"
                "  db.Query(fmt.Sprintf(\"SELECT * FROM u WHERE id = %d\", id))\n"
                "}\n"
                "func Other(w http.ResponseWriter, r *http.Request) {\n"
                "  id := r.URL.Query().Get(\"id\")\n"
                "  _ = id\n"
                "}\n");

    expect_none("py: sibling function locals stay separate", "src/sc4.py",
                "import os, shlex\n"
                "def a():\n"
                "    target = request.args['t']\n"
                "    return target\n"
                "def b():\n"
                "    target = shlex.quote(request.args['t'])\n"
                "    os.system('convert ' + target)\n");

    // A closure must still see its enclosing scope's variables -- the express
    // handler shape depends on it.
    expect_class("js: a closure sees the enclosing scope", "src/sc5.js",
                 "const db = mysql.createConnection({});\n"
                 "function outer(req) {\n"
                 "  const name = req.query.name;\n"
                 "  setImmediate(() => {\n"
                 "    db.query('SELECT * FROM u WHERE n = ' + name);\n"
                 "  });\n"
                 "}\n",
                 VulnClass::SqlInjection);

    // Module-scope variables are visible inside every function.
    expect_class("js: module scope is visible inside a function", "src/sc6.js",
                 "const db = mysql.createConnection({});\n"
                 "const globalName = req.query.name;\n"
                 "function handler() {\n"
                 "  db.query('SELECT * FROM u WHERE n = ' + globalName);\n"
                 "}\n",
                 VulnClass::SqlInjection);
}

void type_inference_suite() {
    harness::section("Receiver-type inference");

    // The README's named gap: any `.exec(` used to be command injection.
    expect_not_class("js: RegExp.exec is not command injection", "src/t1.js",
                     "const pattern = /^[a-z]+$/;\n"
                     "pattern.exec(req.query.name);\n",
                     VulnClass::CommandInjection);

    expect_not_class("js: new RegExp().exec is not command injection", "src/t2.js",
                     "const re = new RegExp('^[a-z]+$');\n"
                     "re.exec(req.query.name);\n",
                     VulnClass::CommandInjection);

    expect_class("js: child_process.exec IS command injection", "src/t3.js",
                 "const child_process = require('child_process');\n"
                 "child_process.exec('ping ' + req.query.host);\n",
                 VulnClass::CommandInjection);

    expect_class("js: destructured exec from child_process", "src/t4.js",
                 "const { exec } = require('child_process');\n"
                 "exec('ping ' + req.query.host);\n",
                 VulnClass::CommandInjection);

    // A DOM element's .query is not a database query.
    expect_not_class("js: element.query is not SQL injection", "src/t5.js",
                     "const el = document.getElementById('x');\n"
                     "el.query(req.query.name);\n",
                     VulnClass::SqlInjection);

    expect_class("js: pg Pool query IS SQL injection", "src/t6.js",
                 "const pool = new Pool({});\n"
                 "pool.query('SELECT * FROM u WHERE n = ' + req.query.name);\n",
                 VulnClass::SqlInjection);

    // A logger sink is Low severity, not a rendering sink.
    expect_class("js: winston logger is log injection, not XSS", "src/t7.js",
                 "const logger = winston.createLogger({});\n"
                 "logger.info('user: ' + req.query.name);\n",
                 VulnClass::LogInjection);

    expect_not_class("js: logging a tainted value is not XSS", "src/t8.js",
                     "const logger = winston.createLogger({});\n"
                     "logger.info('user: ' + req.query.name);\n",
                     VulnClass::CrossSiteScripting);

    // With no binding to infer from, the rule still fires -- conservative by
    // design -- but confidence is lower.
    expect_confidence("js: unresolved receiver lowers confidence", "src/t9.js",
                      "unknownThing.query('SELECT * FROM u WHERE n = ' + req.query.name);\n",
                      VulnClass::SqlInjection, Confidence::Medium);
}

void vulnerability_class_suite() {
    harness::section("Vulnerability class coverage");

    expect_class("js: SSRF via fetch", "src/v1.js",
                 "fetch(req.query.url);\n", VulnClass::ServerSideRequestForgery);

    expect_class("py: SSRF via requests.get", "src/v2.py",
                 "import requests\n"
                 "requests.get(request.args['url'])\n",
                 VulnClass::ServerSideRequestForgery);

    expect_class("py: insecure deserialization via pickle.loads", "src/v3.py",
                 "import pickle\n"
                 "pickle.loads(request.data)\n",
                 VulnClass::InsecureDeserialization);

    expect_class("py: insecure deserialization via yaml.load", "src/v4.py",
                 "import yaml\n"
                 "yaml.load(request.data)\n",
                 VulnClass::InsecureDeserialization);

    expect_class("py: open redirect", "src/v5.py",
                 "from flask import redirect\n"
                 "redirect(request.args['next'])\n",
                 VulnClass::OpenRedirect);

    expect_class("js: NoSQL injection via Mongo find", "src/v6.js",
                 "const collection = db.collection('users');\n"
                 "collection.find(req.body.filter);\n",
                 VulnClass::NoSqlInjection);

    expect_class("js: prototype pollution via __proto__ write", "src/v7.js",
                 "target.__proto__ = req.body.payload;\n",
                 VulnClass::PrototypePollution);

    expect_class("py: XPath injection", "src/v8.py",
                 "tree.xpath('//user[name=\"' + request.args['n'] + '\"]')\n",
                 VulnClass::XPathInjection);

    expect_class("py: SSTI is reported as RCE", "src/v9.py",
                 "from flask import render_template_string\n"
                 "render_template_string(request.args['tpl'])\n",
                 VulnClass::RemoteCodeExecution);

    expect_class("js: XSS via innerHTML", "src/v10.js",
                 "document.getElementById('x').innerHTML = location.hash;\n",
                 VulnClass::CrossSiteScripting);

    expect_class("js: XSS via dangerouslySetInnerHTML", "src/v11.js",
                 "el.dangerouslySetInnerHTML = req.query.html;\n",
                 VulnClass::CrossSiteScripting);

    expect_class("go: SSRF via http.Get", "src/v12.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  http.Get(r.FormValue(\"url\"))\n"
                 "}\n",
                 VulnClass::ServerSideRequestForgery);
}

void weak_crypto_suite() {
    harness::section("Configuration rules (no dataflow required)");

    expect_class("js: MD5 is weak cryptography", "src/w1.js",
                 "const hash = crypto.createHash('md5').update(data).digest('hex');\n",
                 VulnClass::WeakCryptography);

    expect_class("py: hashlib.md5 is weak cryptography", "src/w2.py",
                 "import hashlib\n"
                 "digest = hashlib.md5(data).hexdigest()\n",
                 VulnClass::WeakCryptography);

    expect_class("go: md5.New is weak cryptography", "src/w3.go",
                 "package main\n"
                 "func f() { h := md5.New() }\n",
                 VulnClass::WeakCryptography);

    expect_class("py: requests verify=False disables TLS checks", "src/w4.py",
                 "import requests\n"
                 "requests.get(url, verify=False)\n",
                 VulnClass::WeakCryptography);

    expect_class("go: InsecureSkipVerify disables TLS checks", "src/w5.go",
                 "package main\n"
                 "var cfg = tls.Config{InsecureSkipVerify: true}\n",
                 VulnClass::WeakCryptography);

    expect_none("js: SHA-256 is not flagged", "src/w6.js",
                "const hash = crypto.createHash('sha256').update(data).digest('hex');\n");
}

void secret_suite() {
    harness::section("Hardcoded secret detection");

    expect_class("js: AWS access key id is detected by format", "src/k1.js",
                 "const accessKey = 'AKIA" "IOSFODNN7EXAMPLE';\n",
                 VulnClass::HardcodedSecret);

    expect_class("py: high-entropy value in a secret-named binding", "src/k2.py",
                 "API_KEY = 'aG9wZWZ1bGx5UmFuZG9tOTg3NjU0MzIxWnE'\n",
                 VulnClass::HardcodedSecret);

    expect_class("js: Stripe live key", "src/k3.js",
                 "const key = 'sk_live_" "4eC39HqLyjWDarjtT1zdp7dcAbCdEfGh';\n",
                 VulnClass::HardcodedSecret);

    expect_none("py: low-entropy placeholder is not a secret", "src/k4.py",
                "API_KEY = 'changeme'\n");

    expect_none("py: environment lookup is not a hardcoded secret", "src/k5.py",
                "import os\n"
                "API_KEY = os.environ['API_KEY']\n");

    expect_none("js: process.env is not a hardcoded secret", "src/k6.js",
                "const apiKey = process.env.API_KEY;\n");

    expect_none("py: a non-credential name is ignored", "src/k7.py",
                "greeting = 'aG9wZWZ1bGx5UmFuZG9tOTg3NjU0MzIx'\n");

    expect_none("py: token_count is not a credential name", "src/k8.py",
                "token_count = 'aG9wZWZ1bGx5UmFuZG9tOTg3NjU0MzIx'\n");

    // A real credential in a test file is still real, just lower severity.
    expect_class("js: provider format is still reported in a test file",
                 "tests/fixtures/keys.test.js",
                 "const accessKey = 'AKIA" "IOSFODNN7EXAMPLE';\n",
                 VulnClass::HardcodedSecret);
}

void suppression_suite() {
    harness::section("Inline suppressions");

    expect_none("js: bare sentinel:ignore suppresses the line", "src/p1.js",
                "const db = mysql.createConnection({});\n"
                "// sentinel:ignore -- table name comes from an internal allowlist\n"
                "db.query('SELECT * FROM u WHERE n = ' + req.query.name);\n");

    expect_none("js: trailing suppression on the same line", "src/p2.js",
                "const db = mysql.createConnection({});\n"
                "db.query('SELECT ' + req.query.name); // sentinel:ignore -- reviewed\n");

    expect_none("js: class-scoped suppression matching the finding", "src/p3.js",
                "const db = mysql.createConnection({});\n"
                "// sentinel:ignore sql-injection -- reviewed by security\n"
                "db.query('SELECT * FROM u WHERE n = ' + req.query.name);\n");

    // A suppression for a different class must not hide this one.
    expect_class("js: mismatched class does not suppress", "src/p4.js",
                 "const db = mysql.createConnection({});\n"
                 "// sentinel:ignore cross-site-scripting -- wrong class\n"
                 "db.query('SELECT * FROM u WHERE n = ' + req.query.name);\n",
                 VulnClass::SqlInjection);

    expect_none("py: hash-comment suppression", "src/p5.py",
                "import os\n"
                "# sentinel:ignore command-injection -- input is an internal enum\n"
                "os.system('ping ' + request.args['host'])\n");

    expect_none("js: ignore-file suppresses everything", "src/p6.js",
                "// sentinel:ignore-file -- vendored third-party bundle\n"
                "const db = mysql.createConnection({});\n"
                "db.query('SELECT ' + req.query.a);\n"
                "eval(req.query.b);\n");

    // A typo'd class slug must narrow to nothing rather than widening to all.
    expect_class("js: typo'd class slug does not suppress everything", "src/p7.js",
                 "const db = mysql.createConnection({});\n"
                 "// sentinel:ignore sql-injektion -- typo\n"
                 "db.query('SELECT ' + req.query.name);\n",
                 VulnClass::SqlInjection);

    // Directive parsing, without going through the analyzer.
    {
        const auto parsed = parse_suppression_comment(
            "// sentinel:ignore sql-injection,xss -- reviewed", 7);
        harness::check(parsed.has_value(), "directive: parses a multi-class suppression");
        if (parsed.has_value()) {
            harness::check(parsed->has_reason, "directive: captures the reason text");
            harness::check(parsed->covers(VulnClass::SqlInjection),
                           "directive: covers the named class");
            harness::check(!parsed->covers(VulnClass::PathTraversal),
                           "directive: does not cover an unnamed class");
        }
    }
    {
        const auto parsed = parse_suppression_comment("// just an ordinary comment", 1);
        harness::check(!parsed.has_value(), "directive: ignores an ordinary comment");
    }
    {
        const auto parsed = parse_suppression_comment("# sentinel:ignore-next-line", 3);
        harness::check(parsed.has_value() && parsed->scope == SuppressionScope::NextLine,
                       "directive: parses ignore-next-line scope");
        harness::check(parsed.has_value() && !parsed->has_reason,
                       "directive: flags a suppression with no reason");
    }

    // Stale suppressions are reported so they can be cleaned up.
    {
        const auto report = scan_detailed(
            "test/repo", {"src/p8.js", "// sentinel:ignore sql-injection -- nothing here\n"
                                       "const x = 1;\n"});
        harness::check(report.stale_suppressions.size() == 1,
                       "report: an unused suppression is reported as stale",
                       std::format("got {}", report.stale_suppressions.size()));
    }
    {
        const auto report = scan_detailed(
            "test/repo", {"src/p9.js", "const db = mysql.createConnection({});\n"
                                       "// sentinel:ignore\n"
                                       "db.query('SELECT ' + req.query.n);\n"});
        harness::check(report.undocumented_suppressions.size() == 1,
                       "report: a suppression with no reason is reported");
        harness::check(report.suppressed_count == 1,
                       "report: suppressed findings are counted");
    }
}

void trace_and_scoring_suite() {
    harness::section("Taint traces and scoring");

    expect_trace_mentions("trace: names the entry source", "src/r1.js",
                          "const db = mysql.createConnection({});\n"
                          "const name = req.query.name;\n"
                          "db.query('SELECT ' + name);\n",
                          VulnClass::SqlInjection, "query-string parameter");

    expect_trace_mentions("trace: records the intermediate variable", "src/r2.js",
                          "const db = mysql.createConnection({});\n"
                          "const name = req.query.name;\n"
                          "db.query('SELECT ' + name);\n",
                          VulnClass::SqlInjection, "flows into 'name'");

    // A direct, type-resolved flow into a critical sink is the highest-value
    // thing the engine can report and must sort to the top.
    expect_severity_at_least("scoring: direct SQL flow is Critical", "src/r3.js",
                             "const db = mysql.createConnection({});\n"
                             "db.query('SELECT * FROM u WHERE n = ' + req.query.name);\n",
                             VulnClass::SqlInjection, Severity::Critical);

    // Test paths lower impact.
    {
        const auto production = analyze("src/app.js",
                                        "const db = mysql.createConnection({});\n"
                                        "db.query('SELECT ' + req.query.n);\n");
        const auto test = analyze("tests/app.test.js",
                                  "const db = mysql.createConnection({});\n"
                                  "db.query('SELECT ' + req.query.n);\n");
        const bool ok = !production.empty() && !test.empty() &&
                        static_cast<int>(test.front().severity) <
                            static_cast<int>(production.front().severity);
        harness::check(ok, "scoring: a test path lowers severity",
                       ok ? "" : "expected the test-path finding to score lower");
    }

    // Findings arrive sorted by priority.
    {
        const auto findings = analyze("src/r4.js",
                                      "const logger = winston.createLogger({});\n"
                                      "const db = mysql.createConnection({});\n"
                                      "logger.info('u: ' + req.query.n);\n"
                                      "db.query('SELECT ' + req.query.n);\n");
        bool sorted = true;
        for (std::size_t i = 1; i < findings.size(); ++i) {
            if (findings[i - 1].priority() < findings[i].priority()) sorted = false;
        }
        harness::check(sorted && findings.size() >= 2,
                       "scoring: findings are returned highest-priority first",
                       std::format("got: {}", describe(findings)));
    }

    // Metadata is populated.
    {
        const auto findings = analyze("src/r5.js",
                                      "const db = mysql.createConnection({});\n"
                                      "db.query('SELECT ' + req.query.n);\n");
        const bool ok = !findings.empty() && findings.front().cwe == "CWE-89" &&
                        !findings.front().remediation.empty() &&
                        findings.front().rule_id == "sentinel.javascript.sql-injection";
        harness::check(ok, "metadata: CWE, rule id and remediation are populated",
                       ok ? "" : "missing metadata on the finding");
    }
}

void robustness_suite() {
    harness::section("Robustness and edge cases");

    expect_none("empty file", "src/e1.js", "");
    expect_none("whitespace-only file", "src/e2.js", "   \n\n\t\n");
    expect_none("file of only comments", "src/e3.js", "// a\n// b\n/* c */\n");

    // Broken syntax must not crash, and Tree-sitter's error tolerance means we
    // still analyse what parsed.
    {
        const auto report = scan_detailed(
            "test/repo", {"src/e4.js", "function ( { unclosed\nconst x = ;\n"});
        harness::check(report.parsed, "malformed file still parses (error-tolerant)");
        harness::check(report.had_parse_errors, "malformed file is flagged as having errors");
    }

    // Deep nesting must not blow the stack -- the walker is iterative.
    {
        std::string deep = "const db = mysql.createConnection({});\n";
        for (int i = 0; i < 500; ++i) deep += "if (true) {\n";
        deep += "db.query('SELECT ' + req.query.n);\n";
        for (int i = 0; i < 500; ++i) deep += "}\n";
        const auto findings = analyze("src/e5.js", deep);
        harness::check(!findings.empty(), "deeply nested file is analysed without a crash",
                       "expected the finding at the bottom of 500 nested blocks");
    }

    // Minified bundles are build output: skipped, and reported as skipped.
    {
        // 12 KB on two lines, with a real source-to-sink flow in it.
        std::string bundle = "var db=mysql.createConnection({});";
        while (bundle.size() < 12 * 1024) bundle += "function f(a){return a+1}var q=f(2);";
        bundle += "\ndb.query('SELECT '+req.query.n);\n";
        harness::check(looks_minified(bundle), "minified: a bundle on two lines is recognised");

        const FileReport report = scan("public/js/app.min.js", bundle);
        harness::check(report.skipped_minified && !report.parsed && report.findings.empty(),
                       "minified: the bundle is skipped, with no findings");

        ScanSummary summary;
        summary.absorb(report);
        harness::check(summary.files_minified == 1 && summary.files_scanned == 0,
                       "minified: counted as skipped, not as scanned");

        // The same code laid out normally is analysed as usual.
        std::string readable = "const db = mysql.createConnection({});\n";
        for (int i = 0; i < 400; ++i) readable += "function f" + std::to_string(i) + "(a) {\n  return a + 1;\n}\n";
        readable += "db.query('SELECT ' + req.query.n);\n";
        harness::check(!looks_minified(readable) && readable.size() > 12 * 1024,
                       "minified: ordinary code of the same size is not");
        harness::check(!analyze("src/big.js", readable).empty(),
                       "minified: and its findings are still reported");

        // One long line in a small file is not a bundle.
        harness::check(!looks_minified(std::string(3000, 'x') + "\nshort\n"),
                       "minified: a small file with one long line is not");
    }

    // Long lines are truncated rather than flooding the report.
    {
        std::string long_line = "const db = mysql.createConnection({});\ndb.query('";
        long_line += std::string(2000, 'A');
        long_line += "' + req.query.n);\n";
        const auto findings = analyze("src/e6.js", long_line);
        const bool ok = !findings.empty() && findings.front().snippet.size() <= 240;
        harness::check(ok, "very long lines are truncated in the snippet",
                       ok ? "" : "snippet was not truncated");
    }

    // A CRLF checkout must produce clean snippets.
    {
        const auto findings =
            analyze("src/e7.js",
                    "const db = mysql.createConnection({});\r\ndb.query('S' + req.query.n);\r\n");
        const bool ok = !findings.empty() &&
                        findings.front().snippet.find('\r') == std::string::npos;
        harness::check(ok, "CRLF line endings do not leak into snippets");
    }

    // Unicode in source must not corrupt byte offsets.
    expect_class("unicode in source does not break offsets", "src/e8.js",
                 "const db = mysql.createConnection({});\n"
                 "const greeting = 'ハロー・ワールド 🎌';\n"
                 "db.query('SELECT ' + req.query.name);\n",
                 VulnClass::SqlInjection);

    // The detailed report carries diagnostics.
    {
        const auto report = scan_detailed(
            "test/repo", {"src/e9.js", "function a(x) { return x; }\n"
                                       "function b(y) { return y; }\n"});
        harness::check(report.functions_analyzed == 2, "report: counts analysed functions",
                       std::format("got {}", report.functions_analyzed));
        harness::check(report.language == Language::JavaScript,
                       "report: records the detected language");
        harness::check(report.analysis_ms >= 0.0, "report: records analysis time");
    }

    {
        const auto report = scan_detailed("test/repo", {"notes.txt", "anything"});
        harness::check(!report.language_supported,
                       "report: an unsupported extension is flagged, not analysed");
    }
}

void sarif_suite() {
    harness::section("SARIF and report formatting");

    {
        const auto quoted = json_escape("he said \"hi\"");
        harness::check(quoted == "he said \\\"hi\\\"", "json: escapes double quotes",
                       std::format("got {}", quoted));
    }
    {
        const auto backslash = json_escape("C:\\path\\file");
        harness::check(backslash == "C:\\\\path\\\\file", "json: escapes backslashes",
                       std::format("got {}", backslash));
    }
    {
        const auto control = json_escape(std::string("a\x01" "b"));
        harness::check(control == "a\\u0001b", "json: escapes control characters",
                       std::format("got {}", control));
    }
    {
        const auto newline = json_escape("line1\nline2");
        harness::check(newline == "line1\\nline2", "json: escapes newlines");
    }

    {
        const auto findings = analyze("src/x1.js",
                                      "const db = mysql.createConnection({});\n"
                                      "const n = req.query.n;\n"
                                      "db.query('SELECT ' + n);\n");
        const std::string sarif = to_sarif(findings);

        harness::check(sarif.find("\"version\": \"2.1.0\"") != std::string::npos,
                       "sarif: declares version 2.1.0");
        harness::check(sarif.find("sentinel.javascript.sql-injection") != std::string::npos,
                       "sarif: emits the rule id");
        harness::check(sarif.find("\"codeFlows\"") != std::string::npos,
                       "sarif: emits the taint path as a code flow");
        harness::check(sarif.find("\"level\": \"error\"") != std::string::npos,
                       "sarif: maps Critical severity to the error level");
        harness::check(sarif.find("CWE-89") != std::string::npos,
                       "sarif: includes the CWE tag");

        // Balanced braces is a cheap structural check that catches most
        // serialisation slips without linking a JSON parser into the tests.
        int depth = 0;
        bool in_string = false;
        bool escaped = false;
        for (const char c : sarif) {
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if (c == '"') { in_string = !in_string; continue; }
            if (in_string) continue;
            if (c == '{' || c == '[') ++depth;
            if (c == '}' || c == ']') --depth;
        }
        harness::check(depth == 0, "sarif: braces and brackets are balanced",
                       std::format("final depth {}", depth));
    }

    {
        const std::string empty = to_sarif({});
        harness::check(empty.find("\"results\": [") != std::string::npos,
                       "sarif: an empty run is still valid");
    }

    {
        const auto findings = analyze("src/x2.js",
                                      "const db = mysql.createConnection({});\n"
                                      "db.query('SELECT ' + req.query.n);\n");
        const std::string text = to_text_report(findings, false);
        harness::check(text.find("SQL Injection") != std::string::npos,
                       "text report: names the vulnerability");
        harness::check(text.find("CWE-89") != std::string::npos,
                       "text report: includes the CWE");
        harness::check(text.find("\033[") == std::string::npos,
                       "text report: emits no ANSI codes when colour is off");

        const std::string lines = to_line_report(findings);
        harness::check(lines.find("src/x2.js:2:CRITICAL") != std::string::npos,
                       "line report: file:line:severity format",
                       std::format("got {}", lines));
    }
}

void unit_suite() {
    harness::section("Unit tests: entropy, taint lattice, metadata");

    // Entropy.
    harness::check(shannon_entropy("") == 0.0, "entropy: empty string scores zero");
    harness::check(shannon_entropy("aaaaaaaa") == 0.0, "entropy: one repeated char scores zero");
    harness::check(shannon_entropy("aG9wZWZ1bGx5UmFuZG9t") > 3.5,
                   "entropy: a random-looking token scores high");
    harness::check(shannon_entropy("password") < 3.5, "entropy: a dictionary word scores low");

    harness::check(looks_like_secret_name("API_KEY"), "secrets: API_KEY looks like a credential");
    harness::check(looks_like_secret_name("apiKey"), "secrets: camelCase is normalised");
    harness::check(looks_like_secret_name("api-key"), "secrets: kebab-case is normalised");
    harness::check(!looks_like_secret_name("username"), "secrets: username is not a credential");
    harness::check(!looks_like_secret_name("token_count"),
                   "secrets: token_count is excluded by name");
    harness::check(looks_like_placeholder("changeme"), "secrets: 'changeme' is a placeholder");
    harness::check(looks_like_placeholder("xxxxxxxxxxxx"), "secrets: repeated chars");
    harness::check(is_environment_reference("process.env.KEY"),
                   "secrets: process.env is an environment reference");
    harness::check(is_test_context("tests/fixtures/a.js"), "secrets: recognises a test path");
    harness::check(!is_test_context("src/server.js"), "secrets: a src path is not a test path");

    harness::check(match_secret_pattern("AKIA" "IOSFODNN7EXAMPLE").has_value(),
                   "secrets: matches an AWS key format");
    harness::check(!match_secret_pattern("AKIA").has_value(),
                   "secrets: rejects a too-short AWS prefix");

    // Sanitizer mask semantics.
    {
        SanitizerMask mask;
        mask.add(VulnClass::CrossSiteScripting);
        harness::check(mask.covers(VulnClass::CrossSiteScripting),
                       "mask: covers the class it was given");
        harness::check(!mask.covers(VulnClass::SqlInjection),
                       "mask: does not cover an unrelated class");

        SanitizerMask other;
        other.add(VulnClass::SqlInjection);
        const SanitizerMask merged = mask.merged_with(other);
        harness::check(!merged.covers(VulnClass::CrossSiteScripting) &&
                           !merged.covers(VulnClass::SqlInjection),
                       "mask: merging two flows intersects their coverage");

        SanitizerMask total;
        total.add_all();
        harness::check(total.covers(VulnClass::PathTraversal), "mask: add_all covers everything");
    }

    // Taint state.
    {
        TaintState state;
        TaintFact fact = fact_from_source("req.query.x", {1, "x", "entered"});
        harness::check(state.mark("a", fact), "taint: marking a new name reports a change");
        harness::check(!state.mark("a", fact), "taint: re-marking the same fact reports none");
        harness::check(state.is_tainted("a"), "taint: the name is tainted");
        harness::check(state.is_dangerous_for("a", VulnClass::SqlInjection),
                       "taint: dangerous for an unsanitized class");

        SanitizerMask mask;
        mask.add(VulnClass::SqlInjection);
        harness::check(state.sanitize("a", mask), "taint: sanitizing reports a change");
        harness::check(!state.is_dangerous_for("a", VulnClass::SqlInjection),
                       "taint: no longer dangerous for the sanitized class");
        harness::check(state.is_dangerous_for("a", VulnClass::CrossSiteScripting),
                       "taint: still dangerous for other classes");
    }

    // Vulnerability registry.
    {
        harness::check(metadata_for(VulnClass::SqlInjection).cwe == "CWE-89",
                       "registry: SQL injection maps to CWE-89");
        harness::check(vuln_class_from_slug("sql-injection") == VulnClass::SqlInjection,
                       "registry: slug round-trips");
        harness::check(vuln_class_from_slug("nonsense") == VulnClass::Unknown,
                       "registry: an unknown slug resolves to Unknown");
        harness::check(all_vulnerability_classes().size() >= 15,
                       "registry: every class has metadata",
                       std::format("got {}", all_vulnerability_classes().size()));
        harness::check(sarif_level_for(Severity::Critical) == "error",
                       "registry: Critical maps to the SARIF error level");
        harness::check(raise(Severity::Critical) == Severity::Critical,
                       "registry: raising Critical saturates");
        harness::check(lower(Severity::Info) == Severity::Info,
                       "registry: lowering Info saturates");
    }

    // Language detection.
    {
        harness::check(language_for_path("a/b.js") == Language::JavaScript,
                       "languages: .js is JavaScript");
        harness::check(language_for_path("a/b.tsx") == Language::JavaScript,
                       "languages: .tsx is handled by the JavaScript grammar");
        harness::check(language_for_path("a/b.py") == Language::Python,
                       "languages: .py is Python");
        harness::check(language_for_path("a/b.go") == Language::Go, "languages: .go is Go");
        harness::check(language_for_path("a/b.rs") == Language::Unknown,
                       "languages: an unsupported extension resolves to Unknown");
        harness::check(total_rule_count() > 250, "languages: the ruleset is fully loaded",
                       std::format("got {} rules", total_rule_count()));
    }
}

// ---------------------------------------------------------------------------
// Coverage matrices.
//
// The suites above test one behaviour each. These walk the rule tables
// systematically: every taint source, every sanitizer in both directions,
// every provider secret format, every configuration rule. A rule that exists
// in languages.cpp but was never exercised is a rule nobody knows works.
// ---------------------------------------------------------------------------

// Every JavaScript source pattern should carry taint into a universal sink.
void js_source_coverage_suite() {
    harness::section("Source coverage: JavaScript (27 patterns)");

    struct Case { const char* label; const char* expr; };
    static const Case kSources[] = {
        {"req.query",                 "req.query.x"},
        {"req.body",                  "req.body.x"},
        {"req.params",                "req.params.x"},
        {"req.headers",               "req.headers.x"},
        {"req.cookies",               "req.cookies.x"},
        {"req.url",                   "req.url"},
        {"req.originalUrl",           "req.originalUrl"},
        {"request.query",             "request.query.x"},
        {"request.body",              "request.body.x"},
        {"request.params",            "request.params.x"},
        {"request.headers",           "request.headers.x"},
        {"ctx.query",                 "ctx.query.x"},
        {"ctx.request.body",          "ctx.request.body.x"},
        {"event.body",                "event.body"},
        {"event.queryStringParameters", "event.queryStringParameters.x"},
        {"process.argv",              "process.argv[2]"},
        {"location.search",           "location.search"},
        {"location.hash",             "location.hash"},
        {"location.href",             "location.href"},
        {"document.URL",              "document.URL"},
        {"document.referrer",         "document.referrer"},
        {"window.name",               "window.name"},
        {"localStorage.getItem",      "localStorage.getItem('k')"},
        {"sessionStorage.getItem",    "sessionStorage.getItem('k')"},
    };

    for (const auto& source : kSources) {
        expect_class(std::format("js source: {}", source.label), "src/src.js",
                     std::format("eval({});\n", source.expr), VulnClass::RemoteCodeExecution);
    }

    // Upload filenames are scoped to filesystem and shell sinks only, so they
    // must reach a path sink and must NOT reach an unrelated one.
    expect_class("js source: file.originalname reaches a path sink", "src/up.js",
                 "fs.readFile('/d/' + file.originalname);\n", VulnClass::PathTraversal);
    expect_not_class("js source: file.originalname is not an RCE source", "src/up2.js",
                     "eval(file.originalname);\n", VulnClass::RemoteCodeExecution);
    expect_class("js source: req.file reaches a path sink", "src/up3.js",
                 "fs.readFile('/d/' + req.file.name);\n", VulnClass::PathTraversal);

    // process.env is scoped: dangerous for shell and filesystem, not for eval.
    expect_class("js source: process.env reaches a command sink", "src/env.js",
                 "const cp = require('child_process');\n"
                 "cp.exec('run ' + process.env.CMD);\n",
                 VulnClass::CommandInjection);
    expect_not_class("js source: process.env is not an RCE source", "src/env2.js",
                     "eval(process.env.CODE);\n", VulnClass::RemoteCodeExecution);
}

void py_source_coverage_suite() {
    harness::section("Source coverage: Python (19 patterns)");

    struct Case { const char* label; const char* expr; };
    static const Case kSources[] = {
        {"request.args",         "request.args['x']"},
        {"request.form",         "request.form['x']"},
        {"request.json",         "request.json['x']"},
        {"request.data",         "request.data"},
        {"request.values",       "request.values['x']"},
        {"request.cookies",      "request.cookies['x']"},
        {"request.headers",      "request.headers['x']"},
        {"request.GET",          "request.GET['x']"},
        {"request.POST",         "request.POST['x']"},
        {"request.body",         "request.body"},
        {"request.query_params", "request.query_params['x']"},
        {"self.get_argument",    "self.get_argument('x')"},
        {"sys.argv",             "sys.argv[1]"},
    };

    for (const auto& source : kSources) {
        expect_class(std::format("py source: {}", source.label), "src/src.py",
                     std::format("eval({})\n", source.expr), VulnClass::RemoteCodeExecution);
    }

    expect_class("py source: input()", "src/in.py", "eval(input('> '))\n",
                 VulnClass::RemoteCodeExecution);
    expect_class("py source: request.files reaches a path sink", "src/f.py",
                 "open('/d/' + request.files['f'].filename)\n", VulnClass::PathTraversal);
    expect_not_class("py source: request.files is not an RCE source", "src/f2.py",
                     "eval(request.files['f'].filename)\n", VulnClass::RemoteCodeExecution);
    expect_class("py source: os.environ reaches a command sink", "src/e.py",
                 "import os\n"
                 "os.system('run ' + os.environ['CMD'])\n",
                 VulnClass::CommandInjection);
    expect_not_class("py source: os.environ is not an RCE source", "src/e2.py",
                     "import os\n"
                     "eval(os.environ['CODE'])\n",
                     VulnClass::RemoteCodeExecution);
}

void go_source_coverage_suite() {
    harness::section("Source coverage: Go (20 patterns)");

    struct Case { const char* label; const char* expr; };
    static const Case kSources[] = {
        {"r.URL.Query",      "r.URL.Query().Get(\"x\")"},
        {"req.URL.Query",    "req.URL.Query().Get(\"x\")"},
        {"r.URL.Path",       "r.URL.Path"},
        {"r.FormValue",      "r.FormValue(\"x\")"},
        {"r.PostFormValue",  "r.PostFormValue(\"x\")"},
        {"r.Form",           "r.Form.Get(\"x\")"},
        {"r.PostForm",       "r.PostForm.Get(\"x\")"},
        {"r.Header.Get",     "r.Header.Get(\"X\")"},
        {"r.Cookie",         "r.Cookie(\"session\")"},
        {"mux.Vars",         "mux.Vars(r)[\"id\"]"},
        {"c.Param",          "c.Param(\"id\")"},
        {"c.Query",          "c.Query(\"id\")"},
        {"c.PostForm",       "c.PostForm(\"id\")"},
        {"chi.URLParam",     "chi.URLParam(r, \"id\")"},
        {"os.Args",          "os.Args[1]"},
    };

    for (const auto& source : kSources) {
        expect_class(std::format("go source: {}", source.label), "src/src.go",
                     std::format("package main\n"
                                 "func h(w http.ResponseWriter, r *http.Request) {{\n"
                                 "  exec.Command(\"sh\", \"-c\", {})\n"
                                 "}}\n",
                                 source.expr),
                     VulnClass::CommandInjection);
    }

    expect_class("go source: r.Body reaches a deserialization sink", "src/b.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  gob.NewDecoder(r.Body)\n"
                 "}\n",
                 VulnClass::InsecureDeserialization);
    expect_class("go source: r.MultipartForm reaches a path sink", "src/m.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  os.ReadFile(\"/d/\" + r.MultipartForm.Value[\"f\"][0])\n"
                 "}\n",
                 VulnClass::PathTraversal);
    expect_class("go source: os.Getenv reaches a command sink", "src/g.go",
                 "package main\n"
                 "func h() {\n"
                 "  exec.Command(\"sh\", \"-c\", os.Getenv(\"CMD\"))\n"
                 "}\n",
                 VulnClass::CommandInjection);
}

// Each sanitizer is checked twice: it must clear the class it covers, and it
// must NOT clear an unrelated one. A sanitizer that over-clears hides real
// bugs, which is the more expensive direction to get wrong.
void sanitizer_matrix_suite() {
    harness::section("Sanitizer matrix: clears the right class, and only that one");

    // ---- JavaScript -------------------------------------------------------
    expect_not_class("js sanitizer: parseFloat clears SQL", "src/m1.js",
                     "const db = new Pool({});\n"
                     "db.query('SELECT ' + parseFloat(req.query.n));\n",
                     VulnClass::SqlInjection);
    expect_not_class("js sanitizer: Number clears SQL", "src/m2.js",
                     "const db = new Pool({});\n"
                     "db.query('SELECT ' + Number(req.query.n));\n",
                     VulnClass::SqlInjection);
    expect_not_class("js sanitizer: Math.floor clears SQL", "src/m3.js",
                     "const db = new Pool({});\n"
                     "db.query('SELECT ' + Math.floor(req.query.n));\n",
                     VulnClass::SqlInjection);
    expect_not_class("js sanitizer: escapeHTML clears XSS", "src/m4.js",
                     "el.innerHTML = escapeHTML(req.query.n);\n",
                     VulnClass::CrossSiteScripting);
    expect_not_class("js sanitizer: sanitizeHtml clears XSS", "src/m5.js",
                     "el.innerHTML = sanitizeHtml(req.query.n);\n",
                     VulnClass::CrossSiteScripting);
    expect_not_class("js sanitizer: DOMPurify.sanitize clears XSS", "src/m6.js",
                     "el.innerHTML = DOMPurify.sanitize(req.query.n);\n",
                     VulnClass::CrossSiteScripting);
    expect_not_class("js sanitizer: encodeURIComponent clears SSRF", "src/m7.js",
                     "fetch('https://api/' + encodeURIComponent(req.query.u));\n",
                     VulnClass::ServerSideRequestForgery);
    expect_not_class("js sanitizer: shellQuote clears command injection", "src/m8.js",
                     "const cp = require('child_process');\n"
                     "cp.exec('ping ' + shellQuote(req.query.h));\n",
                     VulnClass::CommandInjection);
    expect_not_class("js sanitizer: sanitizeFilename clears path traversal", "src/m9.js",
                     "fs.readFile('/d/' + sanitizeFilename(req.query.f));\n",
                     VulnClass::PathTraversal);
    expect_not_class("js sanitizer: escapeId clears SQL", "src/m10.js",
                     "const db = new Pool({});\n"
                     "db.query('SELECT * FROM ' + escapeId(req.query.t));\n",
                     VulnClass::SqlInjection);

    // The other direction: a sanitizer must not clear a class it does not cover.
    expect_class("js sanitizer: DOMPurify does NOT clear command injection", "src/n1.js",
                 "const cp = require('child_process');\n"
                 "cp.exec('ping ' + DOMPurify.sanitize(req.query.h));\n",
                 VulnClass::CommandInjection);
    expect_class("js sanitizer: shellQuote does NOT clear SQL", "src/n2.js",
                 "const db = new Pool({});\n"
                 "db.query('SELECT ' + shellQuote(req.query.n));\n",
                 VulnClass::SqlInjection);
    expect_class("js sanitizer: path.basename does NOT clear SQL", "src/n3.js",
                 "const db = new Pool({});\n"
                 "db.query('SELECT ' + path.basename(req.query.n));\n",
                 VulnClass::SqlInjection);
    expect_class("js sanitizer: escapeId does NOT clear command injection", "src/n4.js",
                 "const cp = require('child_process');\n"
                 "cp.exec('ping ' + escapeId(req.query.h));\n",
                 VulnClass::CommandInjection);

    // ---- Python -----------------------------------------------------------
    expect_not_class("py sanitizer: float() clears SQL", "src/m11.py",
                     "cursor.execute('SELECT ' + str(float(request.args['n'])))\n",
                     VulnClass::SqlInjection);
    expect_not_class("py sanitizer: bool() clears SQL", "src/m12.py",
                     "cursor.execute('SELECT ' + str(bool(request.args['n'])))\n",
                     VulnClass::SqlInjection);
    expect_not_class("py sanitizer: bleach.clean clears XSS", "src/m13.py",
                     "from flask import Markup\n"
                     "Markup(bleach.clean(request.args['n']))\n",
                     VulnClass::CrossSiteScripting);
    expect_not_class("py sanitizer: markupsafe.escape clears XSS", "src/m14.py",
                     "from flask import Markup\n"
                     "Markup(markupsafe.escape(request.args['n']))\n",
                     VulnClass::CrossSiteScripting);
    expect_not_class("py sanitizer: pipes.quote clears command injection", "src/m15.py",
                     "import os, pipes\n"
                     "os.system('ping ' + pipes.quote(request.args['h']))\n",
                     VulnClass::CommandInjection);
    expect_not_class("py sanitizer: os.path.basename clears path traversal", "src/m16.py",
                     "import os\n"
                     "open('/d/' + os.path.basename(request.args['f']))\n",
                     VulnClass::PathTraversal);
    expect_not_class("py sanitizer: quote_plus clears SSRF", "src/m17.py",
                     "import requests\n"
                     "requests.get('https://api/' + quote_plus(request.args['u']))\n",
                     VulnClass::ServerSideRequestForgery);
    expect_not_class("py sanitizer: uuid.UUID clears SQL", "src/m18.py",
                     "import uuid\n"
                     "cursor.execute('SELECT ' + str(uuid.UUID(request.args['id'])))\n",
                     VulnClass::SqlInjection);

    expect_class("py sanitizer: bleach does NOT clear command injection", "src/n5.py",
                 "import os, bleach\n"
                 "os.system('ping ' + bleach.clean(request.args['h']))\n",
                 VulnClass::CommandInjection);
    expect_class("py sanitizer: secure_filename does NOT clear SQL", "src/n6.py",
                 "from werkzeug.utils import secure_filename\n"
                 "cursor.execute('SELECT ' + secure_filename(request.args['n']))\n",
                 VulnClass::SqlInjection);
    expect_class("py sanitizer: pipes.quote does NOT clear SQL", "src/n7.py",
                 "import pipes\n"
                 "cursor.execute('SELECT ' + pipes.quote(request.args['n']))\n",
                 VulnClass::SqlInjection);

    // ---- Go ---------------------------------------------------------------
    expect_not_class("go sanitizer: strconv.ParseInt clears SQL", "src/m19.go",
                     "package main\n"
                     "func h(w http.ResponseWriter, r *http.Request) {\n"
                     "  n, _ := strconv.ParseInt(r.FormValue(\"n\"), 10, 64)\n"
                     "  db.Query(fmt.Sprintf(\"SELECT %d\", n))\n"
                     "}\n",
                     VulnClass::SqlInjection);
    expect_not_class("go sanitizer: strconv.ParseFloat clears SQL", "src/m20.go",
                     "package main\n"
                     "func h(w http.ResponseWriter, r *http.Request) {\n"
                     "  n, _ := strconv.ParseFloat(r.FormValue(\"n\"), 64)\n"
                     "  db.Query(fmt.Sprintf(\"SELECT %f\", n))\n"
                     "}\n",
                     VulnClass::SqlInjection);
    expect_not_class("go sanitizer: html.EscapeString clears XSS", "src/m21.go",
                     "package main\n"
                     "func h(w http.ResponseWriter, r *http.Request) {\n"
                     "  template.HTML(html.EscapeString(r.FormValue(\"n\")))\n"
                     "}\n",
                     VulnClass::CrossSiteScripting);
    expect_not_class("go sanitizer: filepath.Clean clears path traversal", "src/m22.go",
                     "package main\n"
                     "func h(w http.ResponseWriter, r *http.Request) {\n"
                     "  os.ReadFile(\"/d/\" + filepath.Clean(r.FormValue(\"f\")))\n"
                     "}\n",
                     VulnClass::PathTraversal);
    expect_not_class("go sanitizer: url.QueryEscape clears SSRF", "src/m23.go",
                     "package main\n"
                     "func h(w http.ResponseWriter, r *http.Request) {\n"
                     "  http.Get(\"https://api/\" + url.QueryEscape(r.FormValue(\"u\")))\n"
                     "}\n",
                     VulnClass::ServerSideRequestForgery);
    expect_not_class("go sanitizer: uuid.Parse clears SQL", "src/m24.go",
                     "package main\n"
                     "func h(w http.ResponseWriter, r *http.Request) {\n"
                     "  id, _ := uuid.Parse(r.FormValue(\"id\"))\n"
                     "  db.Query(\"SELECT \" + id.String())\n"
                     "}\n",
                     VulnClass::SqlInjection);

    expect_class("go sanitizer: filepath.Base does NOT clear SQL", "src/n8.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  db.Query(\"SELECT \" + filepath.Base(r.FormValue(\"n\")))\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go sanitizer: html.EscapeString does NOT clear SQL", "src/n9.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  db.Query(\"SELECT \" + html.EscapeString(r.FormValue(\"n\")))\n"
                 "}\n",
                 VulnClass::SqlInjection);
}

// Every provider format in the secrets table, plus the shapes that must not fire.
void secret_format_suite() {
    harness::section("Secret provider formats (22 patterns)");

    // These fixtures are deliberately written as two adjacent string literals.
    // The compiler joins them, so the analyzer still receives the full value --
    // but the source file never contains a contiguous token-shaped string, which
    // would otherwise trip GitHub push protection and every other secret scanner
    // pointed at this repository. Do not join them back into one literal.
    struct Case { const char* label; const char* value; };
    static const Case kFormats[] = {
        {"AWS access key id (AKIA)",   "AKIA" "IOSFODNN7EXAMPLE"},
        {"AWS session key (ASIA)",     "ASIA" "IOSFODNN7EXAMPLE"},
        {"GitHub PAT (ghp_)",          "ghp_" "16C7e42F292c6912E7710c838347Ae178B4a"},
        {"GitHub OAuth (gho_)",        "gho_" "16C7e42F292c6912E7710c838347Ae178B4a"},
        {"GitHub app token (ghu_)",    "ghu_" "16C7e42F292c6912E7710c838347Ae178B4a"},
        {"GitHub refresh (ghr_)",      "ghr_" "16C7e42F292c6912E7710c838347Ae178B4a"},
        {"Slack bot token (xoxb-)",    "xoxb-" "123456789012-1234567890123-AbCdEfGhIjKlMnOp"},
        {"Slack user token (xoxp-)",   "xoxp-" "123456789012-1234567890123-AbCdEfGhIjKlMnOp"},
        {"Stripe live key (sk_live_)", "sk_live_" "4eC39HqLyjWDarjtT1zdp7dcAbCdEfGh"},
        {"Stripe test key (sk_test_)", "sk_test_" "4eC39HqLyjWDarjtT1zdp7dcAbCdEfGh"},
        {"Stripe restricted (rk_live_)", "rk_live_" "4eC39HqLyjWDarjtT1zdp7dcAbCdEfGh"},
        {"Google API key (AIza)",      "AIza" "SyD-1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P"},
        {"SendGrid (SG.)",             "SG." "aBcDeFgHiJkLmNoPqRsTuV.wXyZ1234567890AbCdEfGhIjKl"},
        {"npm token (npm_)",           "npm_" "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"},
        {"OpenAI key (sk-)",           "sk-" "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890AbCd"},
        {"PyPI token (pypi-)",         "pypi-" "AgEIcHlwaS5vcmcCJDU2Nzg5MDEyLTM0NTYtNzg5MC0xMjM0LTU2Nzg5MDEyMzQ1Ng"},
        {"JWT (eyJ)",                  "eyJ" "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"},
    };

    for (const auto& format : kFormats) {
        expect_class(std::format("secret: {}", format.label), "src/keys.js",
                     std::format("const credential = '{}';\n", format.value),
                     VulnClass::HardcodedSecret);
    }

    expect_class("secret: Twilio account SID", "src/tw.py",
                 "auth_sid = 'AC" "1234567890abcdef1234567890abcdef'\n",
                 VulnClass::HardcodedSecret);
    expect_class("secret: private key block", "src/pk.py",
                 "private_key = '-----BEGIN" " RSA PRIVATE KEY-----'\n",
                 VulnClass::HardcodedSecret);
    expect_class("secret: Slack webhook URL", "src/wh.js",
                 "const webhookSecret = 'https://hooks.slack.com/services/" "T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX';\n",
                 VulnClass::HardcodedSecret);

    // Credential-named bindings with high entropy, across languages.
    expect_class("secret: python password with high entropy", "src/p.py",
                 "DB_PASSWORD = 'x9Kq2mZv7Lp4Rt8Wn3Bd6Fh1Jy5Ge0Uc'\n",
                 VulnClass::HardcodedSecret);
    expect_class("secret: go private key binding", "src/p.go",
                 "package main\n"
                 "const signingKey = \"x9Kq2mZv7Lp4Rt8Wn3Bd6Fh1Jy5Ge0Uc\"\n",
                 VulnClass::HardcodedSecret);
    expect_class("secret: camelCase clientSecret", "src/cs.js",
                 "const clientSecret = 'x9Kq2mZv7Lp4Rt8Wn3Bd6Fh1Jy5Ge0Uc';\n",
                 VulnClass::HardcodedSecret);

    // Shapes that must not fire.
    expect_none("secret: short value below the length floor", "src/q1.py",
                "API_KEY = 'abc123'\n");
    expect_none("secret: your-key-here placeholder", "src/q2.py",
                "API_KEY = 'your-api-key-here-replace-me'\n");
    expect_none("secret: example placeholder", "src/q3.py",
                "API_KEY = 'example-key-for-documentation'\n");
    expect_none("secret: a URL is structural, not a credential", "src/q4.py",
                "AUTH_URL = 'https://accounts.example.com/oauth/authorize'\n");
    expect_none("secret: a sentence is not a credential", "src/q5.py",
                "SECRET_HELP = 'Set this to your token before running'\n");
    expect_none("secret: os.getenv is a runtime lookup", "src/q6.py",
                "import os\n"
                "SECRET_KEY = os.getenv('SECRET_KEY')\n");
    expect_none("secret: template interpolation is computed", "src/q7.js",
                "const apiKey = `${prefix}-${suffix}-value-here-long`;\n");
    expect_none("secret: password_hash is excluded by name", "src/q8.py",
                "password_hash = 'x9Kq2mZv7Lp4Rt8Wn3Bd6Fh1Jy5Ge0Uc'\n");
    expect_none("secret: min_password_length is excluded", "src/q9.py",
                "min_password_length = 'x9Kq2mZv7Lp4Rt8Wn3Bd6Fh1Jy5Ge0Uc'\n");
}

// Every configuration rule, in both directions where a safe counterpart exists.
void config_rule_suite() {
    harness::section("Configuration rule coverage (24 rules)");

    expect_class("config js: createCipher uses a broken KDF", "src/c1.js",
                 "const c = crypto.createCipher('aes-256-cbc', pass);\n",
                 VulnClass::WeakCryptography);
    expect_class("config js: Math.random is not cryptographic", "src/c2.js",
                 "const token = Math.random().toString(36);\n",
                 VulnClass::WeakCryptography);
    expect_class("config js: rejectUnauthorized false disables TLS", "src/c3.js",
                 "const agent = new https.Agent({ rejectUnauthorized: false });\n",
                 VulnClass::WeakCryptography);
    expect_class("config js: sha1 digest", "src/c4.js",
                 "const h = crypto.createHash('sha1').digest('hex');\n",
                 VulnClass::WeakCryptography);
    expect_class("config js: md5 with double quotes", "src/c5.js",
                 "const h = crypto.createHash(\"md5\").digest('hex');\n",
                 VulnClass::WeakCryptography);

    expect_class("config py: hashlib.sha1", "src/c6.py",
                 "import hashlib\n"
                 "d = hashlib.sha1(data).hexdigest()\n",
                 VulnClass::WeakCryptography);
    expect_class("config py: DES cipher", "src/c7.py",
                 "cipher = DES.new(key, DES.MODE_ECB)\n",
                 VulnClass::WeakCryptography);
    expect_class("config py: RC4 cipher", "src/c8.py",
                 "cipher = ARC4.new(key)\n",
                 VulnClass::WeakCryptography);
    expect_class("config py: unverified SSL context", "src/c9.py",
                 "ctx = ssl._create_unverified_context()\n",
                 VulnClass::WeakCryptography);
    expect_class("config py: random.random is not cryptographic", "src/c10.py",
                 "import random\n"
                 "token = random.random()\n",
                 VulnClass::WeakCryptography);
    expect_class("config py: shell=True routes through a shell", "src/c11.py",
                 "import subprocess\n"
                 "subprocess.run(cmd, shell=True)\n",
                 VulnClass::CommandInjection);

    expect_class("config go: md5.Sum", "src/c12.go",
                 "package main\n"
                 "func f(d []byte) { _ = md5.Sum(d) }\n",
                 VulnClass::WeakCryptography);
    expect_class("config go: sha1.New", "src/c13.go",
                 "package main\n"
                 "func f() { h := sha1.New() }\n",
                 VulnClass::WeakCryptography);
    expect_class("config go: DES cipher", "src/c14.go",
                 "package main\n"
                 "func f(k []byte) { c, _ := des.NewCipher(k) }\n",
                 VulnClass::WeakCryptography);
    expect_class("config go: RC4 cipher", "src/c15.go",
                 "package main\n"
                 "func f(k []byte) { c, _ := rc4.NewCipher(k) }\n",
                 VulnClass::WeakCryptography);

    // Safe counterparts must stay quiet.
    expect_none("config js: sha512 is fine", "src/d1.js",
                "const h = crypto.createHash('sha512').digest('hex');\n");
    expect_none("config js: createCipheriv is the correct API", "src/d2.js",
                "const c = crypto.createCipheriv('aes-256-gcm', key, iv);\n");
    expect_none("config js: randomBytes is cryptographic", "src/d3.js",
                "const token = crypto.randomBytes(32).toString('hex');\n");
    expect_none("config py: hashlib.sha256 is fine", "src/d4.py",
                "import hashlib\n"
                "d = hashlib.sha256(data).hexdigest()\n");
    expect_none("config py: secrets module is cryptographic", "src/d5.py",
                "import secrets\n"
                "token = secrets.token_hex(32)\n");
    expect_none("config go: sha256.New is fine", "src/d6.go",
                "package main\n"
                "func f() { h := sha256.New() }\n");
}

// Safe idioms across all three languages that a naive scanner reports.
void true_negative_suite() {
    harness::section("True negatives: safe code that must stay quiet");

    expect_none("js: parameterised query with ?", "src/t1.js",
                "const db = new Pool({});\n"
                "db.query('SELECT * FROM u WHERE id = ?', [req.params.id]);\n");
    expect_none("js: parameterised query with $1", "src/t2.js",
                "const db = new Pool({});\n"
                "db.query('SELECT * FROM u WHERE id = $1', [req.params.id]);\n");
    expect_none("js: textContent does not parse HTML", "src/t3.js",
                "document.getElementById('x').textContent = req.query.name;\n");
    expect_none("js: constant argument vector", "src/t4.js",
                "const cp = require('child_process');\n"
                "cp.execFile('git', ['status']);\n");
    expect_none("js: a constant path", "src/t5.js",
                "fs.readFile('/etc/app/config.json');\n");
    expect_none("js: comment containing eval", "src/t6.js",
                "// never call eval(req.query.code) here\n");
    expect_none("js: block comment containing a sink", "src/t7.js",
                "/* db.query('SELECT ' + req.query.n) is wrong */\n");
    expect_none("js: JSON.parse is not deserialization of code", "src/t8.js",
                "const data = JSON.parse(req.body.payload);\n");
    expect_none("js: a template literal with no interpolation", "src/t9.js",
                "const db = new Pool({});\n"
                "db.query(`SELECT * FROM users`);\n");
    expect_none("js: constant concatenation", "src/t10.js",
                "const db = new Pool({});\n"
                "db.query('SELECT * FROM ' + 'users');\n");

    expect_none("py: psycopg2 parameter binding", "src/t11.py",
                "cursor.execute('SELECT * FROM t WHERE id = %s', (request.args['id'],))\n");
    expect_none("py: named parameter binding", "src/t12.py",
                "cursor.execute('SELECT * FROM t WHERE id = :id', {'id': request.args['id']})\n");
    expect_none("py: argument vector with a constant binary", "src/t13.py",
                "import subprocess\n"
                "subprocess.run(['git', 'status'], check=True)\n");
    expect_none("py: yaml.safe_load cannot construct objects", "src/t14.py",
                "import yaml\n"
                "cfg = yaml.safe_load(request.data)\n");
    expect_none("py: json.loads is data-only", "src/t15.py",
                "import json\n"
                "data = json.loads(request.data)\n");
    expect_none("py: docstring mentioning eval", "src/t16.py",
                "def f():\n"
                "    \"\"\"Do not eval(request.args['x']) here.\"\"\"\n"
                "    return 1\n");
    expect_none("py: hash comment containing a sink", "src/t17.py",
                "# os.system('rm ' + request.args['f']) would be wrong\n");
    expect_none("py: a constant path", "src/t18.py",
                "open('/etc/app/config.json')\n");

    expect_none("go: parameterised query", "src/t19.go",
                "package main\n"
                "func h(w http.ResponseWriter, r *http.Request) {\n"
                "  db.Query(\"SELECT * FROM u WHERE id = $1\", r.FormValue(\"id\"))\n"
                "}\n");
    expect_none("go: argument vector with a constant binary", "src/t20.go",
                "package main\n"
                "func f() { exec.Command(\"git\", \"status\") }\n");
    expect_none("go: a constant path", "src/t21.go",
                "package main\n"
                "func f() { os.ReadFile(\"/etc/app/config.json\") }\n");
    expect_none("go: line comment containing a sink", "src/t22.go",
                "package main\n"
                "// db.Query(\"SELECT \" + r.FormValue(\"n\")) would be wrong\n");
    expect_none("go: constant query with QueryRow", "src/t23.go",
                "package main\n"
                "func f() { db.QueryRow(\"SELECT COUNT(*) FROM users\") }\n");
    expect_none("go: reading a param without using it", "src/t24.go",
                "package main\n"
                "func h(w http.ResponseWriter, r *http.Request) {\n"
                "  name := r.FormValue(\"name\")\n"
                "  _ = name\n"
                "}\n");
}

// Additional sinks per class that the focused suites do not reach.
void sink_coverage_suite() {
    harness::section("Additional sink coverage");

    expect_class("js sink: Function constructor is RCE", "src/k1.js",
                 "const f = new Function(req.query.body);\n", VulnClass::RemoteCodeExecution);
    expect_class("js sink: vm.runInNewContext is RCE", "src/k2.js",
                 "vm.runInNewContext(req.query.code);\n", VulnClass::RemoteCodeExecution);
    expect_class("js sink: execSync is command injection", "src/k3.js",
                 "execSync('ping ' + req.query.host);\n", VulnClass::CommandInjection);
    expect_class("js sink: spawn with a tainted binary", "src/k4.js",
                 "spawn(req.query.cmd, []);\n", VulnClass::CommandInjection);
    expect_class("js sink: writeFile is path traversal", "src/k5.js",
                 "fs.writeFile('/d/' + req.query.f, data);\n", VulnClass::PathTraversal);
    expect_class("js sink: createReadStream is path traversal", "src/k6.js",
                 "fs.createReadStream('/d/' + req.query.f);\n", VulnClass::PathTraversal);
    expect_class("js sink: sendFile is path traversal", "src/k7.js",
                 "res.sendFile('/d/' + req.query.f);\n", VulnClass::PathTraversal);
    expect_class("js sink: outerHTML is XSS", "src/k8.js",
                 "el.outerHTML = req.query.html;\n", VulnClass::CrossSiteScripting);
    expect_class("js sink: srcdoc is XSS", "src/k9.js",
                 "frame.srcdoc = req.query.html;\n", VulnClass::CrossSiteScripting);
    expect_class("js sink: document.write is XSS", "src/k10.js",
                 "document.write(req.query.html);\n", VulnClass::CrossSiteScripting);
    expect_class("js sink: insertAdjacentHTML is XSS", "src/k11.js",
                 "el.insertAdjacentHTML('beforeend', req.query.html);\n",
                 VulnClass::CrossSiteScripting);
    expect_class("js sink: axios.get is SSRF", "src/k12.js",
                 "axios.get(req.query.url);\n", VulnClass::ServerSideRequestForgery);
    expect_class("js sink: mongo deleteOne is NoSQL injection", "src/k13.js",
                 "const collection = db.collection('u');\n"
                 "collection.deleteOne(req.body.filter);\n",
                 VulnClass::NoSqlInjection);
    expect_class("js sink: setTimeout with a string body is RCE", "src/k14.js",
                 "setTimeout(req.query.code, 100);\n", VulnClass::RemoteCodeExecution);

    expect_class("py sink: exec is RCE", "src/k15.py",
                 "exec(request.args['code'])\n", VulnClass::RemoteCodeExecution);
    expect_class("py sink: compile is RCE", "src/k16.py",
                 "compile(request.args['code'], '<s>', 'exec')\n",
                 VulnClass::RemoteCodeExecution);
    expect_class("py sink: os.popen is command injection", "src/k17.py",
                 "import os\n"
                 "os.popen('ls ' + request.args['d'])\n",
                 VulnClass::CommandInjection);
    expect_class("py sink: check_output is command injection", "src/k18.py",
                 "import subprocess\n"
                 "subprocess.check_output(request.args['cmd'])\n",
                 VulnClass::CommandInjection);
    expect_class("py sink: executemany is SQL injection", "src/k19.py",
                 "cursor.executemany('INSERT ' + request.args['q'], rows)\n",
                 VulnClass::SqlInjection);
    expect_class("py sink: Django .raw is SQL injection", "src/k20.py",
                 "User.objects.raw('SELECT * FROM u WHERE n = ' + request.args['n'])\n",
                 VulnClass::SqlInjection);
    expect_class("py sink: send_file is path traversal", "src/k21.py",
                 "send_file('/d/' + request.args['f'])\n", VulnClass::PathTraversal);
    expect_class("py sink: marshal.loads is deserialization", "src/k22.py",
                 "import marshal\n"
                 "marshal.loads(request.data)\n",
                 VulnClass::InsecureDeserialization);
    expect_class("py sink: urlopen is SSRF", "src/k23.py",
                 "urlopen(request.args['url'])\n", VulnClass::ServerSideRequestForgery);
    expect_class("py sink: Markup marks a string as trusted HTML", "src/k24.py",
                 "from flask import Markup\n"
                 "Markup(request.args['html'])\n",
                 VulnClass::CrossSiteScripting);

    expect_class("go sink: QueryRow is SQL injection", "src/k25.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  db.QueryRow(\"SELECT * FROM u WHERE n = \" + r.FormValue(\"n\"))\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go sink: Exec is SQL injection", "src/k26.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  db.Exec(\"DELETE FROM u WHERE n = \" + r.FormValue(\"n\"))\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go sink: Prepare is SQL injection", "src/k27.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  db.Prepare(\"SELECT * FROM u WHERE n = \" + r.FormValue(\"n\"))\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go sink: CommandContext is command injection", "src/k28.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  exec.CommandContext(ctx, \"sh\", \"-c\", r.FormValue(\"c\"))\n"
                 "}\n",
                 VulnClass::CommandInjection);
    expect_class("go sink: os.OpenFile is path traversal", "src/k29.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  os.OpenFile(\"/d/\"+r.FormValue(\"f\"), os.O_RDWR, 0644)\n"
                 "}\n",
                 VulnClass::PathTraversal);
    expect_class("go sink: ServeFile is path traversal", "src/k30.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  http.ServeFile(w, r, \"/d/\"+r.FormValue(\"f\"))\n"
                 "}\n",
                 VulnClass::PathTraversal);
    expect_class("go sink: template.HTML is XSS", "src/k31.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  template.HTML(r.FormValue(\"n\"))\n"
                 "}\n",
                 VulnClass::CrossSiteScripting);
    expect_class("go sink: NewRequest is SSRF", "src/k32.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  http.NewRequest(\"GET\", r.FormValue(\"url\"), nil)\n"
                 "}\n",
                 VulnClass::ServerSideRequestForgery);
}

// More propagation shapes: the fixpoint has to survive real code structure.
void propagation_shape_suite() {
    harness::section("Propagation through real code shapes");

    expect_class("js: taint through a template literal", "src/g1.js",
                 "const db = new Pool({});\n"
                 "db.query(`SELECT * FROM u WHERE n = '${req.query.name}'`);\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint through nested template literals", "src/g2.js",
                 "const db = new Pool({});\n"
                 "const frag = `n = '${req.query.name}'`;\n"
                 "db.query(`SELECT * FROM u WHERE ${frag}`);\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint through array join", "src/g3.js",
                 "const db = new Pool({});\n"
                 "const parts = ['SELECT * FROM u WHERE n = ', req.query.name];\n"
                 "db.query(parts.join(''));\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint through an object property read", "src/g4.js",
                 "const db = new Pool({});\n"
                 "const opts = { name: req.query.name };\n"
                 "db.query('SELECT ' + opts.name);\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint through destructuring", "src/g5.js",
                 "const db = new Pool({});\n"
                 "const { name } = req.query;\n"
                 "db.query('SELECT * FROM u WHERE n = ' + name);\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint through an augmented assignment", "src/g6.js",
                 "const db = new Pool({});\n"
                 "let sql = 'SELECT * FROM u WHERE n = ';\n"
                 "sql += req.query.name;\n"
                 "db.query(sql);\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint inside a loop body", "src/g7.js",
                 "const db = new Pool({});\n"
                 "for (const k of keys) {\n"
                 "  db.query('SELECT * FROM u WHERE n = ' + req.query[k]);\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint inside a try block", "src/g8.js",
                 "const db = new Pool({});\n"
                 "try {\n"
                 "  db.query('SELECT ' + req.query.n);\n"
                 "} catch (e) {}\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint through a ternary branch", "src/g9.js",
                 "const db = new Pool({});\n"
                 "const n = req.query.a ? req.query.a : 'default';\n"
                 "db.query('SELECT ' + n);\n",
                 VulnClass::SqlInjection);
    expect_class("js: taint through an async await chain", "src/g10.js",
                 "const db = new Pool({});\n"
                 "async function h(req) {\n"
                 "  const n = await Promise.resolve(req.query.n);\n"
                 "  return db.query('SELECT ' + n);\n"
                 "}\n",
                 VulnClass::SqlInjection);

    expect_class("py: taint through an f-string", "src/g11.py",
                 "cursor.execute(f\"SELECT * FROM u WHERE n = '{request.args['n']}'\")\n",
                 VulnClass::SqlInjection);
    expect_class("py: taint through % formatting", "src/g12.py",
                 "cursor.execute('SELECT * FROM u WHERE n = %s' % request.args['n'])\n",
                 VulnClass::SqlInjection);
    expect_class("py: taint through .format()", "src/g13.py",
                 "cursor.execute('SELECT * FROM u WHERE n = {}'.format(request.args['n']))\n",
                 VulnClass::SqlInjection);
    expect_class("py: taint through a list element", "src/g14.py",
                 "parts = ['SELECT ', request.args['n']]\n"
                 "cursor.execute(''.join(parts))\n",
                 VulnClass::SqlInjection);
    expect_class("py: taint inside a with block", "src/g15.py",
                 "import os\n"
                 "with open('/tmp/log') as f:\n"
                 "    os.system('echo ' + request.args['m'])\n",
                 VulnClass::CommandInjection);
    expect_class("py: taint inside a for loop", "src/g16.py",
                 "import os\n"
                 "for k in keys:\n"
                 "    os.system('echo ' + request.args[k])\n",
                 VulnClass::CommandInjection);
    expect_class("py: taint through a dict value", "src/g17.py",
                 "opts = {'n': request.args['n']}\n"
                 "cursor.execute('SELECT ' + opts['n'])\n",
                 VulnClass::SqlInjection);

    expect_class("go: taint through fmt.Sprintf", "src/g18.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  q := fmt.Sprintf(\"SELECT * FROM u WHERE n = '%s'\", r.FormValue(\"n\"))\n"
                 "  db.Query(q)\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go: taint through a multi-assign", "src/g19.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  a, b := r.FormValue(\"n\"), \"const\"\n"
                 "  _ = b\n"
                 "  db.Query(\"SELECT \" + a)\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go: taint inside an if block", "src/g20.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  if r.Method == \"POST\" {\n"
                 "    db.Query(\"SELECT \" + r.FormValue(\"n\"))\n"
                 "  }\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go: taint through a var declaration", "src/g21.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  var n string = r.FormValue(\"n\")\n"
                 "  db.Query(\"SELECT \" + n)\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go: taint inside a range loop", "src/g22.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  for _, k := range keys {\n"
                 "    db.Query(\"SELECT \" + r.FormValue(k))\n"
                 "  }\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_class("go: taint through a deferred closure", "src/g23.go",
                 "package main\n"
                 "func h(w http.ResponseWriter, r *http.Request) {\n"
                 "  n := r.FormValue(\"n\")\n"
                 "  defer func() { db.Query(\"SELECT \" + n) }()\n"
                 "}\n",
                 VulnClass::SqlInjection);
}

void scan_summary_suite() {
    harness::section("Scan aggregation");

    ScanSummary summary;
    summary.absorb(scan_detailed("test/repo",
                                         {"src/a.js", "const db = mysql.createConnection({});\n"
                                                      "db.query('SELECT ' + req.query.n);\n"}));
    summary.absorb(scan_detailed("test/repo", {"README.md", "not code"}));
    summary.absorb(scan_detailed("test/repo", {"src/b.py", "x = 1\n"}));

    harness::check(summary.files_scanned == 2, "summary: counts scanned files",
                   std::format("got {}", summary.files_scanned));
    harness::check(summary.files_skipped == 1, "summary: counts skipped files",
                   std::format("got {}", summary.files_skipped));
    harness::check(summary.total_findings >= 1, "summary: counts findings");
    harness::check(summary.by_severity[static_cast<int>(Severity::Critical)] >= 1,
                   "summary: buckets findings by severity");
}

// ---------------------------------------------------------------------------
// Class x language matrix.
//
// The claim this backs is "N vulnerability classes across JavaScript, Python
// and Go". Each cell is one canonical vulnerable line, run three ways:
//
//   live      the line as code                 -> must be reported, on that line
//   comment   the same line commented out      -> must produce nothing
//   string    the same text inside a literal   -> must produce nothing
//
// The second and third are what separate matching the syntax tree from
// matching text: the characters are identical in all three.
// ---------------------------------------------------------------------------

struct MatrixCell {
    VulnClass id;
    std::string_view path;    // extension selects the language
    std::string prefix;       // setup; must not contain a sink itself
    std::string sink;         // the one line that must be reported
    std::string suffix;
};

std::string as_string_literal(std::string_view text) {
    std::string out = "\"";
    for (const char c : text) {
        if (c == '\\' || c == '"') out += '\\';
        out += c;
    }
    return out + "\"";
}

std::string_view matrix_language(std::string_view path) {
    if (path.ends_with(".js")) return "js";
    if (path.ends_with(".py")) return "py";
    return "go";
}

void check_matrix_cell(const MatrixCell& cell) {
    const std::string_view language = matrix_language(cell.path);
    const std::string_view name = metadata_for(cell.id).name;
    const std::string path(cell.path);

    const int sink_line =
        1 + static_cast<int>(std::ranges::count(cell.prefix, '\n'));
    const std::string_view sink_text = std::string_view(cell.sink).substr(
        cell.sink.find_first_not_of(' '));
    const std::string indent = cell.sink.substr(0, cell.sink.size() - sink_text.size());

    expect_finding(std::format("{} / {}: live code is reported", language, name), path,
                   cell.prefix + cell.sink + "\n" + cell.suffix, cell.id, sink_line);

    const std::string_view marker = language == "py" ? "# " : "// ";
    expect_none(std::format("{} / {}: commented out is silent", language, name), path,
                cell.prefix + indent + std::string(marker) + std::string(sink_text) + "\n" +
                    cell.suffix);

    const std::string literal = as_string_literal(sink_text);
    std::string statement;
    if (language == "js") {
        statement = "const note = " + literal + ";";
    } else if (language == "py") {
        statement = "note = " + literal;
    } else {
        statement = "note := " + literal;
    }
    expect_none(std::format("{} / {}: inside a string literal is silent", language, name), path,
                cell.prefix + indent + statement + "\n" + cell.suffix);
}

void class_matrix_suite() {
    harness::section("Class x language matrix (live / comment / string)");

    const std::string go_open = "package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n";
    const std::string go_close = "}\n";

    const std::vector<MatrixCell> cells = {
        // ---- JavaScript ----------------------------------------------------
        {VulnClass::SqlInjection, "m/sql.js", "const db = mysql.createConnection({});\n",
         "db.query('SELECT * FROM users WHERE id = ' + req.query.id);", ""},
        {VulnClass::CommandInjection, "m/cmd.js", "const cp = require('child_process');\n",
         "cp.exec('ping -c 1 ' + req.query.host);", ""},
        {VulnClass::CrossSiteScripting, "m/xss.js",
         "const out = document.getElementById('out');\n",
         "out.innerHTML = req.query.name;", ""},
        {VulnClass::PathTraversal, "m/path.js", "const fs = require('fs');\n",
         "fs.readFileSync('/srv/data/' + req.query.file);", ""},
        {VulnClass::ServerSideRequestForgery, "m/ssrf.js", "", "fetch(req.query.url);", ""},
        {VulnClass::RemoteCodeExecution, "m/rce.js", "", "eval(req.body.expression);", ""},
        {VulnClass::OpenRedirect, "m/redirect.js", "app.get('/go', (req, res) => {\n",
         "  res.redirect(req.query.next);", "});\n"},
        {VulnClass::InsecureDeserialization, "m/deser.js",
         "const serialize = require('node-serialize');\n",
         "serialize.unserialize(req.body.profile);", ""},

        // ---- Python --------------------------------------------------------
        {VulnClass::SqlInjection, "m/sql.py", "cursor = conn.cursor()\n",
         "cursor.execute(\"SELECT * FROM users WHERE id = \" + request.args['id'])", ""},
        {VulnClass::CommandInjection, "m/cmd.py", "import os\n",
         "os.system('ping -c 1 ' + request.args['host'])", ""},
        {VulnClass::CrossSiteScripting, "m/xss.py", "from markupsafe import Markup\n",
         "Markup('<b>' + request.args['name'] + '</b>')", ""},
        {VulnClass::PathTraversal, "m/path.py", "",
         "open('/srv/data/' + request.args['file'])", ""},
        {VulnClass::ServerSideRequestForgery, "m/ssrf.py", "import requests\n",
         "requests.get(request.args['url'])", ""},
        {VulnClass::RemoteCodeExecution, "m/rce.py", "", "eval(request.args['expression'])", ""},
        {VulnClass::OpenRedirect, "m/redirect.py", "from flask import redirect\n",
         "redirect(request.args['next'])", ""},
        {VulnClass::InsecureDeserialization, "m/deser.py", "import pickle\n",
         "pickle.loads(request.data)", ""},

        // ---- Go ------------------------------------------------------------
        {VulnClass::SqlInjection, "m/sql.go", go_open,
         "  db.Query(\"SELECT * FROM users WHERE name = '\" + r.FormValue(\"name\") + \"'\")",
         go_close},
        {VulnClass::CommandInjection, "m/cmd.go", go_open,
         "  exec.Command(\"sh\", \"-c\", r.FormValue(\"cmd\"))", go_close},
        {VulnClass::CrossSiteScripting, "m/xss.go", go_open,
         "  fmt.Fprintf(w, \"<h1>Hello %s</h1>\", r.FormValue(\"name\"))", go_close},
        {VulnClass::PathTraversal, "m/path.go", go_open,
         "  os.Open(\"/srv/data/\" + r.FormValue(\"file\"))", go_close},
        {VulnClass::ServerSideRequestForgery, "m/ssrf.go", go_open,
         "  http.Get(r.FormValue(\"url\"))", go_close},
        {VulnClass::RemoteCodeExecution, "m/rce.go", go_open,
         "  template.New(\"page\").Parse(r.FormValue(\"tpl\"))", go_close},
        {VulnClass::OpenRedirect, "m/redirect.go", go_open,
         "  http.Redirect(w, r, r.FormValue(\"next\"), http.StatusFound)", go_close},
        {VulnClass::InsecureDeserialization, "m/deser.go", go_open,
         "  gob.NewDecoder(r.Body).Decode(&session)", go_close},
    };

    for (const auto& cell : cells) check_matrix_cell(cell);
}

// Go names things generically -- Write, Parse, Run, Unmarshal, Open -- so a
// rule keyed on the method name alone reports most of the standard library.
// These pin down both halves of each strict rule: it fires on the dangerous
// receiver and stays quiet on the look-alikes.
void go_receiver_precision_suite() {
    harness::section("Go: strict receiver guards");

    const auto handler = [](const std::string& body) {
        return "package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n" + body + "}\n";
    };

    // ---- XSS: the writer has to be the response ----------------------------
    expect_finding("go xss: w.Write on a ResponseWriter parameter", "g/x1.go",
                   handler("  w.Write([]byte(\"<p>\" + r.FormValue(\"q\") + \"</p>\"))\n"),
                   VulnClass::CrossSiteScripting, 3);
    expect_finding("go xss: tainted Fprintf format string", "g/x2.go",
                   handler("  fmt.Fprintf(w, r.FormValue(\"q\"))\n"),
                   VulnClass::CrossSiteScripting, 3);
    expect_finding("go xss: io.WriteString to the response", "g/x3.go",
                   handler("  io.WriteString(w, r.FormValue(\"q\"))\n"),
                   VulnClass::CrossSiteScripting, 3);
    expect_confidence("go xss: a typed parameter resolves the receiver", "g/x4.go",
                      handler("  w.Write([]byte(r.FormValue(\"q\")))\n"),
                      VulnClass::CrossSiteScripting, Confidence::High);

    expect_not_class("go xss: Fprintf to stderr is not HTML output", "g/x5.go",
                     handler("  fmt.Fprintf(os.Stderr, \"bad input: %s\\n\", r.FormValue(\"q\"))\n"),
                     VulnClass::CrossSiteScripting);
    expect_not_class("go xss: writing to a hash is not HTML output", "g/x6.go",
                     handler("  digest := sha256.New()\n"
                             "  digest.Write([]byte(r.FormValue(\"q\")))\n"),
                     VulnClass::CrossSiteScripting);
    expect_not_class("go xss: writing to an io.Writer parameter is not HTML output", "g/x7.go",
                     "package main\n"
                     "func dump(out io.Writer, r *http.Request) {\n"
                     "  out.Write([]byte(r.FormValue(\"q\")))\n"
                     "}\n",
                     VulnClass::CrossSiteScripting);
    expect_not_class("go xss: Fprintf of constants to the response", "g/x8.go",
                     handler("  fmt.Fprintf(w, \"<p>%d items</p>\", 3)\n"),
                     VulnClass::CrossSiteScripting);

    // Grouped names share one declared type.
    expect_class("go types: grouped parameters both take the declared type", "g/x9.go",
                 "package main\n"
                 "func copyTo(primary, mirror http.ResponseWriter, r *http.Request) {\n"
                 "  mirror.Write([]byte(r.FormValue(\"q\")))\n"
                 "}\n",
                 VulnClass::CrossSiteScripting);

    // ---- Deserialization: data-only codecs are not CWE-502 ------------------
    expect_none("go deser: json.Unmarshal of a request body is data-only", "g/d1.go",
                handler("  body, _ := io.ReadAll(r.Body)\n"
                        "  var payload map[string]string\n"
                        "  json.Unmarshal(body, &payload)\n"));
    expect_none("go deser: proto.Unmarshal is data-only", "g/d2.go",
                handler("  body, _ := io.ReadAll(r.Body)\n"
                        "  proto.Unmarshal(body, &message)\n"));

    // ---- Code injection ------------------------------------------------------
    expect_finding("go rce: template bound to a variable, then parsed", "g/r1.go",
                   handler("  page := template.New(\"page\")\n"
                           "  page.Parse(r.FormValue(\"tpl\"))\n"),
                   VulnClass::RemoteCodeExecution, 4);
    expect_finding("go rce: template.Must wrapping a tainted Parse", "g/r2.go",
                   handler("  template.Must(template.New(\"page\").Parse(r.FormValue(\"tpl\")))\n"),
                   VulnClass::RemoteCodeExecution, 3);
    expect_finding("go rce: goja RunString", "g/r3.go",
                   handler("  vm := goja.New()\n"
                           "  vm.RunString(r.FormValue(\"script\"))\n"),
                   VulnClass::RemoteCodeExecution, 4);
    expect_finding("go rce: otto Run on a bound interpreter", "g/r4.go",
                   handler("  vm := otto.New()\n"
                           "  vm.Run(r.FormValue(\"script\"))\n"),
                   VulnClass::RemoteCodeExecution, 4);
    expect_finding("go rce: gopher-lua DoString", "g/r5.go",
                   handler("  state := lua.NewState()\n"
                           "  state.DoString(r.FormValue(\"script\"))\n"),
                   VulnClass::RemoteCodeExecution, 4);
    expect_finding("go rce: expr.Eval", "g/r6.go",
                   handler("  expr.Eval(r.FormValue(\"rule\"), env)\n"),
                   VulnClass::RemoteCodeExecution, 3);
    expect_finding("go rce: plugin.Open loads attacker-chosen code", "g/r7.go",
                   handler("  plugin.Open(r.FormValue(\"module\"))\n"),
                   VulnClass::RemoteCodeExecution, 3);
    expect_not_class("go rce: plugin.Open is not double-reported as path traversal", "g/r8.go",
                     handler("  plugin.Open(r.FormValue(\"module\"))\n"),
                     VulnClass::PathTraversal);

    expect_not_class("go rce: url.Parse is not a template", "g/r9.go",
                     handler("  url.Parse(r.FormValue(\"next\"))\n"),
                     VulnClass::RemoteCodeExecution);
    expect_not_class("go rce: time.Parse is not a template", "g/r10.go",
                     handler("  time.Parse(time.RFC3339, r.FormValue(\"when\"))\n"),
                     VulnClass::RemoteCodeExecution);
    expect_not_class("go rce: Run on something that is not an interpreter", "g/r11.go",
                     handler("  server.Run(r.FormValue(\"addr\"))\n"),
                     VulnClass::RemoteCodeExecution);
    expect_none("go rce: a constant template is not injection", "g/r12.go",
                handler("  template.New(\"page\").Parse(\"<h1>{{.Title}}</h1>\")\n"));
    expect_not_class("go rce: template data is not template source", "g/r13.go",
                     handler("  page := template.Must(template.New(\"page\").Parse(\"<h1>{{.}}</h1>\"))\n"
                             "  page.Execute(w, r.FormValue(\"title\"))\n"),
                     VulnClass::RemoteCodeExecution);
}

// The single-hop case -- handler calls helper, helper holds the sink -- is in
// interprocedural_suite. These are the shapes beyond it: the sink two or more
// calls away, a source two calls away, and a sanitizer somewhere in between.
void transitive_interprocedural_suite() {
    harness::section("Interprocedural taint: chains of helpers");

    // ---- A sink two calls away ------------------------------------------------
    expect_finding("js chain: handler -> findUser -> run -> db.query", "t/a1.js",
                   "const db = mysql.createConnection({});\n"
                   "function run(sql) {\n"
                   "  return db.query(sql);\n"
                   "}\n"
                   "function findUser(id) {\n"
                   "  return run('SELECT * FROM users WHERE id = ' + id);\n"
                   "}\n"
                   "app.get('/u', (req, res) => {\n"
                   "  findUser(req.query.id);\n"
                   "});\n",
                   VulnClass::SqlInjection, 9);

    expect_finding("py chain: handler -> lookup -> run -> os.system", "t/a2.py",
                   "import os\n"
                   "def run(cmd):\n"
                   "    os.system(cmd)\n"
                   "def lookup(host):\n"
                   "    run('nslookup ' + host)\n"
                   "def handler():\n"
                   "    lookup(request.args.get('host'))\n",
                   VulnClass::CommandInjection, 7);

    expect_finding("go chain: handler -> findUser -> run -> db.Query", "t/a3.go",
                   "package main\n"
                   "func run(q string) {\n"
                   "  db.Query(q)\n"
                   "}\n"
                   "func findUser(name string) {\n"
                   "  run(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
                   "}\n"
                   "func handler(w http.ResponseWriter, r *http.Request) {\n"
                   "  findUser(r.FormValue(\"name\"))\n"
                   "}\n",
                   VulnClass::SqlInjection, 9);

    // ---- Three calls away, and the callers written before their callees ---------
    expect_finding("js chain: three helpers, defined caller-first", "t/a4.js",
                   "const db = mysql.createConnection({});\n"
                   "app.get('/r', (req, res) => {\n"
                   "  report(req.query.month);\n"
                   "});\n"
                   "function report(month) { return build(month); }\n"
                   "function build(month) { return fetch_rows('WHERE m = ' + month); }\n"
                   "function fetch_rows(clause) { return db.query('SELECT * FROM r ' + clause); }\n",
                   VulnClass::SqlInjection, 3);

    // A chain longer than the fixpoint's old iteration bound, in the worst
    // order for it: every caller appears before its callee, so an unordered
    // pass learns one level per iteration.
    {
        std::string code = "const db = mysql.createConnection({});\n"
                           "app.get('/deep', (req, res) => {\n"
                           "  f0(req.query.v);\n"
                           "});\n";
        constexpr int kDepth = 14;
        for (int i = 0; i < kDepth; ++i) {
            code += std::format("function f{}(v) {{ return f{}(v); }}\n", i, i + 1);
        }
        code += std::format("function f{}(v) {{ return db.query('SELECT ' + v); }}\n", kDepth);
        expect_finding("js chain: fourteen helpers deep, caller-first", "t/a5.js", code,
                       VulnClass::SqlInjection, 3);
    }

    // ---- The trace names where the sink really is ------------------------------
    expect_trace_mentions("js chain: the trace names the function holding the sink", "t/a6.js",
                          "const db = mysql.createConnection({});\n"
                          "function run(sql) { return db.query(sql); }\n"
                          "function findUser(id) { return run('SELECT ' + id); }\n"
                          "app.get('/u', (req, res) => { findUser(req.query.id); });\n",
                          VulnClass::SqlInjection, "inside run()");

    // ---- A source two calls away ----------------------------------------------
    expect_finding("js chain: a source returned through two helpers", "t/b1.js",
                   "const db = mysql.createConnection({});\n"
                   "function rawId(req) { return req.query.id; }\n"
                   "function userId(req) { return rawId(req); }\n"
                   "app.get('/u', (req, res) => {\n"
                   "  db.query('SELECT * FROM u WHERE id = ' + userId(req));\n"
                   "});\n",
                   VulnClass::SqlInjection, 5);

    expect_finding("py chain: a source returned through two helpers", "t/b2.py",
                   "import os\n"
                   "def raw_host():\n"
                   "    return request.args.get('host')\n"
                   "def host():\n"
                   "    return raw_host()\n"
                   "def handler():\n"
                   "    os.system('ping ' + host())\n",
                   VulnClass::CommandInjection, 7);

    // ---- Source and sink both behind helpers -----------------------------------
    expect_class("js chain: helper source into helper sink", "t/b3.js",
                 "const db = mysql.createConnection({});\n"
                 "function param(req) { return req.query.q; }\n"
                 "function search(term) { return db.query('SELECT * FROM t WHERE x = ' + term); }\n"
                 "app.get('/s', (req, res) => { search(param(req)); });\n",
                 VulnClass::SqlInjection);

    // ---- A sanitizer in the middle of the chain --------------------------------
    expect_none("js chain: sanitised before the helper that holds the sink", "t/c1.js",
                "function clean(s) { return escapeHtml(s); }\n"
                "function render(html) { document.getElementById('out').innerHTML = html; }\n"
                "function show(text) { render(clean(text)); }\n"
                "app.get('/p', (req, res) => { show(req.query.name); });\n");

    expect_class("js chain: the same chain without the sanitizer reports", "t/c2.js",
                 "function render(html) { document.getElementById('out').innerHTML = html; }\n"
                 "function show(text) { render(text); }\n"
                 "app.get('/p', (req, res) => { show(req.query.name); });\n",
                 VulnClass::CrossSiteScripting);

    expect_none("js chain: a numeric coercion two calls up clears every class", "t/c3.js",
                "const db = mysql.createConnection({});\n"
                "function run(sql) { return db.query(sql); }\n"
                "function byId(id) { return run('SELECT * FROM u WHERE id = ' + parseInt(id, 10)); }\n"
                "app.get('/u', (req, res) => { byId(req.query.id); });\n");

    // ---- Recursion that reaches a sink -----------------------------------------
    expect_class("js chain: a recursive function with a sink at its base case", "t/d1.js",
                 "const db = mysql.createConnection({});\n"
                 "function walk(path, depth) {\n"
                 "  if (depth > 3) return db.query('SELECT * FROM n WHERE p = ' + path);\n"
                 "  return walk(path, depth + 1);\n"
                 "}\n"
                 "app.get('/n', (req, res) => { walk(req.query.p, 0); });\n",
                 VulnClass::SqlInjection);

    expect_class("js chain: mutual recursion with a sink on one side", "t/d2.js",
                 "const db = mysql.createConnection({});\n"
                 "function ping(v, n) { return n > 2 ? db.query('SELECT ' + v) : pong(v, n + 1); }\n"
                 "function pong(v, n) { return ping(v, n + 1); }\n"
                 "app.get('/pp', (req, res) => { pong(req.query.v, 0); });\n",
                 VulnClass::SqlInjection);

    // ---- A property sink behind a helper ----------------------------------------
    expect_finding("js chain: a helper that assigns innerHTML", "t/c4.js",
                   "function render(html) {\n"
                   "  document.getElementById('out').innerHTML = html;\n"
                   "}\n"
                   "app.get('/p', (req, res) => {\n"
                   "  render(req.query.name);\n"
                   "});\n",
                   VulnClass::CrossSiteScripting, 5);

    // ---- And what must stay quiet ----------------------------------------------
    expect_none("js chain: a constant through the whole chain", "t/e1.js",
                "const db = mysql.createConnection({});\n"
                "function run(sql) { return db.query(sql); }\n"
                "function findUser(id) { return run('SELECT * FROM users WHERE id = ' + id); }\n"
                "findUser('42');\n");

    expect_none("js chain: the tainted argument is not the one that reaches the sink", "t/e2.js",
                "const db = mysql.createConnection({});\n"
                "function run(sql, label) { return db.query(sql); }\n"
                "function findAll(label) { return run('SELECT * FROM users', label); }\n"
                "app.get('/u', (req, res) => { findAll(req.query.label); });\n");
}

// The summary fixpoint itself, with a stand-in for the analyzer: each function
// "reaches a sink" if it is the leaf, or if the function it calls does.
void summary_fixpoint_suite() {
    harness::section("Summary fixpoint: ordering and recomputation");

    const auto make = [](std::initializer_list<const char*> names) {
        std::vector<FunctionInfo> functions;
        for (const char* name : names) {
            FunctionInfo info;
            info.name = name;
            info.parameters = {"p"};
            functions.push_back(std::move(info));
        }
        return functions;
    };

    // a -> b -> c, and c holds the sink.
    const std::map<std::string, std::string> calls = {{"a", "b"}, {"b", "c"}};
    int computations = 0;
    const SummaryComputer compute = [&](const FunctionInfo& function, const SummaryTable& known) {
        ++computations;
        FunctionSummary summary;
        if (function.name == "c") {
            summary.parameter_sinks.push_back({0, VulnClass::SqlInjection, 7, "db.query(p)", "c"});
        } else if (const auto callee = calls.find(function.name); callee != calls.end()) {
            const FunctionSummary* inner = known.find(callee->second);
            if (inner != nullptr && inner->reaches_sink_from(0)) {
                summary.parameter_sinks.push_back(inner->parameter_sinks.front());
            }
        }
        return summary;
    };

    const auto functions = make({"a", "b", "c"});  // callers listed first

    {
        // Callees first: every function is computed exactly once.
        SummaryPlan plan;
        plan.order = {2, 1, 0};
        plan.callees = {{"b"}, {"c"}, {}};
        computations = 0;
        const SummaryTable table = compute_summaries(functions, compute, plan);
        const FunctionSummary* a = table.find("a");
        harness::check(a != nullptr && a->reaches_sink_from(0),
                       "fixpoint: the sink at the end of the chain reaches its first caller");
        harness::check(a != nullptr && !a->parameter_sinks.empty() &&
                           a->parameter_sinks.front().sink_function == "c" &&
                           a->parameter_sinks.front().line == 7,
                       "fixpoint: and still names the function and line that hold it");
        harness::check(computations == 3,
                       "fixpoint: callee-first order settles an acyclic chain in one pass",
                       std::format("{} computations for 3 functions", computations));
    }

    {
        // No plan: source order, everything recomputed each pass. Slower, same answer.
        computations = 0;
        const SummaryTable table = compute_summaries(functions, compute);
        const FunctionSummary* a = table.find("a");
        harness::check(a != nullptr && a->reaches_sink_from(0) && computations > 3,
                       "fixpoint: without a plan it still converges, by iterating",
                       std::format("{} computations", computations));
    }

    {
        // Dependencies known but the order adverse: only stale functions are redone.
        SummaryPlan plan;
        plan.order = {0, 1, 2};
        plan.callees = {{"b"}, {"c"}, {}};
        computations = 0;
        const SummaryTable table = compute_summaries(functions, compute, plan);
        const FunctionSummary* a = table.find("a");
        // Pass 1 computes a, b, c (b sees c's seed, not its result). Pass 2 redoes
        // b only; pass 3 redoes a only. Five in all, where recomputing everything
        // on every pass until nothing moves would take twelve.
        harness::check(a != nullptr && a->reaches_sink_from(0) && computations == 5,
                       "fixpoint: in a bad order, only functions whose callees changed are redone",
                       std::format("{} computations", computations));
    }

    {
        // A function that calls itself is revisited until it stops changing.
        const auto recursive = make({"walk"});
        int depth_learned = 0;
        int visits = 0;
        const SummaryComputer grow = [&](const FunctionInfo&, const SummaryTable& known) {
            ++visits;
            FunctionSummary summary;
            const FunctionSummary* self = known.find("walk");
            // Learns one more fact per visit, up to three, as a recursive
            // summary that depends on its own previous value would.
            depth_learned = std::min<int>(3, static_cast<int>(self->parameter_sinks.size()) + 1);
            for (int i = 0; i < depth_learned; ++i) {
                summary.parameter_sinks.push_back(
                    {static_cast<std::size_t>(i), VulnClass::SqlInjection, 1, "", "walk"});
            }
            return summary;
        };
        SummaryPlan plan;
        plan.order = {0};
        plan.callees = {{"walk"}};
        const SummaryTable table = compute_summaries(recursive, grow, plan);
        harness::check(table.find("walk")->parameter_sinks.size() == 3 && visits == 4,
                       "fixpoint: recursion iterates to its fixpoint and then stops",
                       std::format("{} facts after {} visits", table.find("walk")->parameter_sinks.size(),
                                   visits));
    }

    {
        // Two definitions with one name: the table holds what either does.
        const auto twins = make({"save", "save"});
        const SummaryComputer one_each = [&](const FunctionInfo& function, const SummaryTable&) {
            FunctionSummary summary;
            const bool first = &function == &twins[0];
            summary.parameter_sinks.push_back(
                {0, first ? VulnClass::SqlInjection : VulnClass::PathTraversal, 1, "", "save"});
            return summary;
        };
        const SummaryTable table = compute_summaries(twins, one_each);
        const FunctionSummary* save = table.find("save");
        harness::check(save != nullptr && save->parameter_sinks.size() == 2,
                       "fixpoint: same-named definitions are combined, neither hides the other");
    }
}

// These assert what the engine does NOT do. Each is a real limit, written down
// as a test so that it is a known quantity rather than a surprise, and so that
// whoever lifts one finds the test that has to change.
void known_limit_suite() {
    harness::section("Known limits (asserted so they stay visible)");

    // A function passed as a value is summarised, but nothing connects the
    // values it is eventually called with to its parameter.
    expect_none("limit: a callback's parameter is not connected to its caller's data",
                "limits/callback.js",
                "const db = mysql.createConnection({});\n"
                "function each(items, fn) { items.forEach(fn); }\n"
                "app.get('/x', (req, res) => {\n"
                "  each([req.query.a], (v) => db.query('SELECT ' + v));\n"
                "});\n");

    // Calls are matched to functions by name, not by receiver, so two methods
    // called `save` are one function. This over-reports.
    expect_class("limit: methods are matched by name, so cache.save is read as audit.save",
                 "limits/methods.js",
                 "const db = mysql.createConnection({});\n"
                 "const audit = { save(entry) { db.query('INSERT INTO log VALUES (' + entry + ')'); } };\n"
                 "const cache = { save(entry) { memory.push(entry); } };\n"
                 "app.post('/c', (req, res) => { cache.save(req.body.item); });\n",
                 VulnClass::SqlInjection);

    // Taint is per variable, not per field: assigning one field taints the
    // whole object, and so every other field read from it.
    expect_class("limit: no field sensitivity, tainting user.name taints user.id",
                 "limits/fields.js",
                 "app.post('/u', (req, res) => {\n"
                 "  const user = {};\n"
                 "  user.name = req.body.name;\n"
                 "  user.id = 7;\n"
                 "  res.redirect('/users/' + user.id);\n"
                 "});\n",
                 VulnClass::OpenRedirect);

    // A helper defined in another file has no summary here. The call is
    // treated as an unknown function: its result carries its arguments' taint,
    // but a sink inside it is invisible.
    expect_none("limit: a sink inside an imported helper is not seen",
                "limits/crossfile.js",
                "const { runQuery } = require('./db');\n"
                "app.get('/u', (req, res) => {\n"
                "  runQuery('SELECT * FROM u WHERE id = ' + req.query.id);\n"
                "});\n");
}

std::size_t count_class(const std::vector<Finding>& findings, VulnClass id) {
    return static_cast<std::size_t>(std::ranges::count(findings, id, &Finding::vulnerability));
}

// Each case here is a false positive (or a double count) that the benchmark
// over real repositories turned up, reduced to the smallest code that shows it,
// next to the true positive it must not be confused with.
void benchmark_regression_suite() {
    harness::section("Regressions found by the benchmark corpus");

    const auto go_handler = [](const std::string& body) {
        return "package main\nfunc h(w http.ResponseWriter, r *http.Request) {\n" + body + "}\n";
    };

    // ---- One construct, one finding -----------------------------------------
    {
        const auto findings = analyze("net/client.go",
                                      "package main\n"
                                      "func client() *http.Client {\n"
                                      "  tr := &http.Transport{\n"
                                      "    TLSClientConfig: &tls.Config{\n"
                                      "      InsecureSkipVerify: true,\n"
                                      "    },\n"
                                      "  }\n"
                                      "  return &http.Client{Transport: tr}\n"
                                      "}\n");
        harness::check(count_class(findings, VulnClass::WeakCryptography) == 1,
                       "config: a nested literal is reported once, not once per enclosing entry",
                       describe(findings));
        harness::check(!findings.empty() && findings.front().line == 5,
                       "config: and on the line the setting is written",
                       describe(findings));
    }

    // ---- Sources match whole name segments -----------------------------------
    harness::check(source_pattern_matches("r.Form", "r.Form") &&
                       source_pattern_matches("r.Form.Get", "r.Form") &&
                       source_pattern_matches("r.Form[\"q\"]", "r.Form") &&
                       source_pattern_matches("ctx.req.query.id", "req.query"),
                   "source match: a pattern matches at segment boundaries");
    harness::check(!source_pattern_matches("r.Format", "r.Form") &&
                       !source_pattern_matches("r.Formatter.Run", "r.Form") &&
                       !source_pattern_matches("prereq.query", "req.query") &&
                       !source_pattern_matches("req.filename", "req.file"),
                   "source match: but not inside a longer identifier");
    harness::check(source_pattern_matches("input(", "input(") &&
                       source_pattern_matches("x = input(", "input(") &&
                       !source_pattern_matches("raw_input(", "input("),
                   "source match: a pattern ending in punctuation needs no right boundary");

    expect_none("go source: r.Format is a field, not the parsed form", "render/text.go",
                "package render\n"
                "func (r String) Render(w http.ResponseWriter) error {\n"
                "  fmt.Fprintf(w, r.Format, r.Data...)\n"
                "  return nil\n"
                "}\n");
    expect_class("go source: r.Form.Get still is", "h/form.go",
                 go_handler("  db.Query(\"SELECT * FROM u WHERE n = '\" + r.Form.Get(\"n\") + \"'\")\n"),
                 VulnClass::SqlInjection);
    expect_class("go source: gin c.Params", "h/params.go",
                 "package main\n"
                 "func h(c *gin.Context) {\n"
                 "  db.Query(\"SELECT * FROM u WHERE id = \" + c.Params.ByName(\"id\"))\n"
                 "}\n",
                 VulnClass::SqlInjection);
    expect_none("js source: req.queryCache is not req.query", "src/cache.js",
                "const db = mysql.createConnection({});\n"
                "db.query('SELECT * FROM t WHERE k = ' + req.queryCache.key);\n");

    // ---- A prepared statement's arguments are bound values --------------------
    expect_none("go sql: arguments to a prepared statement are parameters", "db/stmt.go",
                go_handler("  stmt, _ := db.Prepare(\"SELECT * FROM u WHERE name = ?\")\n"
                           "  stmt.QueryRow(r.FormValue(\"name\"))\n"));
    expect_none("go sql: a *sql.Stmt parameter is recognised by its type", "db/stmt2.go",
                "package main\n"
                "func find(stmt *sql.Stmt, r *http.Request) {\n"
                "  stmt.Query(r.FormValue(\"name\"))\n"
                "}\n");
    expect_none("go sql: a helper that binds its parameter is not a sink", "db/stmt3.go",
                "package main\n"
                "func lookup(name string) {\n"
                "  stmt, _ := db.Prepare(\"SELECT * FROM u WHERE name = ?\")\n"
                "  stmt.QueryRow(name)\n"
                "}\n"
                "func h(w http.ResponseWriter, r *http.Request) {\n"
                "  lookup(r.FormValue(\"name\"))\n"
                "}\n");
    expect_finding("go sql: tainted text given to Prepare is still injection", "db/stmt4.go",
                   go_handler("  db.Prepare(\"SELECT * FROM u WHERE name = '\" + r.FormValue(\"name\") + \"'\")\n"),
                   VulnClass::SqlInjection, 3);
    expect_finding("go sql: QueryRow on the database itself is still injection", "db/stmt5.go",
                   go_handler("  db.QueryRow(\"SELECT * FROM u WHERE name = '\" + r.FormValue(\"name\") + \"'\")\n"),
                   VulnClass::SqlInjection, 3);

    // ---- An ORM where-clause is not a document-database filter ---------------
    expect_none("js nosql: Sequelize find({ where }) is an ORM query", "src/orm.js",
                "app.get('/u', (req, res) => {\n"
                "  db.User.find({ where: { id: req.query.id } });\n"
                "});\n");
    expect_class("js nosql: a tainted filter on a Mongo collection still reports", "src/mongo.js",
                 "const users = db.collection('users');\n"
                 "app.post('/login', (req, res) => {\n"
                 "  users.findOne({ name: req.body.name, password: req.body.password });\n"
                 "});\n",
                 VulnClass::NoSqlInjection);
    expect_class("js nosql: so does $where, which is not the ORM key", "src/mongo2.js",
                 "const users = db.collection('users');\n"
                 "users.find({ $where: req.body.predicate });\n",
                 VulnClass::NoSqlInjection);

    // ---- A non-cryptographic RNG matters only where it must be unpredictable --
    expect_none("js rng: Math.random for jitter is not a weakness", "src/retry.js",
                "const delay = 100 + Math.random() * 50;\n");
    expect_none("js rng: nor for a DOM element id", "src/tooltip.js",
                "Tooltip.prototype.getUID = function (prefix) {\n"
                "  do prefix += ~~(Math.random() * 1000000)\n"
                "  while (document.getElementById(prefix))\n"
                "  return prefix\n"
                "}\n");
    expect_class("js rng: Math.random for a session id is", "src/session.js",
                 "const sessionId = Math.random().toString(36).slice(2);\n",
                 VulnClass::WeakCryptography);
    expect_class("js rng: the enclosing function's name counts as context", "src/reset.js",
                 "function generateResetCode() {\n"
                 "  return Math.floor(Math.random() * 1000000);\n"
                 "}\n",
                 VulnClass::WeakCryptography);
    expect_none("py rng: random.random for a backoff is not a weakness", "src/retry.py",
                "import random\n"
                "delay = 1.0 + random.random()\n");
    expect_class("py rng: random.random for a one-time code is", "src/otp.py",
                 "import random\n"
                 "otp = int(random.random() * 1000000)\n",
                 VulnClass::WeakCryptography);

    // ---- `loads` is only dangerous on a serializer that builds objects ---------
    expect_none("py deser: a signed-cookie serializer's loads is not pickle", "src/sess.py",
                "s = URLSafeTimedSerializer(secret)\n"
                "data = s.loads(request.cookies.get('session'))\n");
    expect_class("py deser: pickle imported under an alias still reports", "src/alias.py",
                 "import pickle as pk\n"
                 "pk.loads(request.data)\n",
                 VulnClass::InsecureDeserialization);
    expect_class("py deser: so does a bare loads imported from pickle", "src/bare.py",
                 "from pickle import loads\n"
                 "loads(request.data)\n",
                 VulnClass::InsecureDeserialization);
    expect_none("py deser: a bare loads imported from json does not", "src/barejson.py",
                "from json import loads\n"
                "loads(request.data)\n");

    // ---- One flaw, one finding: a flow and a pattern on the same call ---------
    {
        const auto findings = analyze("src/dig.py",
                                      "import subprocess\n"
                                      "command = 'dig ' + request.POST['domain']\n"
                                      "process = subprocess.Popen(\n"
                                      "    command,\n"
                                      "    shell=True,\n"
                                      "    stdout=subprocess.PIPE)\n");
        harness::check(count_class(findings, VulnClass::CommandInjection) == 1,
                       "config: shell=True inside an already-reported call is not a second finding",
                       describe(findings));
    }
    expect_class("config: shell=True with no tainted flow is still reported by itself", "src/sh.py",
                 "import subprocess\n"
                 "subprocess.Popen(build_command(), shell=True)\n",
                 VulnClass::CommandInjection);

    // ---- Operator-controlled input is still reported, at low confidence ------
    expect_confidence("local source: argv reaching a shell is low confidence", "tools/run.js",
                      "const cp = require('child_process');\n"
                      "cp.exec('ls ' + process.argv[2]);\n",
                      VulnClass::CommandInjection, Confidence::Low);
    expect_confidence("local source: the same flow from a request is not", "src/run.js",
                      "const cp = require('child_process');\n"
                      "cp.exec('ls ' + req.query.dir);\n",
                      VulnClass::CommandInjection, Confidence::High);
    expect_confidence("local source: sys.argv through a variable stays low", "tools/brute.py",
                      "import subprocess, sys\n"
                      "program = sys.argv[1]\n"
                      "subprocess.run(program)\n",
                      VulnClass::CommandInjection, Confidence::Low);
    expect_confidence("local source: an environment variable naming a file", "tools/conf.py",
                      "import os\n"
                      "open(os.environ['APP_CONFIG'])\n",
                      VulnClass::PathTraversal, Confidence::Low);
    {
        const TaintFact remote = fact_from_source("req.query.x", {1, "x", "entered"});
        TaintFact local = fact_from_source("sys.argv", {2, "y", "entered"});
        local.local = true;
        harness::check(!merge(remote, local).local && !merge(local, remote).local &&
                           merge(local, local).local,
                       "local source: a value also reachable from a request is not local");
    }
}

// A sanitizer is rarely called directly at the sink. Real code wraps it --
// `clean()`, `safe()`, a one-line arrow function -- and the engine has to see
// through the wrapper in both directions: the wrapped value is clean for what
// the sanitizer covers, and still dirty for everything else.
void sanitizer_wrapper_suite() {
    harness::section("Sanitizers behind user-defined wrappers");

    // ---- JavaScript ----------------------------------------------------------
    expect_none("js wrapper: escapeHtml wrapper clears XSS", "w/a1.js",
                "function clean(s) {\n"
                "  return escapeHtml(s);\n"
                "}\n"
                "const el = document.getElementById('out');\n"
                "el.innerHTML = clean(req.query.name);\n");

    expect_finding("js wrapper: the same wrapper does not clear SQL injection", "w/a2.js",
                   "const db = mysql.createConnection({});\n"
                   "function clean(s) {\n"
                   "  return escapeHtml(s);\n"
                   "}\n"
                   "db.query('SELECT * FROM u WHERE n = ' + clean(req.query.name));\n",
                   VulnClass::SqlInjection, 5);

    expect_none("js wrapper: parseInt wrapper clears every class", "w/a3.js",
                "const db = mysql.createConnection({});\n"
                "function toId(value) {\n"
                "  return parseInt(value, 10);\n"
                "}\n"
                "db.query('SELECT * FROM u WHERE id = ' + toId(req.query.id));\n");

    expect_none("js wrapper: sanitizer result held in a local first", "w/a4.js",
                "function clean(s) {\n"
                "  const out = escapeHtml(s);\n"
                "  return out;\n"
                "}\n"
                "document.getElementById('out').innerHTML = clean(req.query.name);\n");

    expect_none("js wrapper: expression-bodied arrow sanitizer", "w/a5.js",
                "const clean = (s) => escapeHtml(s);\n"
                "document.getElementById('out').innerHTML = clean(req.query.name);\n");

    // The mirror image: an expression-bodied arrow that is a plain conduit must
    // keep the taint. It has no `return` statement to find.
    expect_finding("js wrapper: expression-bodied arrow conduit keeps taint", "w/a6.js",
                   "const db = mysql.createConnection({});\n"
                   "const where = (v) => 'SELECT * FROM u WHERE id = ' + v;\n"
                   "db.query(where(req.query.id));\n",
                   VulnClass::SqlInjection, 3);

    // One unsanitised path out is enough to stay dirty.
    expect_finding("js wrapper: a branch that skips the sanitizer still reports", "w/a7.js",
                   "function maybeClean(s, raw) {\n"
                   "  if (raw) return s;\n"
                   "  return escapeHtml(s);\n"
                   "}\n"
                   "document.getElementById('out').innerHTML = maybeClean(req.query.name, true);\n",
                   VulnClass::CrossSiteScripting, 5);

    // A helper that reads the source itself and sanitises it.
    expect_none("js wrapper: source-returning helper sanitised for XSS", "w/a8.js",
                "function displayName(req) {\n"
                "  return escapeHtml(req.query.name);\n"
                "}\n"
                "app.get('/', (req, res) => {\n"
                "  document.getElementById('out').innerHTML = displayName(req);\n"
                "});\n");

    expect_class("js wrapper: that helper's value is still SQL-dangerous", "w/a9.js",
                 "const db = mysql.createConnection({});\n"
                 "function displayName(req) {\n"
                 "  return escapeHtml(req.query.name);\n"
                 "}\n"
                 "app.get('/', (req, res) => {\n"
                 "  db.query('SELECT * FROM u WHERE n = ' + displayName(req));\n"
                 "});\n",
                 VulnClass::SqlInjection);

    // Wrappers compose.
    expect_none("js wrapper: a wrapper around a wrapper", "w/a10.js",
                "function inner(s) { return escapeHtml(s); }\n"
                "function outer(s) { return inner(s); }\n"
                "document.getElementById('out').innerHTML = outer(req.query.name);\n");

    // Library escapes addressed by their dotted names.
    expect_none("js sanitizer: lodash _.escape clears XSS", "w/a11.js",
                "document.getElementById('out').innerHTML = _.escape(req.query.name);\n");
    expect_none("js sanitizer: validator.escape clears XSS", "w/a12.js",
                "document.getElementById('out').innerHTML = validator.escape(req.query.name);\n");
    expect_none("js sanitizer: connection.escape clears SQL injection", "w/a13.js",
                "const connection = mysql.createConnection({});\n"
                "connection.query('SELECT * FROM u WHERE n = ' + connection.escape(req.query.n));\n");
    expect_class("js sanitizer: connection.escape does not clear XSS", "w/a14.js",
                 "const connection = mysql.createConnection({});\n"
                 "document.getElementById('out').innerHTML = connection.escape(req.query.n);\n",
                 VulnClass::CrossSiteScripting);

    // ---- Python --------------------------------------------------------------
    expect_none("py wrapper: html.escape wrapper clears XSS", "w/b1.py",
                "import html\n"
                "from markupsafe import Markup\n"
                "def clean(s):\n"
                "    return html.escape(s)\n"
                "Markup(clean(request.args['name']))\n");

    expect_finding("py wrapper: the same wrapper does not clear command injection", "w/b2.py",
                   "import html, os\n"
                   "def clean(s):\n"
                   "    return html.escape(s)\n"
                   "os.system('ping ' + clean(request.args['host']))\n",
                   VulnClass::CommandInjection, 4);

    expect_none("py wrapper: shlex.quote wrapper clears command injection", "w/b3.py",
                "import os, shlex\n"
                "def arg(s):\n"
                "    return shlex.quote(s)\n"
                "os.system('ping ' + arg(request.args['host']))\n");

    expect_none("py wrapper: lambda sanitizer", "w/b4.py",
                "import html\n"
                "from markupsafe import Markup\n"
                "clean = lambda s: html.escape(s)\n"
                "Markup(clean(request.args['name']))\n");

    expect_finding("py wrapper: lambda conduit keeps taint", "w/b5.py",
                   "cursor = conn.cursor()\n"
                   "where = lambda v: 'SELECT * FROM u WHERE id = ' + v\n"
                   "cursor.execute(where(request.args['id']))\n",
                   VulnClass::SqlInjection, 3);

    expect_none("py wrapper: int() wrapper clears every class", "w/b6.py",
                "cursor = conn.cursor()\n"
                "def to_id(value):\n"
                "    return int(value)\n"
                "cursor.execute('SELECT * FROM u WHERE id = ' + str(to_id(request.args['id'])))\n");

    // ---- Go ------------------------------------------------------------------
    expect_none("go wrapper: html.EscapeString wrapper clears XSS", "w/c1.go",
                "package main\n"
                "func clean(s string) string {\n"
                "  return html.EscapeString(s)\n"
                "}\n"
                "func h(w http.ResponseWriter, r *http.Request) {\n"
                "  fmt.Fprintf(w, \"<p>%s</p>\", clean(r.FormValue(\"q\")))\n"
                "}\n");

    expect_finding("go wrapper: the same wrapper does not clear SQL injection", "w/c2.go",
                   "package main\n"
                   "func clean(s string) string {\n"
                   "  return html.EscapeString(s)\n"
                   "}\n"
                   "func h(w http.ResponseWriter, r *http.Request) {\n"
                   "  db.Query(\"SELECT * FROM u WHERE n = '\" + clean(r.FormValue(\"n\")) + \"'\")\n"
                   "}\n",
                   VulnClass::SqlInjection, 6);

    expect_none("go wrapper: filepath.Base wrapper clears path traversal", "w/c3.go",
                "package main\n"
                "func leaf(p string) string {\n"
                "  return filepath.Base(p)\n"
                "}\n"
                "func h(w http.ResponseWriter, r *http.Request) {\n"
                "  os.Open(\"/srv/data/\" + leaf(r.FormValue(\"f\")))\n"
                "}\n");

    expect_none("go wrapper: strconv.Atoi wrapper clears every class", "w/c4.go",
                "package main\n"
                "func toID(s string) int {\n"
                "  id, _ := strconv.Atoi(s)\n"
                "  return id\n"
                "}\n"
                "func h(w http.ResponseWriter, r *http.Request) {\n"
                "  db.Query(fmt.Sprintf(\"SELECT * FROM u WHERE id = %d\", toID(r.FormValue(\"id\"))))\n"
                "}\n");
}

// The mask is a compile-time value type, so its algebra is checked by the
// compiler: if one of these stops holding, the test binary does not build.
constexpr SanitizerMask mask_of_classes(std::initializer_list<VulnClass> classes) {
    SanitizerMask mask;
    for (const VulnClass id : classes) mask.add(id);
    return mask;
}
static_assert(SanitizerMask{}.empty());
static_assert(mask_of_classes({VulnClass::CrossSiteScripting}).covers(VulnClass::CrossSiteScripting));
static_assert(!mask_of_classes({VulnClass::CrossSiteScripting}).covers(VulnClass::SqlInjection));
static_assert(mask_of_classes({VulnClass::CrossSiteScripting})
                  .merged_with(mask_of_classes({VulnClass::SqlInjection}))
                  .empty(),
              "joining two flows keeps only what both were cleaned for");
static_assert(mask_of_classes({VulnClass::SqlInjection}).raw() ==
              std::uint32_t{1} << std::to_underlying(VulnClass::SqlInjection));

// Queue messages are untrusted input. parse_job is the boundary where a
// malformed one becomes an error value instead of an exception thrown from
// somewhere inside the scan loop.
void job_suite() {
    harness::section("Scan job parsing (std::expected)");

    {
        const auto job = parse_job(
            R"({"job_id":"abc123","repository":"acme/web","commit":"deadbeef",)"
            R"("files":[{"path":"src/a.js","content":"eval(req.query.x);\n"},)"
            R"({"path":"src/b.py","content":"x = 1\n"}]})");
        harness::check(job.has_value(), "job: a well-formed job parses",
                       job ? "" : job.error());
        if (job) {
            harness::check(job->job_id == "abc123" && job->repository == "acme/web" &&
                               job->commit == "deadbeef",
                           "job: carries id, repository and commit");
            harness::check(job->files.size() == 2 && job->files[0].path == "src/a.js" &&
                               job->files[1].content == "x = 1\n",
                           "job: carries every file in order");

            // The parsed job feeds the engine unchanged.
            const auto report = scan_detailed(job->repository, job->files[0]);
            harness::check(report.findings.size() == 1 &&
                               report.findings[0].vulnerability == VulnClass::RemoteCodeExecution,
                           "job: a parsed file analyses like any other",
                           describe(report.findings));
        }
    }

    {
        const auto job = parse_job(R"({"files":[]})");
        harness::check(job.has_value() && job->files.empty() && job->job_id == "-" &&
                           job->repository == "unknown/repo",
                       "job: missing fields take defaults and an empty job is valid");
    }

    {
        const auto job = parse_job(R"({"job_id":"x"})");
        harness::check(job.has_value() && job->files.empty(),
                       "job: an absent files array is an empty job");
    }

    const auto expect_error = [](std::string_view label, std::string_view body,
                                 std::string_view needle) {
        const auto job = parse_job(body);
        const bool ok = !job.has_value() && job.error().contains(needle);
        harness::check(ok, label,
                       ok ? ""
                          : std::format("expected an error mentioning '{}', got: {}", needle,
                                        job ? "a parsed job" : job.error()));
    };

    expect_error("job: truncated JSON is an error, not an exception",
                 R"({"job_id": "x", "files": [)", "not valid JSON");
    expect_error("job: an empty body is an error", "", "not valid JSON");
    expect_error("job: a top-level array is rejected", R"([{"path":"a.js"}])",
                 "must be a JSON object");
    expect_error("job: files as a string is rejected", R"({"files":"src/a.js"})",
                 "'files' must be an array");
    expect_error("job: a non-object file entry names its index",
                 R"({"files":[{"path":"a.js","content":""},"b.js"]})", "files[1]");
    expect_error("job: non-string content names the field",
                 R"({"files":[{"path":"a.js","content":42}]})", "'content' must be a string");
    expect_error("job: a numeric job_id is rejected", R"({"job_id":7,"files":[]})",
                 "'job_id' must be a string");
}

// The result document is a contract with the gateway, which stores it, and
// with the benchmark, which counts from it. These pin the parts both rely on.
void scan_result_suite() {
    harness::section("Scan result serialisation");

    ScanResult result;
    result.job_id = "job-42";
    result.repository = "acme/web";
    result.commit = "deadbeef";

    const auto report = scan_detailed(
        "acme/web", {"src/app.js", "const db = mysql.createConnection({});\n"
                                   "const id = req.query.id;\n"
                                   "db.query('SELECT * FROM u WHERE id = ' + id);\n"
                                   "eval(req.body.code);\n"
                                   "fetch(req.query.url);\n"});
    result.absorb(report);
    result.absorb(scan_detailed("acme/web", {"docs/notes.md", "not source"}));
    harness::check(report.findings.size() == 3, "result: fixture yields three findings",
                   describe(report.findings));
    if (report.findings.size() != 3) return;

    result.findings.push_back({report.findings[0], Verdict::Escalated, 0.31, "nothing similar"});
    result.findings.push_back({report.findings[1], Verdict::Suppressed, 0.93, "seen before"});
    result.findings.push_back({report.findings[2], Verdict::Untriaged, 0.0, "triage disabled"});

    harness::check(result.count(Verdict::Escalated) == 1 && result.count(Verdict::Suppressed) == 1 &&
                       result.count(Verdict::Untriaged) == 1,
                   "result: counts findings by verdict");

    const std::string compact = to_json(result);
    harness::check(!compact.contains('\n'), "result: the queue form is a single line");

    // Round-trip through the job parser's sibling: the text must be JSON the
    // other side can read, with the fields it reads.
    const auto has = [&](std::string_view needle) { return compact.contains(needle); };
    harness::check(has(R"("job_id":"job-42")") && has(R"("repository":"acme/web")") &&
                       has(R"("commit":"deadbeef")"),
                   "result: identifies the job it belongs to");
    harness::check(has(R"("status":"COMPLETED")"), "result: a normal scan is COMPLETED");
    harness::check(has(std::format(R"("worker_version":"{}")", kVersion)),
                   "result: carries the worker version");
    harness::check(has(R"("files_scanned":1)") && has(R"("findings":3)") &&
                       has(R"("escalated":1)") && has(R"("suppressed":1)") &&
                       has(R"("untriaged":1)"),
                   "result: summary totals match the findings");
    harness::check(has(R"("verdict":"ESCALATED")") && has(R"("verdict":"SUPPRESSED")") &&
                       has(R"("verdict":"UNTRIAGED")"),
                   "result: every finding carries its verdict");
    harness::check(has(R"("triage_reason":"seen before")") && has(R"("triage_confidence":0.93)"),
                   "result: carries the triage explanation and similarity");
    harness::check(has(R"("class":"sql-injection")") && has(R"("cwe":"CWE-89")") &&
                       has(R"("file":"src/app.js")"),
                   "result: findings carry class, CWE and location");
    harness::check(has(R"("trace":[{)") && has("flows into 'id'"),
                   "result: the taint trace is included");
    harness::check(result.files.size() == 1 && has(R"("path":"src/app.js")") &&
                       has(R"("language":"javascript")") && has(R"("had_parse_errors":false)"),
                   "result: lists each supported file with its language and parse state");
    harness::check(has(R"("files_skipped":1)") && !has("docs/notes.md"),
                   "result: an unsupported file is counted as skipped, not listed");

    {
        ScanResult failed;
        failed.job_id = "job-43";
        failed.failed = true;
        failed.error = "boom";
        const std::string text = to_json(failed);
        harness::check(text.contains(R"("status":"FAILED")") && text.contains(R"("error":"boom")") &&
                           text.contains(R"("findings":[])"),
                       "result: a failed job reports FAILED with its error and no findings");
    }

    {
        // A snippet that is not valid UTF-8 must not lose the whole result.
        ScanResult binary = result;
        binary.findings[0].finding.snippet = std::string("caf\xe9 \xff\xfe");
        std::string text;
        bool threw = false;
        try {
            text = to_json(binary);
        } catch (const std::exception&) {
            threw = true;
        }
        harness::check(!threw && text.contains(R"("job_id":"job-42")"),
                       "result: invalid UTF-8 in a snippet does not abort serialisation");
    }

    harness::check(to_json(result, 2).contains("\n  \"job_id\""),
                   "result: an indented form is available for reports");
}

}  // namespace

int main() {
    std::cout << harness::bold() << "\nSentinel SAST — analysis engine test suite"
              << harness::reset() << "\n";
    std::cout << harness::dim()
              << "no broker, no database, no network required" << harness::reset() << "\n";

    regression_suite();
    interprocedural_suite();
    sanitizer_suite();
    scoping_suite();
    type_inference_suite();
    vulnerability_class_suite();
    weak_crypto_suite();
    secret_suite();
    suppression_suite();
    trace_and_scoring_suite();
    robustness_suite();
    sarif_suite();
    unit_suite();
    scan_summary_suite();
    job_suite();
    class_matrix_suite();
    go_receiver_precision_suite();
    sanitizer_wrapper_suite();
    benchmark_regression_suite();
    transitive_interprocedural_suite();
    summary_fixpoint_suite();
    known_limit_suite();
    scan_result_suite();

    // Rule-table coverage matrices.
    js_source_coverage_suite();
    py_source_coverage_suite();
    go_source_coverage_suite();
    sink_coverage_suite();
    sanitizer_matrix_suite();
    propagation_shape_suite();
    secret_format_suite();
    config_rule_suite();
    true_negative_suite();

    return harness::report("Sentinel analysis engine", scan_count());
}

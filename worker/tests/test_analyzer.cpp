// Behavioural tests for the Sentinel analysis engine.
//
//   make test
//
// Needs no broker, no database and no network -- the analysis core has no I/O
// dependencies, which is the property that makes this suite runnable anywhere.

#include <algorithm>
#include <format>
#include <string>
#include <vector>

#include "../src/analyzer.hpp"
#include "../src/sarif.hpp"
#include "../src/secrets.hpp"
#include "../src/suppress.hpp"
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

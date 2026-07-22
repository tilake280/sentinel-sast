// Tests for the Tree-sitter based taint engine.
//   make test

#include <iostream>
#include <string>
#include <vector>

#include "../src/analyzer.hpp"

namespace {

int failures = 0;

void expect_finding(const std::string& label, const std::string& path, const std::string& code,
                    const std::string& expected_type, int expected_line) {
    const auto findings = sentinel::analyze_file("test/repo", {path, code});
    bool matched = false;
    for (const auto& f : findings) {
        if (f.vulnerability_type == expected_type && f.line == expected_line) matched = true;
    }
    if (matched) {
        std::cout << "[PASS] " << label << "\n";
    } else {
        ++failures;
        std::cout << "[FAIL] " << label << " -- expected " << expected_type << " on line "
                  << expected_line << ", got " << findings.size() << " finding(s):\n";
        for (const auto& f : findings) {
            std::cout << "         " << f.vulnerability_type << " @" << f.line << ": " << f.snippet
                      << "\n";
        }
    }
}

void expect_no_finding(const std::string& label, const std::string& path, const std::string& code) {
    const auto findings = sentinel::analyze_file("test/repo", {path, code});
    if (findings.empty()) {
        std::cout << "[PASS] " << label << "\n";
    } else {
        ++failures;
        std::cout << "[FAIL] " << label << " -- expected none, got:\n";
        for (const auto& f : findings) {
            std::cout << "         " << f.vulnerability_type << " @" << f.line << ": " << f.snippet
                      << "\n";
        }
    }
}

}  // namespace

int main() {
    // ---- JavaScript ----
    expect_finding("js: direct source into SQL sink", "a.js",
                   "db.query('SELECT * FROM u WHERE id = ' + req.query.id);", "SQL Injection", 1);

    expect_finding("js: taint through a variable", "a.js",
                   "const term = req.query.term;\n"
                   "db.query('SELECT * FROM p WHERE n = ' + term);\n",
                   "SQL Injection", 2);

    expect_finding("js: taint two hops", "a.js",
                   "const a = req.query.x;\n"
                   "const b = a;\n"
                   "el.innerHTML = b;\n",
                   "Cross-Site Scripting", 3);

    expect_finding("js: eval is RCE", "a.js", "eval(req.body.expression);",
                   "Remote Code Execution", 1);

    // Order-independence: only a fixpoint gets this right, not a single pass.
    expect_finding("js: taint defined after use site", "a.js",
                   "function render() { el.innerHTML = value; }\n"
                   "const value = req.query.html;\n",
                   "Cross-Site Scripting", 1);

    expect_no_finding("js: untainted constant query", "a.js",
                      "db.query('SELECT * FROM products WHERE active = true');");

    expect_no_finding("js: source with no sink", "a.js", "const term = req.query.term;");

    // The AST cannot see into comments or string literals -- these were the
    // cases a line-based regex scanner got wrong.
    expect_no_finding("js: commented-out vulnerability", "a.js",
                      "// db.query('SELECT * FROM u WHERE id = ' + req.query.id);");

    expect_no_finding("js: vulnerability inside a string literal", "a.js",
                      "const doc = \"call db.query('x' + req.query.id) to break things\";");

    // ---- Python ----
    expect_finding("py: os.system command injection", "b.py",
                   "host = request.args.get('host')\n"
                   "os.system('ping -c 1 ' + host)\n",
                   "Command Injection", 2);

    expect_finding("py: path traversal via open()", "b.py",
                   "path = request.args.get('path')\n"
                   "return open(path).read()\n",
                   "Path Traversal", 2);

    expect_finding("py: cursor.execute SQL injection", "b.py",
                   "kind = request.args.get('kind')\n"
                   "cursor.execute('SELECT * FROM events WHERE kind = ' + kind)\n",
                   "SQL Injection", 2);

    expect_no_finding("py: docstring mentioning os.system", "b.py",
                      "def f():\n"
                      "    '''do not call os.system(request.args.get(\"h\")) here'''\n"
                      "    return 1\n");

    // ---- Go ----
    expect_finding("go: SQL injection via URL query", "c.go",
                   "package main\n"
                   "func handler(w http.ResponseWriter, r *http.Request) {\n"
                   "  id := r.URL.Query().Get(\"id\")\n"
                   "  db.Query(\"SELECT * FROM users WHERE id = \" + id)\n"
                   "}\n",
                   "SQL Injection", 4);

    expect_finding("go: command injection via FormValue", "c.go",
                   "package main\n"
                   "func handler(w http.ResponseWriter, r *http.Request) {\n"
                   "  host := r.FormValue(\"host\")\n"
                   "  exec.Command(\"ping\", host)\n"
                   "}\n",
                   "Command Injection", 4);

    // r.URL.Query() ends in Query() but is a source, not a database sink.
    expect_no_finding("go: URL.Query source not mistaken for SQL sink", "c.go",
                      "package main\n"
                      "func handler(w http.ResponseWriter, r *http.Request) {\n"
                      "  id := r.URL.Query().Get(\"id\")\n"
                      "  _ = id\n"
                      "}\n");

    expect_no_finding("go: constant query", "c.go",
                      "package main\n"
                      "func f() { db.Query(\"SELECT 1\") }\n");

    // ---- Unsupported ----
    expect_no_finding("unsupported extension is skipped", "notes.txt",
                      "db.query('SELECT * FROM u WHERE id = ' + req.query.id);");

    std::cout << "\n";
    if (failures) {
        std::cout << failures << " FAILURE(S)\n";
        return 1;
    }
    std::cout << "all analyzer tests passed\n";
    return 0;
}

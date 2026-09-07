// The analysis engine.
//
// Pipeline for one file:
//
//   1. Parse with the language's Tree-sitter grammar          (ast.cpp)
//   2. Collect inline suppression directives                  (suppress.cpp)
//   3. Infer receiver types from imports and constructors     (types.cpp)
//   4. Extract every function definition                      (interproc.cpp)
//   5. Compute function summaries to a fixpoint               (interproc.cpp + here)
//   6. Per-function taint propagation to a fixpoint           (here)
//   7. Match sinks, applying type guards and sanitizers       (here)
//   8. Scan for hardcoded secrets and weak crypto             (secrets.cpp, here)
//   9. Score severity and confidence                          (severity.cpp)
//  10. Drop suppressed findings, report stale suppressions    (suppress.cpp)
//
// Every stage is data-driven from languages.cpp, so the engine itself does not
// know what JavaScript is.

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "languages.hpp"
#include "severity.hpp"
#include "suppress.hpp"
#include "taint.hpp"
#include "types.hpp"
#include "vulnerability.hpp"

namespace sentinel {

struct SourceFile {
    std::string path;
    std::string content;
};

struct Finding {
    std::string repository;
    std::string file;
    std::string vulnerability_type;   // human name; kept for the triage payload
    VulnClass vulnerability = VulnClass::Unknown;
    std::string snippet;
    int line = 0;
    int column = 0;

    Severity severity = Severity::Info;
    Confidence confidence = Confidence::Low;
    std::string cwe;
    std::string owasp;
    std::string rule_id;              // "sentinel.javascript.sql-injection"
    std::string message;
    std::string remediation;

    // The source -> sink path. Empty for findings that need no dataflow, such
    // as a hardcoded secret or a weak cipher.
    std::vector<TaintStep> trace;
    std::string taint_source;         // the originating expression

    // Why it scored the way it did.
    std::vector<std::string> scoring_factors;

    bool crosses_function_boundary = false;
    std::string function_name;        // the enclosing function, when known

    int priority() const;

    // One-line summary used by the worker log.
    std::string headline() const;
};

// Everything one file's analysis produced, including the diagnostics a
// production scanner needs to explain itself.
struct FileReport {
    std::string path;
    Language language = Language::Unknown;
    std::vector<Finding> findings;

    bool parsed = false;
    bool had_parse_errors = false;
    bool language_supported = false;

    std::size_t functions_analyzed = 0;
    std::size_t summaries_computed = 0;
    std::size_t suppressed_count = 0;
    std::vector<Suppression> stale_suppressions;
    std::vector<Suppression> undocumented_suppressions;

    // Wall time in milliseconds, so a slow file can be identified in the log.
    double analysis_ms = 0.0;
};

// Analyses one file. Never throws; an unsupported extension or a parse failure
// produces an empty report with the relevant flag set.
FileReport analyze_file_detailed(const std::string& repository, const SourceFile& file);

// Convenience wrapper preserving the original signature.
std::vector<Finding> analyze_file(const std::string& repository, const SourceFile& file);

// Aggregate across a whole scan job.
struct ScanSummary {
    std::size_t files_scanned = 0;
    std::size_t files_skipped = 0;
    std::size_t files_with_parse_errors = 0;
    std::size_t total_findings = 0;
    std::size_t suppressed_inline = 0;
    std::size_t functions_analyzed = 0;
    double total_ms = 0.0;

    std::size_t by_severity[5] = {};
    std::size_t by_confidence[3] = {};

    void absorb(const FileReport& report);
};

// Orders findings for presentation: severity, then confidence, then file/line.
void sort_findings(std::vector<Finding>& findings);

}  // namespace sentinel

// SARIF 2.1.0 report generation.
//
// SARIF is the OASIS standard that GitHub code scanning, Azure DevOps, VS Code
// and most review tooling consume. Emitting it is what makes this engine usable
// in a real pipeline rather than only through its own log: a CI job uploads the
// file and findings appear as inline annotations on the pull request.
//
// The mapping that matters:
//
//   run.tool.driver.rules[]     one entry per VulnClass actually reported,
//                               carrying CWE and remediation text
//   result.ruleId               "sentinel.javascript.sql-injection"
//   result.level                error / warning / note, from severity
//   result.locations[]          the sink
//   result.codeFlows[]          the taint trace, which is what renders as the
//                               clickable source -> sink path in a UI
//
// Written by hand rather than through the JSON library because this file is
// also linked into the test binary, which deliberately has no third-party
// dependencies -- the engine's only link-time requirement stays Tree-sitter.

#pragma once

#include <string>
#include <vector>

#include "analyzer.hpp"
#include "version.hpp"

namespace sentinel {

struct SarifOptions {
    std::string tool_name = "Sentinel SAST";
    std::string tool_version = std::string(kVersion);
    std::string information_uri = "https://github.com/sentinel-sast";
    std::string repository;
    std::string commit;
    bool pretty = true;
};

// Serialises findings as a SARIF 2.1.0 document.
std::string to_sarif(const std::vector<Finding>& findings, const SarifOptions& options = {});

// Escapes a string for embedding in JSON. Exposed for tests, since getting this
// wrong silently corrupts every report containing a quote or a backslash --
// which, in a tool that reports source code, is most of them.
std::string json_escape(std::string_view value);

// A compact human-readable table, for the worker log and CI output.
std::string to_text_report(const std::vector<Finding>& findings, bool use_color = false);

// A one-line-per-finding format for grep and diffing between runs.
std::string to_line_report(const std::vector<Finding>& findings);

}  // namespace sentinel

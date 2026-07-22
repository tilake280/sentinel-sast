// AST-based taint analysis engine.
//
// Each file is parsed with Tree-sitter (JavaScript, Python and Go grammars are
// vendored under third_party/). The analyzer extracts assignments and calls from
// the concrete syntax tree, propagates taint from attacker-controlled sources to
// a fixpoint, and reports flows that reach a dangerous sink.
//
// Taint rules are expressed as C++ over the AST rather than in Datalog; the
// per-language source/sink configuration lives in languages.cpp. Analysis is
// intraprocedural -- taint is not tracked across function boundaries.

#pragma once

#include <string>
#include <vector>

namespace sentinel {

struct Finding {
    std::string repository;
    std::string file;
    std::string vulnerability_type;
    std::string snippet;
    int line = 0;
};

struct SourceFile {
    std::string path;
    std::string content;
};

// Runs the taint trace over one file and returns every source->sink flow found.
std::vector<Finding> analyze_file(const std::string& repository, const SourceFile& file);

}  // namespace sentinel

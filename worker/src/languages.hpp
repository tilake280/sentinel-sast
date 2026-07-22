// Per-language Tree-sitter grammar bindings and taint configuration.
//
// The analyzer itself is language-agnostic: it works in terms of "assignments",
// "calls" and "property writes". Everything language-specific -- which AST node
// types express those, which expressions are attacker-controlled, and which
// callees are dangerous -- lives here.

#pragma once

#include <string>
#include <vector>

#include <tree_sitter/api.h>

namespace sentinel {

enum class Language { Unknown, JavaScript, Python, Go };

struct SinkRule {
    std::string callee;              // matched against the full callee or its last segment
    std::string vulnerability_type;
};

struct LanguageSpec {
    Language id = Language::Unknown;
    const char* name = "unknown";
    const TSLanguage* grammar = nullptr;

    // AST node types that bind a value to a name, with the fields to read.
    struct AssignmentForm {
        std::string node_type;
        std::string lhs_field;
        std::string rhs_field;
    };
    std::vector<AssignmentForm> assignment_forms;

    std::string call_node_type;      // e.g. "call_expression" / "call"
    std::string call_function_field; // e.g. "function"
    std::string call_arguments_field;

    // Node type for `a.b` used to detect property-write sinks (JS innerHTML).
    std::string member_node_type;
    std::string member_property_field;

    // Substrings identifying attacker-controlled expressions.
    std::vector<std::string> source_patterns;

    std::vector<SinkRule> call_sinks;
    std::vector<SinkRule> property_sinks;
};

// Picks a language from a file path extension.
Language language_for_path(const std::string& path);

// Returns nullptr for Language::Unknown.
const LanguageSpec* spec_for(Language language);

}  // namespace sentinel

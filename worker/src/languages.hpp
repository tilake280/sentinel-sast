// Per-language grammar bindings and rule tables.
//
// The engine in analyzer.cpp is language-agnostic: it reasons about
// "assignments", "calls", "returns" and "property writes". Everything
// language-specific lives here as data -- which AST node types express those
// concepts, which expressions are attacker-controlled, which callees are
// dangerous, and which ones clean a value up.
//
// Adding a language means adding one make_*() function below and vendoring its
// grammar. Adding a rule means adding a row. Neither touches the engine.

#pragma once

#include <string>
#include <vector>

#include <tree_sitter/api.h>

#include "sanitizers.hpp"
#include "types.hpp"
#include "vulnerability.hpp"

namespace sentinel {

enum class Language { Unknown, JavaScript, Python, Go };

std::string_view to_string(Language language) noexcept;

// An expression shape that introduces attacker-controlled data.
struct SourceRule {
    std::string pattern;       // substring match against the expression text
    std::string description;   // "HTTP query parameter", shown in the taint trace

    // Some sources are only dangerous for certain classes. A filename from a
    // multipart upload is a path-traversal source but not a SQL one.
    std::vector<VulnClass> classes;  // empty means all classes
};

// A dangerous callee.
struct SinkRule {
    std::string callee;
    VulnClass vulnerability = VulnClass::Unknown;

    // When set, the rule only fires if the receiver resolved to this type. This
    // is what stops `/re/.exec(x)` being reported as command injection.
    ReceiverType required_receiver = ReceiverType::Unknown;

    // When set, the rule is skipped if the receiver resolved to this type --
    // the inverse guard, for sinks that are dangerous by default but safe on a
    // known-harmless receiver.
    ReceiverType excluded_receiver = ReceiverType::Unknown;

    // Only this argument index matters. -1 means any argument. Used where the
    // first argument is a constant format string and only later ones are data.
    int tainted_argument = -1;

    // Require the full dotted path to match rather than the last segment.
    bool require_full_path = false;

    std::string note;  // appended to the finding message
};

// A property write that is a sink: `el.innerHTML = tainted`.
struct PropertySinkRule {
    std::string property;
    VulnClass vulnerability = VulnClass::Unknown;
    ReceiverType required_receiver = ReceiverType::Unknown;
    std::string note;
};

// A call that is dangerous regardless of taint -- weak crypto, disabled TLS
// verification. No dataflow needed; the call itself is the finding.
struct ConfigurationRule {
    std::string pattern;
    VulnClass vulnerability = VulnClass::Unknown;
    Severity severity = Severity::Medium;
    std::string message;
};

struct LanguageSpec {
    Language id = Language::Unknown;
    std::string name = "unknown";
    const TSLanguage* grammar = nullptr;

    // ---- Structural node types -------------------------------------------

    struct AssignmentForm {
        std::string node_type;
        std::string lhs_field;
        std::string rhs_field;
    };
    std::vector<AssignmentForm> assignment_forms;

    // Flattened list of the node types above, for passes that only need to know
    // "is this an assignment".
    std::vector<std::string> assignment_node_types() const;

    std::string call_node_type;
    std::string call_function_field;
    std::string call_arguments_field;

    // Constructions that behave like calls but are a different node type with
    // different field names -- JavaScript's `new Function(src)` is a
    // new_expression, so a spec that only knew call_expression missed it
    // entirely despite Function being in the sink table.
    struct CallForm {
        std::string node_type;
        std::string function_field;
        std::string arguments_field;
    };
    std::vector<CallForm> additional_call_forms;

    std::string member_node_type;
    std::string member_property_field;

    std::vector<std::string> function_definition_node_types;
    std::string function_name_field = "name";
    std::string function_parameters_field = "parameters";
    std::string function_body_field = "body";

    std::vector<std::string> return_node_types;
    std::vector<std::string> comment_node_types;
    std::vector<std::string> import_node_types;
    std::vector<std::string> pair_node_types;        // object literal / dict entries
    std::vector<std::string> concatenation_node_types;
    std::vector<std::string> conditional_node_types;
    std::vector<std::string> subscript_node_types;

    // ---- Rule tables ------------------------------------------------------

    std::vector<SourceRule> sources;
    std::vector<SinkRule> call_sinks;
    std::vector<PropertySinkRule> property_sinks;
    std::vector<ConfigurationRule> configuration_rules;
    std::vector<TypeRule> type_rules;

    SanitizerTable sanitizers;
    ValidatorTable validators;

    // ---- Helpers ----------------------------------------------------------

    // The source rule matching an expression, if any.
    const SourceRule* match_source(std::string_view expression) const;

    // True when the expression matches a source relevant to `id`.
    bool is_source_for(std::string_view expression, VulnClass id) const;
};

Language language_for_path(std::string_view path);
const LanguageSpec* spec_for(Language language);

// Every configured language, for diagnostics and the rule-count banner.
std::vector<Language> supported_languages();

// Total rule count across all languages, printed at startup so a deployment can
// confirm it is running the ruleset it expects.
std::size_t total_rule_count();

}  // namespace sentinel

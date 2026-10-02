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

    // The value comes from whoever runs the program -- argv, the environment,
    // stdin -- rather than from a remote request. It is still untrusted input
    // to a setuid binary or a CI job, so it stays a source, but a build script
    // shelling out with its own environment is not the finding a handler
    // shelling out with a query parameter is. Lowers confidence, nothing else.
    bool local = false;
};

// True when `pattern` occurs in `expression` as whole name segments. A plain
// substring test matched `r.Form` inside `r.Format` and `req.file` inside
// `req.filename`: the pattern has to end, and begin, where an identifier does.
bool source_pattern_matches(std::string_view expression, std::string_view pattern) noexcept;

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

    // The type guards above are lenient by default: a receiver the inference
    // could not resolve still fires the rule, at lower confidence. That is the
    // wrong trade for a callee whose name is only dangerous on one kind of
    // object -- `Parse`, `Run`, `Write`. When set, the rule fires only if the
    // guarded type actually resolved to `required_receiver`.
    bool strict_receiver = false;

    // When >= 0, the guards apply to this argument instead of the callee's
    // receiver. `fmt.Fprintf(w, ...)` writes HTML only when `w` is an
    // http.ResponseWriter, and `w` is an argument there, not the receiver.
    int typed_argument = -1;

    // When set, the rule does not fire if the checked argument is an object
    // literal with this key. `Model.find({ where: {...} })` is an ORM query
    // whose values are bound by the ORM; a document-database filter has no
    // top-level `where`. The two share a method name and nothing else.
    std::string skip_if_argument_has_key = {};
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

    // The call is only a finding where its result is used for something that
    // needs to be unpredictable. Math.random() picking a tooltip id or a demo
    // date is not a weakness; Math.random() producing a session token is.
    // When set, the rule fires only if the enclosing statement or function
    // names something security-relevant.
    bool needs_security_context = false;
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

    // What a function body looks like when it is a block of statements. A body
    // of any other type is an expression, and the function returns it:
    // `(v) => v + 1`, `lambda v: v + 1`.
    std::vector<std::string> block_node_types;
    std::vector<std::string> comment_node_types;
    std::vector<std::string> import_node_types;
    std::vector<std::string> pair_node_types;        // object literal / dict entries
    std::vector<std::string> concatenation_node_types;
    std::vector<std::string> conditional_node_types;
    std::vector<std::string> subscript_node_types;

    // Parameter declarations that spell out a type, for languages that have
    // them. Feeds receiver-type inference.
    std::vector<TypedParameterForm> typed_parameter_forms;

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

// How one class is detected in one language, read straight off the rule
// tables. This is what `--rules` prints, so a coverage claim can be checked
// against the binary instead of against prose.
struct ClassCoverage {
    VulnClass id = VulnClass::Unknown;
    bool by_taint = false;    // a source reaching a call or property sink
    bool by_pattern = false;  // a configuration or literal pattern, no dataflow

    bool detected() const noexcept { return by_taint || by_pattern; }
};

// One entry per class in registry order, whether or not it is detected.
std::vector<ClassCoverage> class_coverage(const LanguageSpec& spec);

}  // namespace sentinel

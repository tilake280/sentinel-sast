#include "types.hpp"

#include <algorithm>

namespace sentinel {
namespace {

// Longer patterns are more specific, so they win. Without this ordering,
// "exec" would match before "child_process.exec" and mistype the receiver.
const TypeRule* best_match(std::string_view expression, const std::vector<TypeRule>& rules) {
    const TypeRule* best = nullptr;
    for (const auto& rule : rules) {
        if (rule.pattern.empty()) continue;
        if (!ast::contains(expression, rule.pattern)) continue;
        if (best == nullptr || rule.pattern.size() > best->pattern.size()) {
            best = &rule;
        }
    }
    return best;
}

}  // namespace

std::string_view to_string(ReceiverType type) noexcept {
    switch (type) {
        case ReceiverType::Unknown: return "unknown";
        case ReceiverType::Database: return "database";
        case ReceiverType::PreparedStatement: return "prepared-statement";
        case ReceiverType::DomElement: return "dom-element";
        case ReceiverType::ChildProcess: return "child-process";
        case ReceiverType::FileSystem: return "filesystem";
        case ReceiverType::HttpClient: return "http-client";
        case ReceiverType::HttpResponse: return "http-response";
        case ReceiverType::Logger: return "logger";
        case ReceiverType::Regex: return "regex";
        case ReceiverType::Template: return "template";
        case ReceiverType::ScriptEngine: return "script-engine";
        case ReceiverType::Crypto: return "crypto";
        case ReceiverType::Serializer: return "serializer";
        case ReceiverType::DataCodec: return "data-codec";
        case ReceiverType::MongoCollection: return "mongo-collection";
    }
    return "unknown";
}

ReceiverType infer_from_expression(std::string_view expression,
                                   const std::vector<TypeRule>& rules) {
    const TypeRule* match = best_match(expression, rules);
    return match != nullptr ? match->type : ReceiverType::Unknown;
}

void TypeEnvironment::observe_binding(const std::string& name, std::string_view initializer_text,
                                      const std::vector<TypeRule>& rules) {
    if (name.empty()) return;

    const ReceiverType inferred = infer_from_expression(initializer_text, rules);
    if (inferred != ReceiverType::Unknown) {
        bindings_[name] = inferred;
        return;
    }

    // A regex literal has no call to pattern-match against, so recognise it by
    // shape: /.../ with flags, or a `new RegExp(...)` construction.
    const std::string_view trimmed = initializer_text;
    if (trimmed.size() >= 2 && trimmed.front() == '/') {
        bindings_[name] = ReceiverType::Regex;
        return;
    }
    if (ast::contains(trimmed, "RegExp(")) {
        bindings_[name] = ReceiverType::Regex;
        return;
    }

    // Propagate through simple aliasing: `const q = db;` keeps db's type.
    const auto alias = bindings_.find(std::string(ast::trim(trimmed)));
    if (alias != bindings_.end()) {
        bindings_[name] = alias->second;
    }
}

void TypeEnvironment::observe_import(const std::string& bound_name, std::string_view module_path,
                                     const std::vector<TypeRule>& rules) {
    if (bound_name.empty()) return;
    const ReceiverType inferred = infer_from_expression(module_path, rules);
    if (inferred != ReceiverType::Unknown) {
        bindings_[bound_name] = inferred;
    }
}

void TypeEnvironment::assign(const std::string& name, ReceiverType type) {
    if (!name.empty()) bindings_[name] = type;
}

ReceiverType TypeEnvironment::type_of(std::string_view name) const {
    const auto it = bindings_.find(name);
    return it == bindings_.end() ? ReceiverType::Unknown : it->second;
}

ReceiverType TypeEnvironment::receiver_type_of(std::string_view dotted_callee,
                                               const std::vector<TypeRule>& rules) const {
    const std::string_view receiver = ast::receiver_of(dotted_callee);
    if (receiver.empty()) return ReceiverType::Unknown;

    // A locally bound name is the most reliable signal.
    const ReceiverType bound = type_of(receiver);
    if (bound != ReceiverType::Unknown) return bound;

    // `child_process.exec` with no local binding: match the receiver, then the
    // whole path. The full path is tried second because a rule like
    // "child_process.exec" should beat a rule for "child_process" alone.
    const ReceiverType by_receiver = infer_from_expression(receiver, rules);
    const ReceiverType by_full = infer_from_expression(dotted_callee, rules);
    if (by_full != ReceiverType::Unknown) return by_full;
    return by_receiver;
}

TypeEnvironment build_type_environment(const ast::ParsedFile& file, TSNode root,
                                       const std::vector<TypeRule>& rules,
                                       const std::vector<std::string>& import_node_types,
                                       const std::vector<std::string>& assignment_node_types,
                                       const std::vector<TypedParameterForm>& typed_parameters) {
    TypeEnvironment env;
    const std::string& source = file.source();

    ast::walk(root, [&](TSNode node) {
        const std::string_view type = ast::node_type(node);

        // ---- Imports ------------------------------------------------------
        const bool is_import = std::ranges::contains(import_node_types, type);

        if (is_import) {
            const std::string text = ast::node_text(source, node);

            // Bind every identifier in the statement to the module it names.
            // Deliberately broad: `const { exec } = require('child_process')`
            // binds `exec`, and `import subprocess as sp` binds `sp`, without
            // needing a per-grammar special case for each import form.
            for (const auto& identifier : ast::identifiers_in(node, source)) {
                env.observe_import(identifier, text, rules);
            }
            return;
        }

        // ---- Typed parameters ---------------------------------------------
        for (const auto& form : typed_parameters) {
            if (type != form.node_type) continue;

            const TSNode declared = ast::child_by_field(node, form.type_field);
            if (ts_node_is_null(declared)) return;
            const std::string declared_type = ast::node_text(source, declared);

            // `func f(a, b *sql.DB)` declares two names with one type, and the
            // grammar repeats the `name` field once per name.
            const uint32_t count = ts_node_child_count(node);
            for (uint32_t i = 0; i < count; ++i) {
                const char* field = ts_node_field_name_for_child(node, i);
                if (field == nullptr || form.name_field != field) continue;
                env.observe_binding(ast::node_text(source, ts_node_child(node, i)),
                                    declared_type, rules);
            }
            return;
        }

        // ---- Assignments --------------------------------------------------
        const bool is_assignment = std::ranges::contains(assignment_node_types, type);

        if (!is_assignment) return;

        TSNode lhs = ast::child_by_field(node, "name");
        if (ts_node_is_null(lhs)) lhs = ast::child_by_field(node, "left");

        TSNode rhs = ast::child_by_field(node, "value");
        if (ts_node_is_null(rhs)) rhs = ast::child_by_field(node, "right");

        if (ts_node_is_null(lhs) || ts_node_is_null(rhs)) return;

        const std::string initializer = ast::node_text(source, rhs);

        // A regex literal is its own node type in the JS grammar.
        const bool rhs_is_regex = ast::node_type(rhs) == "regex";

        for (const auto& name : ast::identifiers_in(lhs, source)) {
            if (rhs_is_regex) {
                env.assign(name, ReceiverType::Regex);
            } else {
                env.observe_binding(name, initializer, rules);
            }
        }
    });

    return env;
}

}  // namespace sentinel

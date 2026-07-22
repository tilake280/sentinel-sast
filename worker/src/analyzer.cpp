#include "analyzer.hpp"

#include <cstring>
#include <functional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <tree_sitter/api.h>

#include "languages.hpp"

namespace sentinel {
namespace {

std::string node_text(const std::string& source, TSNode node) {
    const uint32_t start = ts_node_start_byte(node);
    const uint32_t end = ts_node_end_byte(node);
    if (end <= start || end > source.size()) return "";
    return source.substr(start, end - start);
}

std::string node_type(TSNode node) {
    const char* type = ts_node_type(node);
    return type ? std::string(type) : std::string();
}

TSNode field(TSNode node, const std::string& name) {
    return ts_node_child_by_field_name(node, name.c_str(),
                                       static_cast<uint32_t>(name.size()));
}

bool matches_source_pattern(const std::string& text, const LanguageSpec& spec) {
    for (const auto& pattern : spec.source_patterns) {
        if (text.find(pattern) != std::string::npos) return true;
    }
    return false;
}

// The segment after the final '.', so `db.query` matches the `query` sink rule.
std::string last_segment(const std::string& callee) {
    const auto pos = callee.find_last_of('.');
    return pos == std::string::npos ? callee : callee.substr(pos + 1);
}

void walk(TSNode node, const std::function<void(TSNode)>& visit) {
    visit(node);
    const uint32_t count = ts_node_named_child_count(node);
    for (uint32_t i = 0; i < count; ++i) {
        walk(ts_node_named_child(node, i), visit);
    }
}

void collect_identifiers(TSNode node, const std::string& source, std::set<std::string>& out) {
    walk(node, [&](TSNode current) {
        const std::string type = node_type(current);
        if (type == "identifier" || type == "field_identifier" ||
            type == "shorthand_property_identifier_pattern") {
            out.insert(node_text(source, current));
        }
    });
}

std::vector<std::string> split_lines(const std::string& source) {
    std::vector<std::string> lines;
    std::istringstream stream(source);
    std::string line;
    while (std::getline(stream, line)) lines.push_back(line);
    return lines;
}

std::string trim(const std::string& value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1);
}

struct Assignment {
    std::set<std::string> targets;  // identifiers bound on the left
    TSNode rhs;
    TSNode lhs;
};

}  // namespace

std::vector<Finding> analyze_file(const std::string& repository, const SourceFile& file) {
    std::vector<Finding> findings;

    const LanguageSpec* spec = spec_for(language_for_path(file.path));
    if (spec == nullptr || spec->grammar == nullptr) return findings;  // unsupported extension

    TSParser* parser = ts_parser_new();
    ts_parser_set_language(parser, spec->grammar);
    TSTree* tree = ts_parser_parse_string(parser, nullptr, file.content.c_str(),
                                          static_cast<uint32_t>(file.content.size()));
    if (tree == nullptr) {
        ts_parser_delete(parser);
        return findings;
    }

    const TSNode root = ts_tree_root_node(tree);
    const std::vector<std::string> lines = split_lines(file.content);

    // ---- Fact extraction -------------------------------------------------
    // Comments and string contents are simply not assignment or call nodes, so
    // unlike the previous regex pass they cannot produce findings.
    std::vector<Assignment> assignments;
    std::vector<TSNode> calls;

    walk(root, [&](TSNode node) {
        const std::string type = node_type(node);

        for (const auto& form : spec->assignment_forms) {
            if (type != form.node_type) continue;
            const TSNode lhs = field(node, form.lhs_field);
            const TSNode rhs = field(node, form.rhs_field);
            if (ts_node_is_null(lhs) || ts_node_is_null(rhs)) continue;

            Assignment assignment;
            assignment.lhs = lhs;
            assignment.rhs = rhs;
            collect_identifiers(lhs, file.content, assignment.targets);
            assignments.push_back(assignment);
        }

        if (type == spec->call_node_type) calls.push_back(node);
    });

    // ---- Taint propagation to fixpoint -----------------------------------
    // Iterating to a fixpoint (rather than a single top-to-bottom pass) means
    // taint flows correctly through chains regardless of statement order.
    std::set<std::string> tainted;

    const auto expression_is_tainted = [&](TSNode node) {
        if (matches_source_pattern(node_text(file.content, node), *spec)) return true;
        std::set<std::string> identifiers;
        collect_identifiers(node, file.content, identifiers);
        for (const auto& identifier : identifiers) {
            if (tainted.count(identifier) > 0) return true;
        }
        return false;
    };

    for (bool changed = true; changed;) {
        changed = false;
        for (const auto& assignment : assignments) {
            if (!expression_is_tainted(assignment.rhs)) continue;
            for (const auto& target : assignment.targets) {
                if (tainted.insert(target).second) changed = true;
            }
        }
    }

    // ---- Sink matching ---------------------------------------------------
    std::set<std::pair<int, std::string>> seen;  // dedupe by (line, type)

    const auto emit = [&](TSNode node, const std::string& vulnerability_type) {
        const int line = static_cast<int>(ts_node_start_point(node).row) + 1;
        if (!seen.insert({line, vulnerability_type}).second) return;

        const std::string snippet =
            (line >= 1 && static_cast<size_t>(line) <= lines.size())
                ? trim(lines[line - 1])
                : trim(node_text(file.content, node));

        findings.push_back(Finding{repository, file.path, vulnerability_type, snippet, line});
    };

    for (TSNode call : calls) {
        const TSNode function = field(call, spec->call_function_field);
        if (ts_node_is_null(function)) continue;

        const std::string callee = node_text(file.content, function);

        // A call that *is* a taint source (r.URL.Query()) must not be treated as
        // a sink just because its last segment collides with one.
        if (matches_source_pattern(callee, *spec)) continue;

        std::string vulnerability_type;
        const std::string segment = last_segment(callee);
        for (const auto& sink : spec->call_sinks) {
            if (segment == sink.callee || callee == sink.callee) {
                vulnerability_type = sink.vulnerability_type;
                break;
            }
        }
        if (vulnerability_type.empty()) continue;

        const TSNode arguments = field(call, spec->call_arguments_field);
        if (ts_node_is_null(arguments)) continue;
        if (!expression_is_tainted(arguments)) continue;

        emit(call, vulnerability_type);
    }

    // Property-write sinks, e.g. `el.innerHTML = tainted`.
    for (const auto& assignment : assignments) {
        if (spec->member_node_type.empty()) continue;
        if (node_type(assignment.lhs) != spec->member_node_type) continue;

        const TSNode property = field(assignment.lhs, spec->member_property_field);
        if (ts_node_is_null(property)) continue;

        const std::string name = node_text(file.content, property);
        for (const auto& sink : spec->property_sinks) {
            if (name != sink.callee) continue;
            if (expression_is_tainted(assignment.rhs)) {
                emit(assignment.lhs, sink.vulnerability_type);
            }
            break;
        }
    }

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    return findings;
}

}  // namespace sentinel

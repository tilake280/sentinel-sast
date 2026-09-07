#include "interproc.hpp"

#include <algorithm>
#include <format>
#include <utility>

#include "ast.hpp"

namespace sentinel {
namespace {

const std::set<std::string>& empty_string_set() {
    static const std::set<std::string> kEmpty;
    return kEmpty;
}

// Parameter nodes differ per grammar: JS has `identifier` and
// `required_parameter`, Python `identifier` / `default_parameter` /
// `typed_parameter`, Go `parameter_declaration` with a `name` field. Rather
// than a per-language table for something this small, take the first identifier
// of each named child, which is correct for all three.
std::vector<std::string> parameter_names(const std::string& source, TSNode parameters) {
    std::vector<std::string> names;
    if (ts_node_is_null(parameters)) return names;

    for (TSNode child : ast::named_children(parameters)) {
        const std::string_view type = ast::node_type(child);

        // Skip type annotations and comments that appear as siblings.
        if (type == "comment" || type == "type_identifier") continue;

        if (type == "identifier") {
            names.push_back(ast::node_text(source, child));
            continue;
        }

        // Go groups parameters: `func f(a, b string)` is one declaration with
        // two names, so take every identifier in the `name` field, then fall
        // back to the first identifier anywhere in the child.
        TSNode named_field = ast::child_by_field(child, "name");
        if (!ts_node_is_null(named_field)) {
            for (auto& identifier : ast::identifiers_in(named_field, source)) {
                names.push_back(std::move(identifier));
            }
            continue;
        }

        const auto identifiers = ast::identifiers_in(child, source);
        if (!identifiers.empty()) names.push_back(identifiers.front());
    }
    return names;
}

// Names an anonymous function by position so summaries stay addressable and
// two closures on different lines never collide.
std::string anonymous_name(int line) {
    return std::format("<anonymous:{}>", line);
}

}  // namespace

// ---- FunctionSummary ------------------------------------------------------

bool FunctionSummary::reaches_sink_from(std::size_t parameter_index) const {
    return std::any_of(parameter_sinks.begin(), parameter_sinks.end(),
                       [parameter_index](const ParamSink& sink) {
                           return sink.parameter_index == parameter_index;
                       });
}

std::vector<ParamSink> FunctionSummary::sinks_for(std::size_t parameter_index) const {
    std::vector<ParamSink> out;
    for (const auto& sink : parameter_sinks) {
        if (sink.parameter_index == parameter_index) out.push_back(sink);
    }
    return out;
}

bool FunctionSummary::equivalent_to(const FunctionSummary& other) const {
    if (returns_taint != other.returns_taint) return false;
    if (parameters_returned != other.parameters_returned) return false;
    if (sanitizes.raw() != other.sanitizes.raw()) return false;
    if (parameter_sinks.size() != other.parameter_sinks.size()) return false;

    // Sink order depends on AST traversal order, which is stable within a run,
    // so a positional comparison is sufficient and avoids a sort on every
    // fixpoint iteration.
    for (std::size_t i = 0; i < parameter_sinks.size(); ++i) {
        const ParamSink& a = parameter_sinks[i];
        const ParamSink& b = other.parameter_sinks[i];
        if (a.parameter_index != b.parameter_index) return false;
        if (a.vulnerability != b.vulnerability) return false;
        if (a.line != b.line) return false;
    }
    return true;
}

// ---- SummaryTable ---------------------------------------------------------

void SummaryTable::set(const std::string& name, FunctionSummary summary) {
    if (name.empty()) return;
    summaries_[name] = std::move(summary);
}

const FunctionSummary* SummaryTable::find(const std::string& name) const {
    const auto it = summaries_.find(name);
    return it == summaries_.end() ? nullptr : &it->second;
}

const FunctionSummary* SummaryTable::resolve(std::string_view dotted_callee) const {
    if (dotted_callee.empty()) return nullptr;

    // Exact match on the whole path first.
    if (const FunctionSummary* exact = find(std::string(dotted_callee))) return exact;

    // Then the final segment, so `helpers.runQuery` resolves `runQuery`. This
    // can alias two same-named functions in one file; the summaries are merged
    // conservatively by whichever was recorded last, and the resulting finding
    // still points at a real sink.
    const std::string_view segment = ast::last_segment(dotted_callee);
    if (segment != dotted_callee) {
        if (const FunctionSummary* by_segment = find(std::string(segment))) return by_segment;
    }
    return nullptr;
}

// ---- Fixpoint driver ------------------------------------------------------

SummaryTable compute_summaries(const std::vector<FunctionInfo>& functions,
                               const SummaryComputer& compute, int max_iterations) {
    SummaryTable table;
    if (functions.empty()) return table;

    // Seed with empty summaries so a recursive or mutually-recursive call
    // resolves to *something* on the first pass rather than being treated as an
    // unknown external callee.
    for (const auto& function : functions) {
        FunctionSummary seed;
        seed.name = function.name;
        seed.parameter_count = function.parameters.size();
        table.set(function.name, std::move(seed));
    }

    // Iterate until no summary changes. In practice this settles in two or
    // three passes: one to learn the leaves, one to propagate into their
    // callers, and one to confirm nothing moved.
    for (int iteration = 1; iteration <= max_iterations; ++iteration) {
        bool changed = false;

        for (const auto& function : functions) {
            FunctionSummary computed = compute(function, table);
            computed.name = function.name;
            computed.parameter_count = function.parameters.size();
            computed.iterations_to_settle = iteration;

            const FunctionSummary* previous = table.find(function.name);
            if (previous == nullptr || !previous->equivalent_to(computed)) {
                table.set(function.name, std::move(computed));
                changed = true;
            }
        }

        if (!changed) break;
    }

    return table;
}

// ---- CallGraph ------------------------------------------------------------

void CallGraph::add_edge(const std::string& caller, const std::string& callee) {
    if (caller.empty() || callee.empty() || caller == callee) return;
    if (edges_[caller].insert(callee).second) ++edge_count_;
}

const std::set<std::string>& CallGraph::callees_of(const std::string& caller) const {
    const auto it = edges_.find(caller);
    return it == edges_.end() ? empty_string_set() : it->second;
}

std::vector<std::string> CallGraph::reverse_topological_order() const {
    std::vector<std::string> order;
    std::set<std::string> visited;
    std::set<std::string> on_stack;

    // Iterative post-order DFS. Recursion would be simpler but the call graph of
    // a generated file can be thousands deep.
    struct Frame {
        std::string node;
        bool expanded = false;
    };

    const auto visit = [&](const std::string& start) {
        if (visited.count(start) > 0) return;

        std::vector<Frame> stack{{start, false}};
        while (!stack.empty()) {
            Frame& frame = stack.back();

            if (frame.expanded) {
                on_stack.erase(frame.node);
                if (visited.insert(frame.node).second) order.push_back(frame.node);
                stack.pop_back();
                continue;
            }

            frame.expanded = true;
            on_stack.insert(frame.node);

            for (const auto& callee : callees_of(frame.node)) {
                // Skip back-edges: a cycle has no valid topological position,
                // and the summary fixpoint resolves those anyway.
                if (visited.count(callee) > 0 || on_stack.count(callee) > 0) continue;
                stack.push_back({callee, false});
            }
        }
    };

    for (const auto& [caller, callees] : edges_) {
        visit(caller);
        for (const auto& callee : callees) visit(callee);
    }
    return order;
}

// ---- Function extraction --------------------------------------------------

std::vector<FunctionInfo> collect_functions(const std::string& source, TSNode root,
                                            const std::vector<std::string>& definition_node_types,
                                            const std::string& name_field,
                                            const std::string& parameters_field,
                                            const std::string& body_field) {
    std::vector<FunctionInfo> functions;
    if (definition_node_types.empty()) return functions;

    ast::walk(root, [&](TSNode node) {
        const std::string_view type = ast::node_type(node);
        if (std::find(definition_node_types.begin(), definition_node_types.end(), type) ==
            definition_node_types.end()) {
            return;
        }

        FunctionInfo info;
        info.node = node;
        info.start_line = ast::start_line(node);
        info.end_line = ast::end_line(node);

        const TSNode name_node = ast::child_by_field(node, name_field);
        if (!ts_node_is_null(name_node)) {
            info.name = ast::node_text(source, name_node);
        }

        // An arrow function or lambda has no name of its own, but is usually
        // bound to one: `const handler = (req) => {...}`. Recover that so the
        // summary is addressable by the name callers actually use.
        if (info.name.empty()) {
            const auto binder = ast::find_ancestor(
                node, {"variable_declarator", "assignment", "assignment_expression",
                       "short_var_declaration", "pair"});
            if (binder.has_value()) {
                TSNode lhs = ast::child_by_field(*binder, "name");
                if (ts_node_is_null(lhs)) lhs = ast::child_by_field(*binder, "left");
                if (ts_node_is_null(lhs)) lhs = ast::child_by_field(*binder, "key");
                if (!ts_node_is_null(lhs)) {
                    const auto identifiers = ast::identifiers_in(lhs, source);
                    if (!identifiers.empty()) info.name = identifiers.front();
                }
            }
        }

        if (info.name.empty()) {
            info.name = anonymous_name(info.start_line);
            info.is_anonymous = true;
        }

        info.parameters =
            parameter_names(source, ast::child_by_field(node, parameters_field));

        info.body = ast::child_by_field(node, body_field);
        if (ts_node_is_null(info.body)) {
            // Go method declarations and expression-bodied arrows keep the body
            // as the last named child rather than in a `body` field.
            const auto children = ast::named_children(node);
            if (!children.empty()) info.body = children.back();
        }

        functions.push_back(std::move(info));
    });

    // Record nesting so a parent can prune its children's bodies when
    // collecting its own facts. O(n^2) in function count, which is fine: files
    // with thousands of functions are generated bundles where the analysis is
    // dominated by parsing anyway.
    for (std::size_t outer = 0; outer < functions.size(); ++outer) {
        for (std::size_t inner = 0; inner < functions.size(); ++inner) {
            if (outer == inner) continue;
            const FunctionInfo& parent = functions[outer];
            const FunctionInfo& child = functions[inner];
            if (child.start_line >= parent.start_line && child.end_line <= parent.end_line &&
                !(child.start_line == parent.start_line && child.end_line == parent.end_line)) {
                functions[outer].nested.push_back(inner);
            }
        }
    }

    return functions;
}

}  // namespace sentinel

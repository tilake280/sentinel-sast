#include "analyzer.hpp"

#include <algorithm>
#include <chrono>
#include <format>
#include <map>
#include <set>
#include <utility>

#include "ast.hpp"
#include "interproc.hpp"
#include "secrets.hpp"

namespace sentinel {
namespace {

// Result of asking "does this expression carry attacker data that is still
// dangerous for `id`?" Carries the provenance so a finding can show its path.
struct EvalResult {
    bool tainted = false;
    std::string origin;
    std::vector<TaintStep> trace;
    bool through_summary = false;   // taint arrived via a function summary
    bool was_sanitized = false;     // some path was cleaned, this one was not

    static EvalResult clean() { return {}; }
};

// Module scope, where a fact sits outside every function definition.
constexpr int kModuleScope = -1;

// A `name = value` fact extracted from the tree.
struct AssignmentFact {
    TSNode node{};
    TSNode lhs{};
    TSNode rhs{};
    std::vector<std::string> targets;
    int line = 0;

    // Index into FileAnalyzer::functions_, or kModuleScope. Two functions can
    // each declare a local called `name`; without this they were treated as one
    // variable and a sanitizer applied in one leaked into the other.
    int scope = kModuleScope;
};

// A call site.
struct CallFact {
    TSNode node{};
    TSNode function{};
    TSNode arguments{};
    std::string callee;
    int line = 0;
    int scope = kModuleScope;
};

// Argument nodes of a call, skipping punctuation.
std::vector<TSNode> argument_nodes(TSNode arguments) {
    std::vector<TSNode> out;
    for (TSNode child : ast::named_children(arguments)) {
        if (ast::node_type(child) == "comment") continue;
        out.push_back(child);
    }
    return out;
}

bool is_identifier_node(std::string_view type) {
    return type == "identifier" || type == "field_identifier" ||
           type == "property_identifier" || type == "shorthand_property_identifier" ||
           type == "shorthand_property_identifier_pattern";
}

std::string rule_id_for(Language language, VulnClass id) {
    return std::format("sentinel.{}.{}", to_string(language), metadata_for(id).slug);
}

}  // namespace

// ---- Finding --------------------------------------------------------------

int Finding::priority() const {
    return static_cast<int>(severity) * 10 + static_cast<int>(confidence);
}

std::string Finding::headline() const {
    return std::format("{} [{}/{}] {}:{}", vulnerability_type, to_string(severity),
                       to_string(confidence), file, line);
}

void ScanSummary::absorb(const FileReport& report) {
    if (!report.language_supported) {
        ++files_skipped;
        return;
    }
    ++files_scanned;
    if (report.had_parse_errors) ++files_with_parse_errors;
    total_findings += report.findings.size();
    suppressed_inline += report.suppressed_count;
    functions_analyzed += report.functions_analyzed;
    total_ms += report.analysis_ms;

    for (const auto& finding : report.findings) {
        ++by_severity[static_cast<std::size_t>(finding.severity)];
        ++by_confidence[static_cast<std::size_t>(finding.confidence)];
    }
}

void sort_findings(std::vector<Finding>& findings) {
    std::sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        if (a.priority() != b.priority()) return a.priority() > b.priority();
        if (a.file != b.file) return a.file < b.file;
        if (a.line != b.line) return a.line < b.line;
        return a.vulnerability_type < b.vulnerability_type;
    });
}

// ===========================================================================
// FileAnalyzer
// ===========================================================================

namespace {

class FileAnalyzer {
public:
    FileAnalyzer(std::string repository, const SourceFile& file, const LanguageSpec& spec,
                 ast::ParsedFile& parsed)
        : repository_(std::move(repository)),
          path_(file.path),
          spec_(spec),
          parsed_(parsed),
          source_(parsed.source()),
          in_test_file_(is_test_context(file.path)) {}

    FileReport run();

private:
    // ---- Fact extraction --------------------------------------------------
    void collect_facts(TSNode root, std::vector<AssignmentFact>& assignments,
                       std::vector<CallFact>& calls) const;

    // ---- Scoping ----------------------------------------------------------
    // Maps a node to the innermost function containing it, and resolves the
    // chain of scopes whose variables that node can see.
    void index_function_scopes();
    int scope_of(TSNode node) const;
    std::vector<int> visible_scopes(int scope) const;
    std::vector<AssignmentFact> assignments_visible_in(
        int scope, const std::vector<AssignmentFact>& all) const;

    // ---- Expression evaluation -------------------------------------------
    EvalResult evaluate(TSNode node, const TaintState& state, VulnClass id, int depth = 0) const;

    // ---- Taint propagation ------------------------------------------------
    TaintState propagate(const std::vector<AssignmentFact>& assignments, VulnClass id,
                         const TaintState& seed) const;

    // ---- Summary computation ----------------------------------------------
    FunctionSummary summarize(const FunctionInfo& function, const SummaryTable& known) const;

    // ---- Sink matching ----------------------------------------------------
    void match_call_sinks(const std::vector<CallFact>& calls,
                          const std::vector<AssignmentFact>& assignments);
    void match_property_sinks(const std::vector<AssignmentFact>& assignments);
    void match_interprocedural(const std::vector<CallFact>& calls,
                               const std::vector<AssignmentFact>& assignments);
    void match_configuration_rules(TSNode root);
    void match_secrets(TSNode root);

    // ---- Emission ---------------------------------------------------------
    void emit(TSNode node, VulnClass id, const EvalResult& flow, const ScoringContext& context,
              std::string extra_note = "");
    void emit_simple(int line, VulnClass id, Severity severity, Confidence confidence,
                     const std::string& message);

    std::string snippet_at(int line, TSNode fallback) const;
    std::string enclosing_function(TSNode node) const;
    bool inside_conditional(TSNode node) const;
    bool validator_nearby(TSNode node, VulnClass id) const;

    // Reports the sink rule that matched a callee, respecting type guards.
    const SinkRule* match_sink_rule(const std::string& callee, ReceiverType receiver,
                                    bool& matched_full_path) const;

    std::string repository_;
    std::string path_;
    const LanguageSpec& spec_;
    ast::ParsedFile& parsed_;
    const std::string& source_;
    bool in_test_file_ = false;

    TypeEnvironment types_;
    std::vector<FunctionInfo> functions_;
    SummaryTable summaries_;
    SuppressionIndex suppressions_;

    // Start byte of each function definition -> its index in functions_, so a
    // node's enclosing function is one ancestor walk and a hash lookup.
    std::map<std::uint32_t, int> function_by_start_byte_;
    std::vector<int> function_parent_;  // index -> enclosing function, or kModuleScope

    std::vector<Finding> findings_;
    std::set<std::pair<int, int>> emitted_;  // (line, class) dedupe
    std::size_t suppressed_count_ = 0;
};

// ---- Fact extraction ------------------------------------------------------

void FileAnalyzer::collect_facts(TSNode root, std::vector<AssignmentFact>& assignments,
                                 std::vector<CallFact>& calls) const {
    ast::walk(root, [&](TSNode node) {
        const std::string_view type = ast::node_type(node);

        for (const auto& form : spec_.assignment_forms) {
            if (type != form.node_type) continue;

            const TSNode lhs = ast::child_by_field(node, form.lhs_field);
            const TSNode rhs = ast::child_by_field(node, form.rhs_field);
            if (ts_node_is_null(lhs) || ts_node_is_null(rhs)) continue;

            AssignmentFact fact;
            fact.node = node;
            fact.lhs = lhs;
            fact.rhs = rhs;
            fact.line = ast::start_line(node);
            fact.targets = ast::identifiers_in(lhs, source_);
            fact.scope = scope_of(node);
            assignments.push_back(std::move(fact));
        }

        const auto record_call = [&](std::string_view function_field,
                                     std::string_view arguments_field) {
            CallFact fact;
            fact.node = node;
            fact.function = ast::child_by_field(node, function_field);
            fact.arguments = ast::child_by_field(node, arguments_field);
            fact.callee = ast::dotted_name(source_, fact.function);
            fact.line = ast::start_line(node);
            fact.scope = scope_of(node);
            calls.push_back(std::move(fact));
        };

        if (type == spec_.call_node_type) {
            record_call(spec_.call_function_field, spec_.call_arguments_field);
        }

        // `new Function(src)` is a new_expression, not a call_expression, so a
        // spec that only knew one node type missed it despite the sink rule.
        for (const auto& form : spec_.additional_call_forms) {
            if (type != form.node_type) continue;
            record_call(form.function_field, form.arguments_field);
        }
    });
}

// ---- Scoping --------------------------------------------------------------

void FileAnalyzer::index_function_scopes() {
    function_by_start_byte_.clear();
    function_parent_.assign(functions_.size(), kModuleScope);

    for (std::size_t i = 0; i < functions_.size(); ++i) {
        if (ts_node_is_null(functions_[i].node)) continue;
        function_by_start_byte_[ts_node_start_byte(functions_[i].node)] = static_cast<int>(i);
    }

    // A function's parent is the innermost function strictly containing it.
    for (std::size_t i = 0; i < functions_.size(); ++i) {
        if (ts_node_is_null(functions_[i].node)) continue;

        TSNode current = ts_node_parent(functions_[i].node);
        while (!ts_node_is_null(current)) {
            const auto it = function_by_start_byte_.find(ts_node_start_byte(current));
            if (it != function_by_start_byte_.end() && it->second != static_cast<int>(i)) {
                function_parent_[i] = it->second;
                break;
            }
            current = ts_node_parent(current);
        }
    }
}

int FileAnalyzer::scope_of(TSNode node) const {
    TSNode current = node;
    while (!ts_node_is_null(current)) {
        const auto it = function_by_start_byte_.find(ts_node_start_byte(current));
        if (it != function_by_start_byte_.end()) {
            // A node can share a start byte with the function that begins at
            // the same position, so confirm the type actually is a definition.
            const std::string_view type = ast::node_type(current);
            const bool is_definition =
                std::find(spec_.function_definition_node_types.begin(),
                          spec_.function_definition_node_types.end(),
                          type) != spec_.function_definition_node_types.end();
            if (is_definition) return it->second;
        }
        current = ts_node_parent(current);
    }
    return kModuleScope;
}

std::vector<int> FileAnalyzer::visible_scopes(int scope) const {
    // A closure sees its own locals, then its enclosing functions', then module
    // scope. Sibling functions are deliberately excluded -- that conflation is
    // what made a sanitizer in one function appear to apply in another.
    std::vector<int> chain;
    int current = scope;
    int guard = 0;

    while (current != kModuleScope && guard++ < 64) {
        chain.push_back(current);
        if (current < 0 || static_cast<std::size_t>(current) >= function_parent_.size()) break;
        current = function_parent_[static_cast<std::size_t>(current)];
    }
    chain.push_back(kModuleScope);
    return chain;
}

std::vector<AssignmentFact> FileAnalyzer::assignments_visible_in(
    int scope, const std::vector<AssignmentFact>& all) const {
    const std::vector<int> chain = visible_scopes(scope);

    std::vector<AssignmentFact> visible;
    visible.reserve(all.size());
    for (const auto& assignment : all) {
        if (std::find(chain.begin(), chain.end(), assignment.scope) != chain.end()) {
            visible.push_back(assignment);
        }
    }
    return visible;
}

// ---- Expression evaluation ------------------------------------------------

EvalResult FileAnalyzer::evaluate(TSNode node, const TaintState& state, VulnClass id,
                                  int depth) const {
    if (ts_node_is_null(node) || depth > 24) return EvalResult::clean();

    const std::string_view type = ast::node_type(node);

    // ---- String literals ---------------------------------------------------
    // A literal cannot be attacker data no matter what it spells. This is what
    // keeps `print("call os.system carefully")` from being a finding, and it
    // has to come before any text matching.
    if (ast::is_string_literal(node)) {
        // A template literal is a literal *plus* its interpolations, so descend
        // only into the substitution nodes.
        bool has_substitution = false;
        EvalResult result;
        for (TSNode child : ast::named_children(node)) {
            const std::string_view child_type = ast::node_type(child);
            if (child_type != "template_substitution" && child_type != "interpolation") {
                continue;
            }
            has_substitution = true;
            EvalResult inner = evaluate(child, state, id, depth + 1);
            if (inner.tainted) return inner;
        }
        if (!has_substitution) return EvalResult::clean();
        return result;
    }

    // ---- Calls -------------------------------------------------------------
    bool is_call = (type == spec_.call_node_type);
    std::string_view call_function_field = spec_.call_function_field;
    std::string_view call_arguments_field = spec_.call_arguments_field;
    for (const auto& form : spec_.additional_call_forms) {
        if (type != form.node_type) continue;
        is_call = true;
        call_function_field = form.function_field;
        call_arguments_field = form.arguments_field;
        break;
    }

    if (is_call) {
        const TSNode function = ast::child_by_field(node, call_function_field);
        const TSNode arguments = ast::child_by_field(node, call_arguments_field);
        const std::string callee = ast::dotted_name(source_, function);

        // Some source patterns are written with their call parenthesis --
        // Python's `input(` -- so the bare callee name never matches. Test the
        // callee plus "(" as well, which is exact and cannot over-match the way
        // scanning the whole call's text would.
        const std::string callee_invocation = callee.empty() ? std::string() : callee + "(";

        // A call that *is* a source: r.URL.Query(), self.get_argument().
        if (!callee.empty() &&
            (spec_.is_source_for(callee, id) || spec_.is_source_for(callee_invocation, id))) {
            const SourceRule* rule = spec_.match_source(callee);
            EvalResult result;
            result.tainted = true;
            result.origin = callee;
            result.trace.push_back(
                {ast::start_line(node), snippet_at(ast::start_line(node), node),
                 std::format("attacker input enters via {}",
                             rule != nullptr ? rule->description : callee)});
            return result;
        }

        // A sanitizer neutralises its argument for the classes it covers.
        if (!callee.empty()) {
            if (const SanitizerRule* sanitizer = spec_.sanitizers.find(callee)) {
                const SanitizerMask mask = mask_of(*sanitizer);
                EvalResult inner = evaluate(arguments, state, id, depth + 1);
                if (mask.covers(id)) {
                    // Clean for this class. Record that a sanitizer was seen so
                    // scoring can note a partially-defended flow.
                    EvalResult cleaned = EvalResult::clean();
                    cleaned.was_sanitized = inner.tainted;
                    return cleaned;
                }
                // Sanitised, but not for this class -- the classic
                // html.escape() into a SQL string. Keep the taint and say so.
                if (inner.tainted) {
                    inner.trace.push_back(
                        {ast::start_line(node), snippet_at(ast::start_line(node), node),
                         std::format("{} by {}(), which does not protect against {}",
                                     sanitizer->note, callee,
                                     metadata_for(id).name)});
                }
                return inner;
            }

            // A call into a function we have a summary for.
            if (const FunctionSummary* summary = summaries_.resolve(callee)) {
                if (summary->returns_taint) {
                    EvalResult result;
                    result.tainted = true;
                    result.origin = callee;
                    result.through_summary = true;
                    result.trace.push_back(
                        {ast::start_line(node), snippet_at(ast::start_line(node), node),
                         std::format("{}() returns attacker-controlled data", callee)});
                    return result;
                }

                // Taint flows out only through the parameters the callee
                // actually returns.
                if (!summary->parameters_returned.empty()) {
                    const auto args = argument_nodes(arguments);
                    for (const std::size_t index : summary->parameters_returned) {
                        if (index >= args.size()) continue;
                        EvalResult inner = evaluate(args[index], state, id, depth + 1);
                        if (!inner.tainted) continue;
                        inner.through_summary = true;
                        inner.trace.push_back(
                            {ast::start_line(node), snippet_at(ast::start_line(node), node),
                             std::format("passed through {}() and returned", callee)});
                        return inner;
                    }
                    return EvalResult::clean();
                }

                // A summarised function that returns nothing tainted: the call
                // result is clean regardless of its arguments.
                return EvalResult::clean();
            }
        }

        // An unknown callee. Assume it is a conduit -- `wrap(userInput)` most
        // often returns something derived from its argument. This is the
        // over-reporting direction, which is the safe one.
        EvalResult from_arguments = evaluate(arguments, state, id, depth + 1);
        if (from_arguments.tainted) return from_arguments;

        // Taint also flows through the *receiver* of a method call:
        // `parts.join('')` on a tainted array, `name.trim()` on a tainted
        // string. Checking only the arguments loses the entire family of
        // string and collection methods.
        if (!ts_node_is_null(function)) {
            const std::string_view receiver = ast::receiver_of(callee);
            if (!receiver.empty()) {
                if (const TaintFact* fact = state.lookup(std::string(receiver))) {
                    if (fact->dangerous_for(id)) {
                        EvalResult result;
                        result.tainted = true;
                        result.origin = fact->origin;
                        result.trace = fact->trace;
                        return result;
                    }
                }
            }
        }
        return from_arguments;
    }

    // ---- Identifiers -------------------------------------------------------
    if (is_identifier_node(type)) {
        const std::string name = ast::node_text(source_, node);
        if (const TaintFact* fact = state.lookup(name)) {
            if (!fact->dangerous_for(id)) {
                EvalResult cleaned = EvalResult::clean();
                cleaned.was_sanitized = true;
                return cleaned;
            }
            EvalResult result;
            result.tainted = true;
            result.origin = fact->origin;
            result.trace = fact->trace;
            return result;
        }
        return EvalResult::clean();
    }

    // ---- Member and subscript expressions ----------------------------------
    if (type == spec_.member_node_type || type == "subscript_expression" ||
        type == "subscript" || type == "index_expression") {
        const std::string dotted = ast::node_text(source_, node);

        if (spec_.is_source_for(dotted, id)) {
            const SourceRule* rule = spec_.match_source(dotted);
            EvalResult result;
            result.tainted = true;
            result.origin = ast::trim(dotted);
            result.trace.push_back(
                {ast::start_line(node), snippet_at(ast::start_line(node), node),
                 std::format("attacker input enters via {}",
                             rule != nullptr ? rule->description : ast::trim(dotted))});
            return result;
        }

        // Not a source itself; the base might still be tainted.
        for (TSNode child : ast::named_children(node)) {
            EvalResult inner = evaluate(child, state, id, depth + 1);
            if (inner.tainted) return inner;
        }
        return EvalResult::clean();
    }

    // ---- Everything else: any tainted child taints the expression -----------
    EvalResult aggregate = EvalResult::clean();
    for (TSNode child : ast::named_children(node)) {
        EvalResult inner = evaluate(child, state, id, depth + 1);
        if (inner.tainted) return inner;
        if (inner.was_sanitized) aggregate.was_sanitized = true;
    }
    return aggregate;
}

// ---- Taint propagation ----------------------------------------------------

TaintState FileAnalyzer::propagate(const std::vector<AssignmentFact>& assignments, VulnClass id,
                                   const TaintState& seed) const {
    TaintState state = seed;

    // Iterate to a fixpoint. A single top-to-bottom pass would miss any flow
    // whose assignments are not already in dependency order, which is common in
    // real code (hoisted functions, reassignment, loops).
    for (int iteration = 0; iteration < kMaxTaintDepth; ++iteration) {
        bool changed = false;

        for (const auto& assignment : assignments) {
            const EvalResult flow = evaluate(assignment.rhs, state, id);
            if (!flow.tainted) continue;

            for (const auto& target : assignment.targets) {
                TaintFact fact;
                fact.origin = flow.origin;
                fact.trace = flow.trace;
                fact.depth = static_cast<int>(flow.trace.size());
                fact.trace.push_back({assignment.line, snippet_at(assignment.line, assignment.node),
                                      std::format("flows into '{}'", target)});
                if (state.mark(target, std::move(fact))) changed = true;
            }
        }

        if (!changed) break;
    }

    return state;
}

// ---- Summary computation --------------------------------------------------

FunctionSummary FileAnalyzer::summarize(const FunctionInfo& function,
                                        const SummaryTable& known) const {
    FunctionSummary summary;
    summary.name = function.name;
    summary.parameter_count = function.parameters.size();

    if (ts_node_is_null(function.body)) return summary;

    std::vector<AssignmentFact> assignments;
    std::vector<CallFact> calls;
    collect_facts(function.body, assignments, calls);

    // Analyse the body once per vulnerability class, seeding each parameter as
    // tainted in turn. Seeding one at a time is what lets the summary say
    // *which* parameter reaches the sink rather than just that one does.
    for (const auto& meta : all_vulnerability_classes()) {
        if (meta.id == VulnClass::Unknown) continue;

        for (std::size_t index = 0; index < function.parameters.size(); ++index) {
            const std::string& parameter = function.parameters[index];
            if (parameter.empty()) continue;

            TaintState seed;
            TaintFact entry;
            entry.origin = std::format("parameter '{}'", parameter);
            entry.trace.push_back({function.start_line,
                                   snippet_at(function.start_line, function.node),
                                   std::format("parameter '{}' of {}()", parameter,
                                               function.name)});
            seed.mark(parameter, std::move(entry));

            const TaintState state = propagate(assignments, meta.id, seed);

            // Does the parameter reach a sink of this class?
            for (const auto& call : calls) {
                if (call.callee.empty()) continue;
                if (spec_.is_source_for(call.callee, meta.id)) continue;

                bool matched_full_path = false;
                const ReceiverType receiver =
                    types_.receiver_type_of(call.callee, spec_.type_rules);
                const SinkRule* rule =
                    match_sink_rule(call.callee, receiver, matched_full_path);
                if (rule == nullptr || rule->vulnerability != meta.id) continue;

                const auto args = argument_nodes(call.arguments);
                bool reaches = false;
                if (rule->tainted_argument >= 0) {
                    const std::size_t want = static_cast<std::size_t>(rule->tainted_argument);
                    if (want < args.size()) {
                        reaches = evaluate(args[want], state, meta.id).tainted;
                    }
                } else {
                    reaches = evaluate(call.arguments, state, meta.id).tainted;
                }

                if (reaches) {
                    ParamSink sink;
                    sink.parameter_index = index;
                    sink.vulnerability = meta.id;
                    sink.line = call.line;
                    sink.sink_snippet = snippet_at(call.line, call.node);
                    summary.parameter_sinks.push_back(std::move(sink));
                    break;  // one sink per (parameter, class) is enough
                }
            }

            // Does the parameter flow out through a return?
            for (const auto& return_type : spec_.return_node_types) {
                for (TSNode node : ast::find_all(function.body, return_type)) {
                    if (evaluate(node, state, meta.id).tainted) {
                        summary.parameters_returned.insert(index);
                        break;
                    }
                }
            }
        }
    }

    // Does the function return attacker data with no parameter involved?
    // Checked with an empty seed so a parameter flow does not masquerade as one.
    {
        const TaintState state = propagate(assignments, VulnClass::SqlInjection, TaintState{});
        for (const auto& return_type : spec_.return_node_types) {
            for (TSNode node : ast::find_all(function.body, return_type)) {
                const EvalResult flow = evaluate(node, state, VulnClass::SqlInjection);
                if (flow.tainted && !flow.through_summary) {
                    summary.returns_taint = true;
                    break;
                }
            }
        }
    }

    // A function whose every return value passed through a sanitizer is itself
    // a sanitizer, so callers get the benefit.
    if (!summary.returns_taint && summary.parameters_returned.empty() &&
        !function.parameters.empty()) {
        bool all_sanitized = true;
        bool saw_return = false;
        SanitizerMask combined;
        combined.add_all();

        for (const auto& return_type : spec_.return_node_types) {
            for (TSNode node : ast::find_all(function.body, return_type)) {
                saw_return = true;
                const auto children = ast::named_children(node);
                if (children.empty()) continue;
                const std::string returned = ast::dotted_name(source_, children.front());
                if (returned.empty()) {
                    all_sanitized = false;
                    continue;
                }
                const SanitizerRule* rule = spec_.sanitizers.find(returned);
                if (rule == nullptr) {
                    all_sanitized = false;
                    continue;
                }
                combined = combined.merged_with(mask_of(*rule));
            }
        }
        if (saw_return && all_sanitized && !combined.empty()) {
            summary.sanitizes = combined;
        }
    }

    (void)known;  // resolution happens through summaries_, refreshed per pass
    return summary;
}

// ---- Sink rule matching ---------------------------------------------------

const SinkRule* FileAnalyzer::match_sink_rule(const std::string& callee, ReceiverType receiver,
                                              bool& matched_full_path) const {
    matched_full_path = false;
    if (callee.empty()) return nullptr;

    const std::string_view segment = ast::last_segment(callee);
    const SinkRule* best = nullptr;

    for (const auto& rule : spec_.call_sinks) {
        const bool exact = (rule.callee == callee);
        const bool by_segment = !rule.require_full_path && (rule.callee == segment);
        if (!exact && !by_segment) continue;

        // Type guards. An Unknown receiver passes both, deliberately: we keep
        // reporting on code shaped in ways the type inference does not model,
        // and downgrade confidence instead of dropping the finding.
        if (rule.required_receiver != ReceiverType::Unknown &&
            receiver != ReceiverType::Unknown && receiver != rule.required_receiver) {
            continue;
        }
        if (rule.excluded_receiver != ReceiverType::Unknown &&
            receiver == rule.excluded_receiver) {
            continue;
        }

        if (best == nullptr || (exact && !matched_full_path) ||
            rule.callee.size() > best->callee.size()) {
            best = &rule;
            matched_full_path = exact;
        }
    }
    return best;
}

// ---- Sink matching --------------------------------------------------------

void FileAnalyzer::match_call_sinks(const std::vector<CallFact>& calls,
                                    const std::vector<AssignmentFact>& assignments) {
    // Group call sites by the function they live in. Taint is then propagated
    // once per (scope, class) over only the assignments that scope can see, so
    // a local in one function never taints a same-named local in another.
    std::map<int, std::vector<const CallFact*>> by_scope;
    for (const auto& call : calls) {
        if (call.callee.empty()) continue;
        by_scope[call.scope].push_back(&call);
    }

    for (const auto& [scope, scope_calls] : by_scope) {
        const auto visible = assignments_visible_in(scope, assignments);

        // One propagation per class: a value sanitised for XSS but not SQL has
        // a different taint state depending on which class is being asked
        // about. Only classes with a candidate sink in this scope are worth
        // propagating for, which keeps the cost proportional to the code.
        for (const auto& meta : all_vulnerability_classes()) {
            if (meta.id == VulnClass::Unknown) continue;

            std::vector<std::pair<const CallFact*, const SinkRule*>> candidates;
            for (const CallFact* call : scope_calls) {
                // A source that happens to share a name with a sink -- Go's
                // r.URL.Query() versus db.Query() -- is not a sink.
                if (spec_.is_source_for(call->callee, meta.id)) continue;

                const ReceiverType receiver =
                    types_.receiver_type_of(call->callee, spec_.type_rules);
                bool matched_full_path = false;
                const SinkRule* rule =
                    match_sink_rule(call->callee, receiver, matched_full_path);
                if (rule == nullptr || rule->vulnerability != meta.id) continue;
                if (ts_node_is_null(call->arguments)) continue;
                candidates.emplace_back(call, rule);
            }
            if (candidates.empty()) continue;

            const TaintState state = propagate(visible, meta.id, TaintState{});

            for (const auto& [call, rule] : candidates) {
                const ReceiverType receiver =
                    types_.receiver_type_of(call->callee, spec_.type_rules);
                bool matched_full_path = false;
                match_sink_rule(call->callee, receiver, matched_full_path);

                const auto args = argument_nodes(call->arguments);
                EvalResult flow;

                if (rule->tainted_argument >= 0) {
                    const std::size_t want = static_cast<std::size_t>(rule->tainted_argument);
                    if (want >= args.size()) continue;
                    flow = evaluate(args[want], state, meta.id);
                } else {
                    flow = evaluate(call->arguments, state, meta.id);
                }

                if (!flow.tainted) continue;

                ScoringContext context;
                context.vulnerability = meta.id;
                context.trace_length = std::max<std::size_t>(flow.trace.size(), 1);
                context.crosses_function_boundary = flow.through_summary;
                context.receiver_type_known = receiver != ReceiverType::Unknown;
                context.receiver_type = receiver;
                context.file_had_parse_errors = parsed_.has_parse_errors();
                context.in_test_file = in_test_file_;
                context.source_is_direct = flow.trace.size() <= 1;
                context.sink_matched_full_path = matched_full_path;
                context.partially_sanitized = flow.was_sanitized;
                context.inside_conditional = inside_conditional(call->node);
                context.validator_seen_nearby = validator_nearby(call->node, meta.id);

                emit(call->node, meta.id, flow, context, rule->note);
            }
        }
    }
}

void FileAnalyzer::match_property_sinks(const std::vector<AssignmentFact>& assignments) {
    if (spec_.property_sinks.empty() || spec_.member_node_type.empty()) return;

    for (const auto& meta : all_vulnerability_classes()) {
        if (meta.id == VulnClass::Unknown) continue;

        for (const auto& assignment : assignments) {
            if (ast::node_type(assignment.lhs) != spec_.member_node_type) continue;

            // Scoped like the call sinks: only what this assignment's own
            // function can see.
            const TaintState state = propagate(
                assignments_visible_in(assignment.scope, assignments), meta.id, TaintState{});

            const TSNode property =
                ast::child_by_field(assignment.lhs, spec_.member_property_field);
            if (ts_node_is_null(property)) continue;

            const std::string name = ast::node_text(source_, property);
            const ReceiverType receiver = types_.receiver_type_of(
                ast::dotted_name(source_, assignment.lhs), spec_.type_rules);

            for (const auto& sink : spec_.property_sinks) {
                if (sink.property != name) continue;
                if (sink.vulnerability != meta.id) continue;
                if (sink.required_receiver != ReceiverType::Unknown &&
                    receiver != ReceiverType::Unknown && receiver != sink.required_receiver) {
                    continue;
                }

                const EvalResult flow = evaluate(assignment.rhs, state, meta.id);
                if (!flow.tainted) break;

                ScoringContext context;
                context.vulnerability = meta.id;
                context.trace_length = std::max<std::size_t>(flow.trace.size(), 1);
                context.crosses_function_boundary = flow.through_summary;
                context.receiver_type_known = receiver != ReceiverType::Unknown;
                context.receiver_type = receiver;
                context.file_had_parse_errors = parsed_.has_parse_errors();
                context.in_test_file = in_test_file_;
                context.source_is_direct = flow.trace.size() <= 1;
                context.partially_sanitized = flow.was_sanitized;
                context.inside_conditional = inside_conditional(assignment.node);

                emit(assignment.lhs, meta.id, flow, context, sink.note);
                break;
            }
        }
    }
}

void FileAnalyzer::match_interprocedural(const std::vector<CallFact>& calls,
                                         const std::vector<AssignmentFact>& assignments) {
    if (summaries_.empty()) return;

    // Same scope grouping as the intraprocedural pass.
    std::map<int, std::vector<const CallFact*>> by_scope;
    for (const auto& call : calls) {
        if (call.callee.empty()) continue;
        if (summaries_.resolve(call.callee) == nullptr) continue;
        by_scope[call.scope].push_back(&call);
    }

    for (const auto& [scope, scope_calls] : by_scope) {
        const auto visible = assignments_visible_in(scope, assignments);

        for (const auto& meta : all_vulnerability_classes()) {
            if (meta.id == VulnClass::Unknown) continue;

            const TaintState state = propagate(visible, meta.id, TaintState{});

            for (const CallFact* call_ptr : scope_calls) {
                const CallFact& call = *call_ptr;

                const FunctionSummary* summary = summaries_.resolve(call.callee);
                if (summary == nullptr || summary->parameter_sinks.empty()) continue;

                const auto args = argument_nodes(call.arguments);

                for (const auto& sink : summary->parameter_sinks) {
                    if (sink.vulnerability != meta.id) continue;
                    if (sink.parameter_index >= args.size()) continue;

                    EvalResult flow = evaluate(args[sink.parameter_index], state, meta.id);
                    if (!flow.tainted) continue;

                    // Extend the trace across the call boundary so the report
                    // shows the whole path rather than stopping at the call.
                    flow.trace.push_back(
                        {call.line, snippet_at(call.line, call.node),
                         std::format("passed as argument {} to {}()",
                                     sink.parameter_index + 1, call.callee)});
                    flow.trace.push_back(
                        {sink.line, sink.sink_snippet,
                         std::format("reaches a {} sink inside {}()",
                                     metadata_for(meta.id).name, summary->name)});
                    flow.through_summary = true;

                    ScoringContext context;
                    context.vulnerability = meta.id;
                    context.trace_length = flow.trace.size();
                    context.crosses_function_boundary = true;
                    context.receiver_type_known = false;
                    context.file_had_parse_errors = parsed_.has_parse_errors();
                    context.in_test_file = in_test_file_;
                    context.inside_conditional = inside_conditional(call.node);
                    context.validator_seen_nearby = validator_nearby(call.node, meta.id);

                    emit(call.node, meta.id, flow, context,
                         std::format("the sink is inside {}(), reached through its parameter",
                                     summary->name));
                }
            }
        }
    }
}

void FileAnalyzer::match_configuration_rules(TSNode root) {
    if (spec_.configuration_rules.empty()) return;

    // These need no dataflow: the call itself is the finding. Matching is on
    // node text rather than structure because the patterns span argument shapes
    // that differ per library, and a false positive here is cheap.
    ast::walk(root, [&](TSNode node) {
        const std::string_view type = ast::node_type(node);
        if (type != spec_.call_node_type && type != "keyed_element" && type != "pair" &&
            type != "keyword_argument" && type != "field_declaration") {
            return;
        }

        const std::string text = ast::node_text(source_, node);
        const int line = ast::start_line(node);

        for (const auto& rule : spec_.configuration_rules) {
            if (!ast::contains(text, rule.pattern)) continue;

            // Match only when the pattern is near the start of the node, so an
            // enclosing expression does not re-report every nested occurrence.
            if (text.find(rule.pattern) > rule.pattern.size() + 32) continue;

            emit_simple(line, rule.vulnerability, rule.severity,
                        in_test_file_ ? Confidence::Low : Confidence::High, rule.message);
            break;
        }
    });
}

void FileAnalyzer::match_secrets(TSNode root) {
    const auto candidates = scan_for_secrets(parsed_, root, path_, spec_.assignment_node_types(),
                                             spec_.pair_node_types);

    for (const auto& candidate : candidates) {
        Severity severity = metadata_for(VulnClass::HardcodedSecret).baseline;
        if (in_test_file_) severity = lower(severity);
        if (!candidate.pattern_name.empty()) severity = raise(severity);

        std::string message = candidate.pattern_name.empty()
                                  ? std::format("Hardcoded credential: {}", candidate.rationale)
                                  : std::format("Hardcoded {}: {}", candidate.pattern_name,
                                                candidate.rationale);

        emit_simple(candidate.line, VulnClass::HardcodedSecret, severity, candidate.confidence,
                    std::move(message));
    }
}

// ---- Emission -------------------------------------------------------------

std::string FileAnalyzer::snippet_at(int line, TSNode fallback) const {
    const auto& lines = parsed_.lines();
    if (line >= 1 && static_cast<std::size_t>(line) <= lines.size()) {
        std::string text = ast::trim(lines[line - 1]);
        // Very long lines (minified code) would flood the report and the triage
        // payload, so truncate on a character boundary.
        if (text.size() > 240) {
            text.resize(237);
            text += "...";
        }
        return text;
    }
    return ast::trim(ast::node_view(source_, fallback));
}

std::string FileAnalyzer::enclosing_function(TSNode node) const {
    std::vector<std::string_view> types;
    types.reserve(spec_.function_definition_node_types.size());
    for (const auto& type : spec_.function_definition_node_types) types.push_back(type);

    const auto ancestor = ast::find_ancestor(node, types);
    if (!ancestor.has_value()) return {};

    const int line = ast::start_line(*ancestor);
    for (const auto& function : functions_) {
        if (function.start_line == line) return function.name;
    }
    return {};
}

bool FileAnalyzer::inside_conditional(TSNode node) const {
    std::vector<std::string_view> types;
    types.reserve(spec_.conditional_node_types.size());
    for (const auto& type : spec_.conditional_node_types) types.push_back(type);
    return ast::has_ancestor_of_type(node, types);
}

bool FileAnalyzer::validator_nearby(TSNode node, VulnClass id) const {
    // "Nearby" means the enclosing function body. A validator anywhere in the
    // same function is weak evidence the developer thought about this input --
    // enough to lower confidence, never enough to suppress.
    std::vector<std::string_view> types;
    types.reserve(spec_.function_definition_node_types.size());
    for (const auto& type : spec_.function_definition_node_types) types.push_back(type);

    const auto scope = ast::find_ancestor(node, types);
    if (!scope.has_value()) return false;

    bool found = false;
    ast::walk(*scope, [&](TSNode current) {
        if (found) return;
        if (ast::node_type(current) != spec_.call_node_type) return;
        const std::string callee =
            ast::dotted_name(source_, ast::child_by_field(current, spec_.call_function_field));
        if (!callee.empty() && spec_.validators.guards(callee, id)) found = true;
    });
    return found;
}

void FileAnalyzer::emit(TSNode node, VulnClass id, const EvalResult& flow,
                        const ScoringContext& context, std::string extra_note) {
    const int line = ast::start_line(node);

    // Dedupe by (line, class): the same flow can be reachable through both the
    // intraprocedural and interprocedural paths.
    if (!emitted_.insert({line, static_cast<int>(id)}).second) return;

    if (suppressions_.suppresses(line, id)) {
        ++suppressed_count_;
        return;
    }

    const VulnMetadata& meta = metadata_for(id);
    const Score score = score_finding(context);

    Finding finding;
    finding.repository = repository_;
    finding.file = path_;
    finding.vulnerability = id;
    finding.vulnerability_type = std::string(meta.name);
    finding.snippet = snippet_at(line, node);
    finding.line = line;
    finding.column = ast::start_column(node);
    finding.severity = score.severity;
    finding.confidence = score.confidence;
    finding.cwe = std::string(meta.cwe);
    finding.owasp = std::string(meta.owasp);
    finding.rule_id = rule_id_for(spec_.id, id);
    finding.remediation = std::string(meta.remediation);
    finding.trace = flow.trace;
    finding.taint_source = flow.origin;
    finding.scoring_factors = score.factors;
    finding.crosses_function_boundary = context.crosses_function_boundary;
    finding.function_name = enclosing_function(node);

    finding.message = std::string(meta.description);
    if (!flow.origin.empty()) {
        finding.message += std::format(" Tainted value originates from {}.", flow.origin);
    }
    if (!extra_note.empty()) {
        finding.message += std::format(" ({})", extra_note);
    }

    findings_.push_back(std::move(finding));
}

void FileAnalyzer::emit_simple(int line, VulnClass id, Severity severity, Confidence confidence,
                               const std::string& message) {
    if (!emitted_.insert({line, static_cast<int>(id)}).second) return;

    if (suppressions_.suppresses(line, id)) {
        ++suppressed_count_;
        return;
    }

    const VulnMetadata& meta = metadata_for(id);

    Finding finding;
    finding.repository = repository_;
    finding.file = path_;
    finding.vulnerability = id;
    finding.vulnerability_type = std::string(meta.name);
    finding.snippet = snippet_at(line, TSNode{});
    finding.line = line;
    finding.severity = severity;
    finding.confidence = confidence;
    finding.cwe = std::string(meta.cwe);
    finding.owasp = std::string(meta.owasp);
    finding.rule_id = rule_id_for(spec_.id, id);
    finding.message = message;
    finding.remediation = std::string(meta.remediation);
    finding.scoring_factors.push_back("matched a configuration or literal pattern; no dataflow required");

    findings_.push_back(std::move(finding));
}

// ---- Driver ---------------------------------------------------------------

FileReport FileAnalyzer::run() {
    const auto started = std::chrono::steady_clock::now();

    FileReport report;
    report.path = path_;
    report.language = spec_.id;
    report.language_supported = true;
    report.parsed = parsed_.ok();

    if (!parsed_.ok()) return report;

    const TSNode root = parsed_.root();
    report.had_parse_errors = parsed_.has_parse_errors();

    // 1. Suppressions, first so nothing downstream has to know about them.
    suppressions_ = collect_suppressions(parsed_, root, spec_.comment_node_types);

    // 2. Receiver types.
    types_ = build_type_environment(parsed_, root, spec_.type_rules, spec_.import_node_types,
                                    spec_.assignment_node_types());

    // 3. Functions and their summaries.
    functions_ = collect_functions(source_, root, spec_.function_definition_node_types,
                                   spec_.function_name_field, spec_.function_parameters_field,
                                   spec_.function_body_field);
    report.functions_analyzed = functions_.size();

    // Must precede any fact collection: scope_of() reads this index, and an
    // unpopulated one would put every fact in module scope.
    index_function_scopes();

    if (!functions_.empty()) {
        summaries_ = compute_summaries(
            functions_,
            [this](const FunctionInfo& function, const SummaryTable& known) {
                return summarize(function, known);
            });
        report.summaries_computed = summaries_.size();
    }

    // 4. Whole-file facts. Analysing the file as one scope rather than
    //    per-function is deliberate: JavaScript closures capture outer
    //    variables, and the express/lambda handler shape puts the source inside
    //    a callback nested in module scope.
    std::vector<AssignmentFact> assignments;
    std::vector<CallFact> calls;
    collect_facts(root, assignments, calls);

    // 5. The four detection passes.
    match_call_sinks(calls, assignments);
    match_property_sinks(assignments);
    match_interprocedural(calls, assignments);
    match_configuration_rules(root);
    match_secrets(root);

    sort_findings(findings_);
    report.findings = std::move(findings_);
    report.suppressed_count = suppressed_count_;
    report.stale_suppressions = suppressions_.unused();
    report.undocumented_suppressions = suppressions_.without_reason();

    const auto finished = std::chrono::steady_clock::now();
    report.analysis_ms =
        std::chrono::duration<double, std::milli>(finished - started).count();

    return report;
}

}  // namespace

// ---- Public entry points --------------------------------------------------

FileReport analyze_file_detailed(const std::string& repository, const SourceFile& file) {
    FileReport report;
    report.path = file.path;

    const Language language = language_for_path(file.path);
    const LanguageSpec* spec = spec_for(language);
    if (spec == nullptr || spec->grammar == nullptr) {
        report.language = Language::Unknown;
        return report;  // language_supported stays false
    }

    report.language = language;

    // An empty or enormous file is not worth parsing. The upper bound keeps a
    // single vendored bundle from stalling a worker for minutes.
    constexpr std::size_t kMaxFileBytes = 4u * 1024u * 1024u;
    if (file.content.empty() || file.content.size() > kMaxFileBytes) {
        report.language_supported = true;
        report.parsed = false;
        return report;
    }

    ast::ParsedFile parsed(spec->grammar, file.content);
    FileAnalyzer analyzer(repository, file, *spec, parsed);
    return analyzer.run();
}

std::vector<Finding> analyze_file(const std::string& repository, const SourceFile& file) {
    return analyze_file_detailed(repository, file).findings;
}

}  // namespace sentinel

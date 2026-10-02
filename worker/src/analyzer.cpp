#include "analyzer.hpp"

#include <algorithm>
#include <chrono>
#include <format>
#include <map>
#include <optional>
#include <ranges>
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
    bool local_source = false;      // the source is argv/env/stdin, not a request

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

// The sink rule a call site matched, with the evidence the match rested on.
struct SinkMatch {
    const SinkRule* rule = nullptr;
    ReceiverType guard_type = ReceiverType::Unknown;  // what the rule's type guard saw
    bool full_path = false;                           // matched the whole dotted callee

    explicit operator bool() const noexcept { return rule != nullptr; }
};

// Everything summarising a function needs from its body, extracted once. The
// summary fixpoint may compute a function several times; its facts do not
// change between passes, only what is known about its callees does.
struct FunctionFacts {
    std::vector<AssignmentFact> assignments;
    std::vector<CallFact> calls;
    std::vector<TSNode> returned;  // the expressions the function hands back
};

// Argument nodes of a call, skipping punctuation.
std::vector<TSNode> argument_nodes(TSNode arguments) {
    std::vector<TSNode> out;
    if (ts_node_is_null(arguments)) return out;
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
    return std::to_underlying(severity) * 10 + std::to_underlying(confidence);
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
    if (report.skipped_minified) {
        ++files_minified;
        return;
    }
    ++files_scanned;
    if (report.had_parse_errors) ++files_with_parse_errors;
    total_findings += report.findings.size();
    suppressed_inline += report.suppressed_count;
    functions_analyzed += report.functions_analyzed;
    total_ms += report.analysis_ms;

    for (const auto& finding : report.findings) {
        ++by_severity[std::to_underlying(finding.severity)];
        ++by_confidence[std::to_underlying(finding.confidence)];
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
          in_test_file_(is_test_context(file.path)) {
        index_active_sources();
    }

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

    // ---- Sources -----------------------------------------------------------
    // The source rules that could match anything in this file. Most files
    // mention two or three of a language's sources, and many mention none, so
    // matching every expression against the whole table is mostly wasted work.
    void index_active_sources();
    bool is_source_for(std::string_view expression, VulnClass id) const;
    const SourceRule* match_source(std::string_view expression) const;

    // True when some source in this file can produce taint relevant to `id`.
    // When it is false no value in the file can be tainted for that class, and
    // every pass can skip it.
    bool class_has_source(VulnClass id) const { return classes_with_source_.covers(id); }

    // ---- Expression evaluation -------------------------------------------
    EvalResult evaluate(TSNode node, const TaintState& state, VulnClass id, int depth = 0) const;

    // ---- Taint propagation ------------------------------------------------
    TaintState propagate(const std::vector<AssignmentFact>& assignments, VulnClass id,
                         const TaintState& seed) const;

    // The taint state of one scope for one class with nothing seeded, computed
    // once and shared by the three sink-matching passes.
    const TaintState& scope_state(int scope, VulnClass id,
                                  const std::vector<AssignmentFact>& all);

    // ---- Summary computation ----------------------------------------------
    FunctionSummary summarize(const FunctionInfo& function) const;

    // The expressions whose value a function hands back to its caller.
    std::vector<TSNode> returned_expressions(const FunctionInfo& function) const;

    // Extracts each function's facts and works out who calls whom, so the
    // fixpoint can visit callees before callers.
    SummaryPlan plan_summaries();

    // The property-sink rule an assignment matches for `id`, if any.
    const PropertySinkRule* match_property_sink(const AssignmentFact& assignment,
                                                VulnClass id) const;

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

    // True when the statement or function around `node` names something that
    // has to be unpredictable -- a token, a secret, a session id.
    bool in_security_context(TSNode node) const;

    // True when argument `index` of the call is an object literal with `key`.
    bool argument_has_key(const CallFact& call, int index, std::string_view key) const;
    bool inside_conditional(TSNode node) const;
    bool validator_nearby(TSNode node, VulnClass id) const;

    // The sink rule that matched a call site, respecting type guards.
    SinkMatch match_sink_rule(const CallFact& call) const;

    // The receiver type of one argument, for rules guarded on an argument.
    ReceiverType argument_type(const CallFact& call, int index) const;

    std::string repository_;
    std::string path_;
    const LanguageSpec& spec_;
    ast::ParsedFile& parsed_;
    const std::string& source_;
    bool in_test_file_ = false;

    TypeEnvironment types_;
    std::vector<FunctionInfo> functions_;
    std::vector<FunctionFacts> function_facts_;  // parallel to functions_
    SummaryTable summaries_;

    // The table evaluate() resolves callees against. Normally summaries_; while
    // the fixpoint is running it is the table being built, so one function's
    // summary can be computed from what is already known about its callees.
    const SummaryTable* summary_lookup_ = &summaries_;
    SuppressionIndex suppressions_;

    // Start byte of each function definition -> its index in functions_, so a
    // node's enclosing function is one ancestor walk and a hash lookup.
    std::map<std::uint32_t, int> function_by_start_byte_;
    std::vector<int> function_parent_;  // index -> enclosing function, or kModuleScope

    std::vector<const SourceRule*> active_sources_;
    ClassSet classes_with_source_;

    std::map<std::pair<int, VulnClass>, TaintState> scope_states_;
    std::map<int, std::vector<AssignmentFact>> visible_assignments_;

    std::vector<Finding> findings_;
    std::set<std::pair<int, int>> emitted_;  // (line, class) dedupe

    // Byte ranges of the sinks a taint finding has been reported on, by class.
    // A pattern rule that matches inside one is describing the same flaw.
    struct ReportedSpan {
        std::uint32_t start = 0;
        std::uint32_t end = 0;
        VulnClass id = VulnClass::Unknown;
    };
    std::vector<ReportedSpan> reported_spans_;
    std::size_t suppressed_count_ = 0;
};

// ---- Sources --------------------------------------------------------------

void FileAnalyzer::index_active_sources() {
    // A rule matches an expression by substring, and every expression the
    // engine tests is built from text in this file -- a node's own text, or a
    // dotted name assembled from identifiers. So a rule can only match if each
    // run of identifier characters in its pattern occurs somewhere in the
    // file. That is a superset of the rules that will match, never a subset,
    // which is the direction that keeps this a pure optimisation.
    const auto is_identifier_char = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '$';
    };

    for (const auto& rule : spec_.sources) {
        bool possible = true;
        const std::string_view pattern = rule.pattern;

        for (std::size_t i = 0; i < pattern.size() && possible;) {
            if (!is_identifier_char(pattern[i])) {
                ++i;
                continue;
            }
            std::size_t end = i;
            while (end < pattern.size() && is_identifier_char(pattern[end])) ++end;
            possible = std::string_view(source_).contains(pattern.substr(i, end - i));
            i = end;
        }
        if (!possible) continue;

        active_sources_.push_back(&rule);
        if (rule.classes.empty()) {
            classes_with_source_.add_all();
        } else {
            for (const VulnClass id : rule.classes) classes_with_source_.add(id);
        }
    }
}

// The two lookups below are LanguageSpec::is_source_for and ::match_source
// restricted to the active rules; they return exactly what those would.

bool FileAnalyzer::is_source_for(std::string_view expression, VulnClass id) const {
    for (const SourceRule* rule : active_sources_) {
        if (!source_pattern_matches(expression, rule->pattern)) continue;
        if (rule->classes.empty() || std::ranges::contains(rule->classes, id)) return true;
    }
    return false;
}

const SourceRule* FileAnalyzer::match_source(std::string_view expression) const {
    const SourceRule* best = nullptr;
    for (const SourceRule* rule : active_sources_) {
        if (!source_pattern_matches(expression, rule->pattern)) continue;
        if (best == nullptr || rule->pattern.size() > best->pattern.size()) best = rule;
    }
    return best;
}

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

    for (const auto& [index, function] : std::views::enumerate(functions_)) {
        if (ts_node_is_null(function.node)) continue;
        function_by_start_byte_[ts_node_start_byte(function.node)] = static_cast<int>(index);
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
            if (std::ranges::contains(spec_.function_definition_node_types, type)) {
                return it->second;
            }
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
        if (std::ranges::contains(chain, assignment.scope)) {
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
            (is_source_for(callee, id) || is_source_for(callee_invocation, id))) {
            const SourceRule* rule = match_source(callee);
            EvalResult result;
            result.tainted = true;
            result.origin = callee;
            result.local_source = rule != nullptr && rule->local;
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
            if (const FunctionSummary* summary = summary_lookup_->resolve(callee)) {
                if (summary->returns_taint.covers(id)) {
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
                // actually returns, and only for the classes it did not clean
                // on the way. A summarised function that returns none of its
                // parameters gives a clean result whatever it was passed.
                EvalResult result = EvalResult::clean();

                // It returns source data, just not data dangerous for this
                // class: something inside sanitised it.
                if (!summary->returns_taint.empty()) result.was_sanitized = true;

                const auto args = argument_nodes(arguments);
                for (const auto& [index, dangerous_for] : summary->parameters_returned) {
                    if (index >= args.size()) continue;

                    EvalResult inner = evaluate(args[index], state, id, depth + 1);
                    if (!inner.tainted) {
                        if (inner.was_sanitized) result.was_sanitized = true;
                        continue;
                    }
                    if (!dangerous_for.covers(id)) {
                        // The argument is tainted and comes back out, but the
                        // callee sanitised it for this class.
                        result.was_sanitized = true;
                        continue;
                    }

                    inner.through_summary = true;
                    inner.trace.push_back(
                        {ast::start_line(node), snippet_at(ast::start_line(node), node),
                         std::format("passed through {}() and returned", callee)});
                    return inner;
                }
                return result;
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
                        result.local_source = fact->local;
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
            result.local_source = fact->local;
            return result;
        }
        return EvalResult::clean();
    }

    // ---- Member and subscript expressions ----------------------------------
    if (type == spec_.member_node_type || type == "subscript_expression" ||
        type == "subscript" || type == "index_expression") {
        const std::string dotted = ast::node_text(source_, node);

        if (is_source_for(dotted, id)) {
            const SourceRule* rule = match_source(dotted);
            EvalResult result;
            result.tainted = true;
            result.origin = ast::trim(dotted);
            result.local_source = rule != nullptr && rule->local;
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
                fact.local = flow.local_source;
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

const TaintState& FileAnalyzer::scope_state(int scope, VulnClass id,
                                            const std::vector<AssignmentFact>& all) {
    const auto key = std::make_pair(scope, id);
    if (const auto it = scope_states_.find(key); it != scope_states_.end()) return it->second;

    auto visible = visible_assignments_.find(scope);
    if (visible == visible_assignments_.end()) {
        visible = visible_assignments_.emplace(scope, assignments_visible_in(scope, all)).first;
    }
    return scope_states_.emplace(key, propagate(visible->second, id, TaintState{})).first->second;
}

// ---- Summary computation --------------------------------------------------

std::vector<TSNode> FileAnalyzer::returned_expressions(const FunctionInfo& function) const {
    std::vector<TSNode> out;
    if (ts_node_is_null(function.body)) return out;

    // `(v) => 'SELECT ' + v` and `lambda v: 'SELECT ' + v` have no return
    // statement: the body is the returned value. Looking only for return
    // statements made these look like functions that return nothing, which
    // silently dropped taint at every call to one.
    if (!std::ranges::contains(spec_.block_node_types, ast::node_type(function.body))) {
        out.push_back(function.body);
        return out;
    }

    for (const auto& return_type : spec_.return_node_types) {
        for (TSNode node : ast::find_all(function.body, return_type)) out.push_back(node);
    }
    return out;
}

SummaryPlan FileAnalyzer::plan_summaries() {
    function_facts_.assign(functions_.size(), {});

    std::set<std::string, std::less<>> names;
    for (const auto& function : functions_) names.insert(function.name);

    // The same resolution SummaryTable::resolve applies at a call site: the
    // whole dotted name, then its last segment.
    const auto resolve = [&](std::string_view callee) -> std::string {
        if (callee.empty()) return {};
        if (const auto it = names.find(callee); it != names.end()) return *it;
        const std::string_view segment = ast::last_segment(callee);
        if (const auto it = names.find(segment); it != names.end()) return *it;
        return {};
    };

    SummaryPlan plan;
    plan.callees.resize(functions_.size());
    CallGraph graph;

    for (const auto& [position, function] : std::views::enumerate(functions_)) {
        const auto index = static_cast<std::size_t>(position);
        if (ts_node_is_null(function.body)) continue;

        FunctionFacts& facts = function_facts_[index];
        collect_facts(function.body, facts.assignments, facts.calls);
        facts.returned = returned_expressions(function);

        for (const auto& call : facts.calls) {
            std::string callee = resolve(call.callee);
            if (callee.empty() || std::ranges::contains(plan.callees[index], callee)) continue;
            graph.add_edge(function.name, callee);  // ignores a self-edge; callees keeps it
            plan.callees[index].push_back(std::move(callee));
        }
    }

    // Callees first. The graph only orders functions that take part in a call;
    // the rest depend on nothing and follow in source order.
    std::vector<bool> placed(functions_.size(), false);
    for (const std::string& name : graph.reverse_topological_order()) {
        for (const auto& [position, function] : std::views::enumerate(functions_)) {
            const auto index = static_cast<std::size_t>(position);
            if (!placed[index] && function.name == name) {
                plan.order.push_back(index);
                placed[index] = true;
            }
        }
    }
    for (std::size_t index = 0; index < functions_.size(); ++index) {
        if (!placed[index]) plan.order.push_back(index);
    }
    return plan;
}

FunctionSummary FileAnalyzer::summarize(const FunctionInfo& function) const {
    FunctionSummary summary;
    summary.name = function.name;
    summary.parameter_count = function.parameters.size();

    if (ts_node_is_null(function.body)) return summary;

    // `function` is an element of functions_, which is how its facts are found.
    const FunctionFacts& facts =
        function_facts_[static_cast<std::size_t>(&function - functions_.data())];
    const auto& assignments = facts.assignments;
    const auto& calls = facts.calls;
    const auto& returned = facts.returned;

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

            // Does the parameter reach a sink of this class? One sink per
            // (parameter, class) is enough, so each search stops at its first.
            std::optional<ParamSink> reached;
            const auto record = [&](int line, std::string snippet, std::string holder) {
                reached = ParamSink{index, meta.id, line, std::move(snippet), std::move(holder)};
            };

            // 1. A call sink in this function's own body.
            for (const auto& call : calls) {
                if (call.callee.empty()) continue;
                if (is_source_for(call.callee, meta.id)) continue;

                const SinkMatch match = match_sink_rule(call);
                if (!match || match.rule->vulnerability != meta.id) continue;
                const SinkRule* rule = match.rule;

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
                    record(call.line, snippet_at(call.line, call.node), function.name);
                    break;
                }
            }

            // 2. A property sink in this function's own body: `el.innerHTML = p`.
            if (!reached) {
                for (const auto& assignment : assignments) {
                    if (match_property_sink(assignment, meta.id) == nullptr) continue;
                    if (!evaluate(assignment.rhs, state, meta.id).tainted) continue;
                    record(assignment.line, snippet_at(assignment.line, assignment.node),
                           function.name);
                    break;
                }
            }

            // 3. A sink further down: the parameter is passed to a function
            //    whose own summary says that argument reaches one. This is the
            //    step that makes the analysis transitive -- it is why a chain
            //    of helpers is followed to its end rather than one call deep.
            if (!reached) {
                for (const auto& call : calls) {
                    const FunctionSummary* callee = summary_lookup_->resolve(call.callee);
                    if (callee == nullptr || callee->parameter_sinks.empty()) continue;

                    const auto args = argument_nodes(call.arguments);
                    for (const ParamSink& inner : callee->parameter_sinks) {
                        if (inner.vulnerability != meta.id) continue;
                        if (inner.parameter_index >= args.size()) continue;
                        if (!evaluate(args[inner.parameter_index], state, meta.id).tainted) {
                            continue;
                        }
                        // Keep pointing at the real sink, however far down it is.
                        record(inner.line, inner.sink_snippet,
                               inner.sink_function.empty() ? callee->name : inner.sink_function);
                        break;
                    }
                    if (reached) break;
                }
            }

            if (reached) summary.parameter_sinks.push_back(std::move(*reached));

            // Does the parameter flow out through the return value, still
            // dangerous for this class? Recorded per class: any one path that
            // returns it unsanitised is enough to keep it dangerous.
            const bool returned_tainted = std::ranges::any_of(returned, [&](TSNode node) {
                return evaluate(node, state, meta.id).tainted;
            });
            if (returned_tainted) summary.parameters_returned[index].add(meta.id);
        }

        // Does the function return attacker data with no parameter involved?
        // Checked with an empty seed so a parameter flow does not masquerade
        // as one, and per class for the same reason as above: a helper that
        // returns escapeHtml(req.query.name) is a source for SQL, not for XSS.
        //
        // Taint that arrives through a callee's summary counts. With nothing
        // seeded, the only way a callee can return taint is by reading a
        // source itself, so `return rawId(req)` is a source too.
        if (!class_has_source(meta.id)) continue;  // nothing in this file to return

        const TaintState unseeded = propagate(assignments, meta.id, TaintState{});
        const bool returns_source = std::ranges::any_of(returned, [&](TSNode node) {
            return evaluate(node, unseeded, meta.id).tainted;
        });
        if (returns_source) summary.returns_taint.add(meta.id);
    }

    return summary;
}

// ---- Sink rule matching ---------------------------------------------------

ReceiverType FileAnalyzer::argument_type(const CallFact& call, int index) const {
    const auto args = argument_nodes(call.arguments);
    if (index < 0 || static_cast<std::size_t>(index) >= args.size()) {
        return ReceiverType::Unknown;
    }

    const std::string name = ast::dotted_name(source_, args[static_cast<std::size_t>(index)]);
    if (name.empty()) return ReceiverType::Unknown;

    // A bound name first, then the expression itself -- the same order
    // receiver_type_of uses for a callee's receiver.
    const ReceiverType bound = types_.type_of(name);
    return bound != ReceiverType::Unknown ? bound
                                          : infer_from_expression(name, spec_.type_rules);
}

bool FileAnalyzer::argument_has_key(const CallFact& call, int index, std::string_view key) const {
    const auto args = argument_nodes(call.arguments);
    if (index < 0 || static_cast<std::size_t>(index) >= args.size()) return false;

    for (TSNode entry : ast::named_children(args[static_cast<std::size_t>(index)])) {
        if (!std::ranges::contains(spec_.pair_node_types, ast::node_type(entry))) continue;
        const TSNode name = ast::child_by_field(entry, "key");
        if (ts_node_is_null(name)) continue;

        // `where`, 'where' and "where" are all the same key.
        std::string_view text = ast::node_view(source_, name);
        if (text.size() >= 2 && (text.front() == '\'' || text.front() == '"')) {
            text = text.substr(1, text.size() - 2);
        }
        if (text == key) return true;
    }
    return false;
}

SinkMatch FileAnalyzer::match_sink_rule(const CallFact& call) const {
    SinkMatch best;
    if (call.callee.empty()) return best;

    const std::string_view segment = ast::last_segment(call.callee);

    // Nearly every rule guards on the callee's receiver, so resolve it once.
    // A bare name has no receiver, but may itself have been imported from a
    // typed module: after `from pickle import loads`, `loads` is the pickle one.
    const ReceiverType receiver = ast::receiver_of(call.callee).empty()
                                      ? types_.type_of(call.callee)
                                      : types_.receiver_type_of(call.callee, spec_.type_rules);

    for (const auto& rule : spec_.call_sinks) {
        const bool exact = (rule.callee == call.callee);
        const bool by_segment = !rule.require_full_path && (rule.callee == segment);
        if (!exact && !by_segment) continue;

        const ReceiverType guard =
            rule.typed_argument < 0 ? receiver : argument_type(call, rule.typed_argument);

        // Type guards. By default an unresolved type passes, deliberately: we
        // keep reporting on code shaped in ways the type inference does not
        // model, and downgrade confidence instead of dropping the finding. A
        // strict rule opts out of that, for callees whose name alone says
        // nothing about what they do.
        if (rule.required_receiver != ReceiverType::Unknown) {
            if (guard == ReceiverType::Unknown) {
                if (rule.strict_receiver) continue;
            } else if (guard != rule.required_receiver) {
                continue;
            }
        }
        if (rule.excluded_receiver != ReceiverType::Unknown &&
            guard == rule.excluded_receiver) {
            continue;
        }
        if (!rule.skip_if_argument_has_key.empty() &&
            argument_has_key(call, std::max(rule.tainted_argument, 0),
                             rule.skip_if_argument_has_key)) {
            continue;
        }

        if (!best || (exact && !best.full_path) ||
            rule.callee.size() > best.rule->callee.size()) {
            best = {&rule, guard, exact};
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
        // One propagation per class: a value sanitised for XSS but not SQL has
        // a different taint state depending on which class is being asked
        // about. Only classes with a candidate sink in this scope are worth
        // propagating for, which keeps the cost proportional to the code.
        for (const auto& meta : all_vulnerability_classes()) {
            if (meta.id == VulnClass::Unknown) continue;
            if (!class_has_source(meta.id)) continue;

            std::vector<std::pair<const CallFact*, SinkMatch>> candidates;
            for (const CallFact* call : scope_calls) {
                // A source that happens to share a name with a sink -- Go's
                // r.URL.Query() versus db.Query() -- is not a sink.
                if (is_source_for(call->callee, meta.id)) continue;

                const SinkMatch match = match_sink_rule(*call);
                if (!match || match.rule->vulnerability != meta.id) continue;
                if (ts_node_is_null(call->arguments)) continue;
                candidates.emplace_back(call, match);
            }
            if (candidates.empty()) continue;

            const TaintState& state = scope_state(scope, meta.id, assignments);

            for (const auto& [call, match] : candidates) {
                const SinkRule* rule = match.rule;
                const ReceiverType receiver = match.guard_type;

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
                context.sink_matched_full_path = match.full_path;
                context.partially_sanitized = flow.was_sanitized;
                context.inside_conditional = inside_conditional(call->node);
                context.validator_seen_nearby = validator_nearby(call->node, meta.id);
                context.source_is_local = flow.local_source;

                emit(call->node, meta.id, flow, context, rule->note);
            }
        }
    }
}

const PropertySinkRule* FileAnalyzer::match_property_sink(const AssignmentFact& assignment,
                                                          VulnClass id) const {
    if (spec_.property_sinks.empty() || spec_.member_node_type.empty()) return nullptr;
    if (ast::node_type(assignment.lhs) != spec_.member_node_type) return nullptr;

    const TSNode property = ast::child_by_field(assignment.lhs, spec_.member_property_field);
    if (ts_node_is_null(property)) return nullptr;
    const std::string_view name = ast::node_view(source_, property);

    for (const auto& sink : spec_.property_sinks) {
        if (sink.property != name || sink.vulnerability != id) continue;
        if (sink.required_receiver != ReceiverType::Unknown) {
            const ReceiverType receiver = types_.receiver_type_of(
                ast::dotted_name(source_, assignment.lhs), spec_.type_rules);
            if (receiver != ReceiverType::Unknown && receiver != sink.required_receiver) continue;
        }
        return &sink;
    }
    return nullptr;
}

void FileAnalyzer::match_property_sinks(const std::vector<AssignmentFact>& assignments) {
    if (spec_.property_sinks.empty() || spec_.member_node_type.empty()) return;

    for (const auto& meta : all_vulnerability_classes()) {
        if (meta.id == VulnClass::Unknown) continue;
        if (!class_has_source(meta.id)) continue;
        if (!std::ranges::contains(spec_.property_sinks, meta.id,
                                   &PropertySinkRule::vulnerability)) {
            continue;
        }

        for (const auto& assignment : assignments) {
            const PropertySinkRule* sink = match_property_sink(assignment, meta.id);
            if (sink == nullptr) continue;

            // Scoped like the call sinks: only what this assignment's own
            // function can see. Looked up here, once a sink has actually
            // matched, rather than propagated afresh for every member
            // assignment in the file.
            const TaintState& state = scope_state(assignment.scope, meta.id, assignments);

            const EvalResult flow = evaluate(assignment.rhs, state, meta.id);
            if (!flow.tainted) continue;

            const ReceiverType receiver = types_.receiver_type_of(
                ast::dotted_name(source_, assignment.lhs), spec_.type_rules);

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
            context.source_is_local = flow.local_source;

            emit(assignment.lhs, meta.id, flow, context, sink->note);
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
        for (const auto& meta : all_vulnerability_classes()) {
            if (meta.id == VulnClass::Unknown) continue;
            if (!class_has_source(meta.id)) continue;

            // Only worth a propagation if some callee here actually has a sink
            // of this class behind one of its parameters.
            const bool any_sink = std::ranges::any_of(scope_calls, [&](const CallFact* call) {
                const FunctionSummary* summary = summaries_.resolve(call->callee);
                return summary != nullptr &&
                       std::ranges::contains(summary->parameter_sinks, meta.id,
                                             &ParamSink::vulnerability);
            });
            if (!any_sink) continue;

            const TaintState& state = scope_state(scope, meta.id, assignments);

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
                    const std::string& holder =
                        sink.sink_function.empty() ? summary->name : sink.sink_function;
                    flow.trace.push_back(
                        {sink.line, sink.sink_snippet,
                         holder == summary->name
                             ? std::format("reaches a {} sink inside {}()",
                                           metadata_for(meta.id).name, holder)
                             : std::format("reaches a {} sink inside {}(), which {}() calls",
                                           metadata_for(meta.id).name, holder,
                                           summary->name)});
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
                    context.source_is_local = flow.local_source;

                    emit(call.node, meta.id, flow, context,
                         std::format("the sink is inside {}(), reached through its parameter",
                                     holder));
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

        for (const auto& rule : spec_.configuration_rules) {
            const std::size_t at = text.find(rule.pattern);
            if (at == std::string::npos) continue;

            // Match only when the pattern is near the start of the node, so an
            // enclosing expression does not re-report every nested occurrence.
            if (at > rule.pattern.size() + 32) continue;

            if (rule.needs_security_context && !in_security_context(node)) continue;

            // `subprocess.Popen(cmd, shell=True)` with a tainted cmd has already
            // been reported as a flow into Popen. The shell=True pattern sits
            // inside that same call, on a later line, so the line-based dedupe
            // cannot see it; without this it is counted as a second finding.
            const std::uint32_t position = ts_node_start_byte(node);
            const bool already_reported =
                std::ranges::any_of(reported_spans_, [&](const ReportedSpan& span) {
                    return span.id == rule.vulnerability && position >= span.start &&
                           position < span.end;
                });
            if (already_reported) break;

            // Report the line the pattern is on, not the line the node starts
            // on. A multi-line literal and the entry nested inside it both
            // contain the pattern; anchored to their own start lines they were
            // two findings for one construct, and the (line, class) dedupe
            // could not see that they were the same.
            const int line = ast::start_line(node) +
                             static_cast<int>(std::ranges::count(
                                 std::string_view(text).substr(0, at), '\n'));

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

bool FileAnalyzer::in_security_context(TSNode node) const {
    // Climb to the statement the call sits in: the assignment, declaration,
    // return or object entry that says what its value is for.
    const auto assignment_types = spec_.assignment_node_types();
    TSNode statement = node;
    for (int hops = 0; hops < 8; ++hops) {
        const std::string_view type = ast::node_type(statement);
        if (std::ranges::contains(assignment_types, type) ||
            std::ranges::contains(spec_.return_node_types, type) ||
            std::ranges::contains(spec_.pair_node_types, type) ||
            type.ends_with("statement") || type.ends_with("declaration")) {
            break;
        }
        const TSNode parent = ts_node_parent(statement);
        if (ts_node_is_null(parent)) break;
        statement = parent;
    }

    std::string context = ast::to_lower(ast::node_view(source_, statement).substr(0, 400));
    context += ' ';
    context += ast::to_lower(enclosing_function(node));

    static constexpr std::string_view kTerms[] = {
        "token",  "secret", "password", "passwd",     "pwd",       "salt",
        "nonce",  "otp",    "csrf",     "session",    "apikey",    "api_key",
        "auth",   "credential", "signature", "verification", "reset",
    };
    return std::ranges::any_of(kTerms,
                               [&](std::string_view term) { return context.contains(term); });
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
    if (!emitted_.insert({line, std::to_underlying(id)}).second) return;

    if (suppressions_.suppresses(line, id)) {
        ++suppressed_count_;
        return;
    }

    reported_spans_.push_back({ts_node_start_byte(node), ts_node_end_byte(node), id});

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
    if (!emitted_.insert({line, std::to_underlying(id)}).second) return;

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
                                    spec_.assignment_node_types(), spec_.typed_parameter_forms);

    // 3. Functions and their summaries.
    functions_ = collect_functions(source_, root, spec_.function_definition_node_types,
                                   spec_.function_name_field, spec_.function_parameters_field,
                                   spec_.function_body_field);
    report.functions_analyzed = functions_.size();

    // Must precede any fact collection: scope_of() reads this index, and an
    // unpopulated one would put every fact in module scope.
    index_function_scopes();

    // With no source anywhere in the file nothing can be tainted, so there is
    // nothing for a summary to describe and no flow for a sink to receive.
    // Only the passes that need no dataflow still have work to do.
    const bool taint_possible = !active_sources_.empty();

    if (taint_possible && !functions_.empty()) {
        // While the fixpoint runs, callees resolve against the table being
        // built. That is what lets a wrapper around a wrapper be summarised
        // from the inner one's summary rather than treated as an unknown call.
        const SummaryPlan plan = plan_summaries();
        summaries_ = compute_summaries(
            functions_,
            [this](const FunctionInfo& function, const SummaryTable& known) {
                summary_lookup_ = &known;
                return summarize(function);
            },
            plan);
        summary_lookup_ = &summaries_;
        report.summaries_computed = summaries_.size();
    }

    // 4. Whole-file facts. Analysing the file as one scope rather than
    //    per-function is deliberate: JavaScript closures capture outer
    //    variables, and the express/lambda handler shape puts the source inside
    //    a callback nested in module scope.
    // 5. The detection passes.
    if (taint_possible) {
        std::vector<AssignmentFact> assignments;
        std::vector<CallFact> calls;
        collect_facts(root, assignments, calls);

        match_call_sinks(calls, assignments);
        match_property_sinks(assignments);
        match_interprocedural(calls, assignments);
    }
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

bool looks_minified(std::string_view content) noexcept {
    constexpr std::size_t kMinimumBytes = 8u * 1024u;
    constexpr std::size_t kMeanLineLength = 400;

    if (content.size() < kMinimumBytes) return false;
    const auto lines = static_cast<std::size_t>(std::ranges::count(content, '\n')) + 1;
    return content.size() / lines > kMeanLineLength;
}

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

    if (looks_minified(file.content)) {
        report.language_supported = true;
        report.parsed = false;
        report.skipped_minified = true;
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

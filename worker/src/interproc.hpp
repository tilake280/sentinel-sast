// Interprocedural taint analysis via function summaries.
//
// The README calls this the biggest analysis gap, and it is: an intraprocedural
// engine misses the single most common shape of real vulnerability, where the
// source and the sink live in different functions.
//
//     function runQuery(sql) { return db.query(sql); }        // sink is here
//     app.get('/u', (req, res) => {
//         runQuery("SELECT * FROM u WHERE id = " + req.query.id);  // source is here
//     });
//
// Neither function contains a source-to-sink flow on its own, so the old engine
// reported nothing.
//
// The approach is summary-based rather than whole-program inlining. Each
// function gets a summary describing its taint behaviour at the boundary:
//
//   * which parameters flow to a dangerous sink inside it, and for which class
//   * which parameters flow out through the return value, and for which
//     classes -- a wrapper around html.escape returns its argument clean for
//     XSS and still dirty for SQL
//   * whether it returns attacker-controlled data outright (a source function),
//     again per class
//
// Summaries are computed to a fixpoint over the call graph, because a summary
// for A depends on the summaries of everything A calls: if A passes its
// parameter to B, and B's summary says that parameter reaches a sink, then A's
// does too. Callees are summarised before their callers, so a chain of any
// length settles in one pass; only recursion needs a second. It terminates for
// the same reason the intraprocedural fixpoint does: facts are only ever added,
// never retracted, and the fact space is finite.
//
// What this does not do, by design or by omission:
//
//   * cross files. Summaries are per file. A helper imported from another
//     module has no summary here and is treated as an unknown call.
//   * resolve methods by receiver. A call is matched to a function by name --
//     the full dotted name, then its last segment -- so `a.save()` and
//     `b.save()` are the same function to this engine. Same-named functions
//     share one summary, the union of what each does.
//   * follow functions passed as values. A callback handed to another function
//     is summarised, but the call that eventually invokes it is not connected.
//   * distinguish call sites. A summary is one answer for every caller
//     (context-insensitive).
//
// This module owns the data structures and the fixpoint driver. Computing one
// function's summary needs the full expression evaluator, which lives in
// analyzer.cpp, so that step is injected as a callback -- which also keeps the
// dependency arrow pointing one way.

#pragma once

#include <cstddef>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <tree_sitter/api.h>

#include "taint.hpp"
#include "vulnerability.hpp"

namespace sentinel {

// A function, method or closure found in the file.
struct FunctionInfo {
    std::string name;                       // "runQuery", "Handler.Serve", or "<anonymous:41>"
    std::vector<std::string> parameters;    // positional
    TSNode node{};                          // the definition
    TSNode body{};                          // the block to analyse
    int start_line = 0;
    int end_line = 0;
    bool is_anonymous = false;

    // Nested functions are analysed separately; the parent records them so its
    // own fact collection can prune their bodies and avoid double-counting.
    std::vector<std::size_t> nested;
};

// How a parameter reaches a sink inside a function.
struct ParamSink {
    std::size_t parameter_index = 0;
    VulnClass vulnerability = VulnClass::Unknown;
    int line = 0;              // where the sink call is, for the trace
    std::string sink_snippet;

    // The function whose body holds the sink. For a parameter that reaches the
    // sink through further calls this is the last function in the chain, not
    // the one being summarised, so the trace can say where the sink really is.
    std::string sink_function;
};

// The taint behaviour of one function at its boundary.
struct FunctionSummary {
    std::string name;
    std::size_t parameter_count = 0;

    // Parameter index -> the sinks it reaches. A parameter can reach several.
    std::vector<ParamSink> parameter_sinks;

    // Parameters that flow out through the return value, each with the classes
    // it is still dangerous for when it does. This is per class because a
    // sanitizer is: `function clean(s) { return escapeHtml(s); }` hands its
    // argument back safe to render and exactly as dangerous as before in a SQL
    // string. A single "returns its parameter" bit cannot say that, and made
    // every wrapped sanitizer look like no sanitizer at all.
    std::map<std::size_t, ClassSet> parameters_returned;

    // The classes for which the function returns attacker-controlled data with
    // no parameter involved, e.g. `function getUser() { return req.query.user; }`.
    ClassSet returns_taint;

    // Set once the summary stops changing, purely for diagnostics.
    int iterations_to_settle = 0;

    bool reaches_sink_from(std::size_t parameter_index) const;
    std::vector<ParamSink> sinks_for(std::size_t parameter_index) const;
    // True when the parameter comes back out still dangerous for `id`.
    bool passes_through(std::size_t parameter_index, VulnClass id) const {
        const auto it = parameters_returned.find(parameter_index);
        return it != parameters_returned.end() && it->second.covers(id);
    }

    // Structural equality, so the fixpoint can tell when it has settled.
    bool equivalent_to(const FunctionSummary& other) const;

    // Adds everything `other` does. Used when two functions share a name and
    // a call could mean either: the summary for that name is what either might
    // do, which over-reports rather than letting one definition hide the other.
    void absorb(const FunctionSummary& other);
};

// Name -> summary, with the lookup rules callers need.
class SummaryTable {
public:
    void set(const std::string& name, FunctionSummary summary);

    const FunctionSummary* find(const std::string& name) const;

    // Resolves a call target. Tries the full dotted name, then the last segment,
    // so `helpers.runQuery(x)` finds a summary recorded as `runQuery`.
    const FunctionSummary* resolve(std::string_view dotted_callee) const;

    std::size_t size() const noexcept { return summaries_.size(); }
    bool empty() const noexcept { return summaries_.empty(); }

    auto begin() const { return summaries_.begin(); }
    auto end() const { return summaries_.end(); }

private:
    std::map<std::string, FunctionSummary> summaries_;
};

// Computes one function's summary given what is currently known about the
// others. Supplied by analyzer.cpp, which owns the expression evaluator.
using SummaryComputer =
    std::function<FunctionSummary(const FunctionInfo&, const SummaryTable&)>;

// What the fixpoint needs to know about the call graph: an order to visit the
// functions in, and what each one calls.
struct SummaryPlan {
    // Indices into the function list, callees before callers where the graph
    // allows it. Empty means "as listed".
    std::vector<std::size_t> order;

    // For each function, the names of the functions it calls -- itself
    // included when it recurses. Empty means "unknown": every function is then
    // recomputed on every pass.
    std::vector<std::vector<std::string>> callees;
};

// Drives the summary fixpoint. Returns the settled table.
//
// With a plan, a function is recomputed only when something it calls has
// changed since it was last computed, so an acyclic file costs one pass.
//
// `max_iterations` bounds the passes. After the first, only recursion can
// still be moving; a cycle that has not settled by the bound keeps what it
// had, which under-reports (a missed finding) rather than inventing one.
SummaryTable compute_summaries(const std::vector<FunctionInfo>& functions,
                               const SummaryComputer& compute,
                               const SummaryPlan& plan = {},
                               int max_iterations = 8);

// The call graph edge set, used to order summary computation so callees settle
// before their callers where the graph is acyclic.
class CallGraph {
public:
    void add_edge(const std::string& caller, const std::string& callee);

    const std::set<std::string>& callees_of(const std::string& caller) const;

    // Functions ordered so that, absent cycles, every callee precedes its
    // caller. Cycles are broken arbitrarily -- the fixpoint handles them.
    std::vector<std::string> reverse_topological_order() const;

    std::size_t edge_count() const noexcept { return edge_count_; }

private:
    std::map<std::string, std::set<std::string>> edges_;
    std::size_t edge_count_ = 0;
};

// Extracts every function definition in the tree.
std::vector<FunctionInfo> collect_functions(const std::string& source, TSNode root,
                                            const std::vector<std::string>& definition_node_types,
                                            const std::string& name_field,
                                            const std::string& parameters_field,
                                            const std::string& body_field);

}  // namespace sentinel

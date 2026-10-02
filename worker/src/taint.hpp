// The taint lattice.
//
// The first version of this engine tracked taint as `std::set<std::string>` --
// a variable was dirty or it was not. That is too coarse for two reasons this
// module fixes:
//
//   1. Sanitizers are sink-specific. `html.escape(x)` makes x safe to render but
//      does nothing for SQL. A boolean cannot express "clean for XSS, still
//      dirty for SQL Injection", so the old engine had to ignore sanitizers
//      entirely and over-report.
//
//   2. A finding should show its path. Reporting "SQL injection on line 40" is
//      much less useful than "req.query.id on line 12 -> name on line 13 ->
//      db.query on line 40". That requires carrying provenance alongside the
//      taint rather than recomputing it after the fact.
//
// So a tainted value here is a TaintFact: where it entered, how it got here, and
// which vulnerability classes it has since been neutralised for.

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "vulnerability.hpp"

namespace sentinel {

// One hop in a source -> sink path.
struct TaintStep {
    int line = 0;
    std::string snippet;
    std::string description;  // "user input enters via req.query.id"
};

// The classes a value has been sanitised for, as a bitmask over VulnClass.
// A bitmask rather than a set because these are copied on every propagation
// step and there are fewer than 32 classes.
class SanitizerMask {
public:
    constexpr SanitizerMask() = default;

    constexpr void add(VulnClass id) noexcept {
        bits_ |= bit_for(id);
    }

    constexpr void add_all() noexcept { bits_ = ~std::uint32_t{0}; }

    constexpr bool covers(VulnClass id) const noexcept {
        return (bits_ & bit_for(id)) != 0;
    }

    constexpr bool empty() const noexcept { return bits_ == 0; }

    constexpr SanitizerMask merged_with(const SanitizerMask& other) const noexcept {
        SanitizerMask out;
        // A value is only clean for a class if *every* path to it was cleaned,
        // so merging two inbound flows intersects their masks. Being wrong in
        // this direction over-reports rather than hiding a real bug.
        out.bits_ = bits_ & other.bits_;
        return out;
    }

    constexpr std::uint32_t raw() const noexcept { return bits_; }

    constexpr bool operator==(const SanitizerMask&) const noexcept = default;

private:
    static constexpr std::uint32_t bit_for(VulnClass id) noexcept {
        return std::uint32_t{1} << (std::to_underlying(id) & 31u);
    }

    std::uint32_t bits_ = 0;
};

// The same bitmask read without the "was cleaned" meaning: just a set of
// classes. Function summaries use it to say which classes a value is still
// dangerous for when it leaves a function.
using ClassSet = SanitizerMask;

// Everything known about one tainted value.
struct TaintFact {
    std::string origin;             // the source expression, e.g. "req.query.id"
    std::vector<TaintStep> trace;   // ordered source -> current position
    SanitizerMask sanitized;        // classes this value is no longer dangerous for
    int depth = 0;                  // propagation hops; used to bound the fixpoint
    bool local = false;             // entered from argv/env/stdin, not a remote request

    // True when this value can still cause `id`.
    bool dangerous_for(VulnClass id) const noexcept { return !sanitized.covers(id); }
};

// Maps variable names to what is known about them. Deliberately a flat name map
// rather than an SSA form: the analysis is per-function and the extra precision
// of SSA is not worth the complexity at this scale, but the interface would not
// change if it were added later.
class TaintState {
public:
    // Returns true when this actually changed the state, which is what drives
    // the fixpoint loop's termination.
    bool mark(const std::string& name, TaintFact fact);

    // Records that `name` is now clean for the classes in `mask`.
    bool sanitize(const std::string& name, const SanitizerMask& mask);

    const TaintFact* lookup(const std::string& name) const;

    bool is_tainted(const std::string& name) const;
    bool is_dangerous_for(const std::string& name, VulnClass id) const;

    std::size_t size() const noexcept { return facts_.size(); }
    bool empty() const noexcept { return facts_.empty(); }

    // Iteration for diagnostics and tests.
    auto begin() const { return facts_.begin(); }
    auto end() const { return facts_.end(); }

    void clear() { facts_.clear(); }

private:
    std::map<std::string, TaintFact> facts_;
};

// Builds the fact for a value flowing from `from` into a new binding, appending
// the hop to the trace.
TaintFact propagate(const TaintFact& from, TaintStep step);

// The fact for a value entering at a source.
TaintFact fact_from_source(std::string origin, TaintStep step);

// Merges two inbound flows for the same variable. Keeps the shorter trace (it
// reads better in a report) and intersects the sanitizer masks.
TaintFact merge(const TaintFact& a, const TaintFact& b);

// A propagation chain longer than this is almost certainly a loop artefact
// rather than a real dataflow; bounding it keeps pathological files fast.
inline constexpr int kMaxTaintDepth = 32;

}  // namespace sentinel

#include "taint.hpp"

#include <algorithm>
#include <utility>

namespace sentinel {

bool TaintState::mark(const std::string& name, TaintFact fact) {
    if (name.empty()) return false;
    if (fact.depth > kMaxTaintDepth) return false;

    const auto it = facts_.find(name);
    if (it == facts_.end()) {
        facts_.emplace(name, std::move(fact));
        return true;
    }

    // Already tainted. This is still progress if the new flow is dangerous for
    // a class the existing one had been sanitised for -- otherwise the fixpoint
    // would stop early and miss the unsanitised path.
    const TaintFact merged = merge(it->second, fact);
    const bool widened = merged.sanitized.raw() != it->second.sanitized.raw();
    if (widened) {
        it->second = merged;
        return true;
    }
    return false;
}

bool TaintState::sanitize(const std::string& name, const SanitizerMask& mask) {
    const auto it = facts_.find(name);
    if (it == facts_.end()) return false;

    const std::uint32_t before = it->second.sanitized.raw();
    // Union here, not intersection: applying a sanitizer adds coverage to this
    // particular value. (merged_with intersects, which is the right operation
    // for joining two different inbound flows -- a different question.)
    SanitizerMask widened = it->second.sanitized;
    for (const auto& meta : all_vulnerability_classes()) {
        if (mask.covers(meta.id)) widened.add(meta.id);
    }
    it->second.sanitized = widened;
    return widened.raw() != before;
}

const TaintFact* TaintState::lookup(const std::string& name) const {
    const auto it = facts_.find(name);
    return it == facts_.end() ? nullptr : &it->second;
}

bool TaintState::is_tainted(const std::string& name) const {
    return facts_.find(name) != facts_.end();
}

bool TaintState::is_dangerous_for(const std::string& name, VulnClass id) const {
    const TaintFact* fact = lookup(name);
    return fact != nullptr && fact->dangerous_for(id);
}

TaintFact propagate(const TaintFact& from, TaintStep step) {
    TaintFact out = from;
    out.depth = from.depth + 1;
    // Collapse consecutive steps on the same line: a chain like
    // `a = b = req.query.x` otherwise produces three near-identical hops.
    if (!out.trace.empty() && out.trace.back().line == step.line) {
        out.trace.back() = std::move(step);
    } else {
        out.trace.push_back(std::move(step));
    }
    return out;
}

TaintFact fact_from_source(std::string origin, TaintStep step) {
    TaintFact fact;
    fact.origin = std::move(origin);
    fact.depth = 0;
    fact.trace.push_back(std::move(step));
    return fact;
}

TaintFact merge(const TaintFact& a, const TaintFact& b) {
    TaintFact out;
    out.sanitized = a.sanitized.merged_with(b.sanitized);
    out.depth = std::min(a.depth, b.depth);

    // Prefer whichever path is still dangerous for more classes -- that is the
    // one worth showing a human. Ties break toward the shorter trace.
    const bool a_broader = a.sanitized.raw() == out.sanitized.raw();
    const bool b_broader = b.sanitized.raw() == out.sanitized.raw();

    if (a_broader && !b_broader) {
        out.origin = a.origin;
        out.trace = a.trace;
    } else if (b_broader && !a_broader) {
        out.origin = b.origin;
        out.trace = b.trace;
    } else if (a.trace.size() <= b.trace.size()) {
        out.origin = a.origin;
        out.trace = a.trace;
    } else {
        out.origin = b.origin;
        out.trace = b.trace;
    }
    return out;
}

}  // namespace sentinel

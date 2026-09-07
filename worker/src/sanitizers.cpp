#include "sanitizers.hpp"

#include <algorithm>
#include <utility>

#include "ast.hpp"

namespace sentinel {
namespace {

// Prefers the most specific rule: a dotted rule beats a bare-segment rule, and
// among equals the longer pattern wins. Without this, a generic "escape" rule
// would shadow "html.escape" and clear the wrong classes.
template <typename Rule>
const Rule* lookup(const std::vector<Rule>& rules, std::string_view dotted) {
    if (dotted.empty()) return nullptr;
    const std::string_view segment = ast::last_segment(dotted);

    const Rule* best = nullptr;
    bool best_is_exact = false;

    for (const auto& rule : rules) {
        const bool exact = (rule.callee == dotted);
        const bool by_segment = (rule.callee == segment);
        if (!exact && !by_segment) continue;

        if (best == nullptr) {
            best = &rule;
            best_is_exact = exact;
            continue;
        }
        // An exact full-path match always wins over a segment match.
        if (exact && !best_is_exact) {
            best = &rule;
            best_is_exact = true;
        } else if (exact == best_is_exact && rule.callee.size() > best->callee.size()) {
            best = &rule;
        }
    }
    return best;
}

}  // namespace

SanitizerMask mask_of(const SanitizerRule& rule) {
    SanitizerMask mask;
    if (rule.total) {
        mask.add_all();
        return mask;
    }
    for (const VulnClass id : rule.clears) mask.add(id);
    return mask;
}

SanitizerTable::SanitizerTable(std::vector<SanitizerRule> rules) : rules_(std::move(rules)) {}

const SanitizerRule* SanitizerTable::find(std::string_view dotted_callee) const {
    return lookup(rules_, dotted_callee);
}

SanitizerMask SanitizerTable::mask_for(std::string_view dotted_callee) const {
    const SanitizerRule* rule = find(dotted_callee);
    return rule != nullptr ? mask_of(*rule) : SanitizerMask{};
}

ValidatorTable::ValidatorTable(std::vector<ValidatorRule> rules) : rules_(std::move(rules)) {}

const ValidatorRule* ValidatorTable::find(std::string_view dotted_callee) const {
    return lookup(rules_, dotted_callee);
}

bool ValidatorTable::guards(std::string_view dotted_callee, VulnClass id) const {
    const ValidatorRule* rule = find(dotted_callee);
    if (rule == nullptr) return false;
    if (rule->relevant_to.empty()) return true;  // relevant to everything
    return std::find(rule->relevant_to.begin(), rule->relevant_to.end(), id) !=
           rule->relevant_to.end();
}

}  // namespace sentinel

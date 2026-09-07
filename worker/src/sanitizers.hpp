// Sanitizer modelling.
//
// The README's second-largest known gap: `escape(userInput)` used to stay
// tainted forever, so every properly-defended call site still produced a
// finding. Those are the false positives developers resent most, because the
// code is already correct.
//
// The subtlety that makes this more than a blocklist is that sanitizers are
// *sink-specific*. Neutralising the wrong thing is worse than neutralising
// nothing, because it hides real bugs:
//
//     html.escape(user)        -- safe to render, still lethal in a SQL string
//     shlex.quote(user)        -- safe in a shell, still lethal in HTML
//     parseInt(user, 10)       -- safe everywhere; a number cannot carry a payload
//     path.basename(user)      -- safe as a filename, useless against SQL
//
// So each rule clears a specific set of VulnClasses rather than a boolean, and
// the taint lattice in taint.hpp carries that set per value.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "taint.hpp"
#include "vulnerability.hpp"

namespace sentinel {

struct SanitizerRule {
    std::string callee;             // matched on the full dotted name or last segment
    std::vector<VulnClass> clears;  // the classes this call neutralises
    std::string note;               // shown in the taint trace

    // True when the call neutralises everything -- numeric coercion, hashing,
    // or an allowlist lookup, where the result cannot carry an attacker payload
    // regardless of where it lands.
    bool total = false;
};

class SanitizerTable {
public:
    SanitizerTable() = default;
    explicit SanitizerTable(std::vector<SanitizerRule> rules);

    // Looks up a callee. Tries the full dotted name first so a specific rule
    // ("html.escape") beats a generic one ("escape").
    const SanitizerRule* find(std::string_view dotted_callee) const;

    // The mask a call to `dotted_callee` applies, or an empty mask when the
    // callee is not a sanitizer.
    SanitizerMask mask_for(std::string_view dotted_callee) const;

    bool is_sanitizer(std::string_view dotted_callee) const {
        return find(dotted_callee) != nullptr;
    }

    std::size_t size() const noexcept { return rules_.size(); }
    const std::vector<SanitizerRule>& rules() const noexcept { return rules_; }

private:
    std::vector<SanitizerRule> rules_;
};

// Builds the mask a rule applies.
SanitizerMask mask_of(const SanitizerRule& rule);

// Validators do not transform a value, they reject it -- `if (!isValidId(x))
// return`. Treating one as a sanitizer would need path sensitivity to be sound,
// which this engine does not have, so they are tracked separately and used only
// to lower a finding's confidence rather than to suppress it.
struct ValidatorRule {
    std::string callee;
    std::vector<VulnClass> relevant_to;
};

class ValidatorTable {
public:
    ValidatorTable() = default;
    explicit ValidatorTable(std::vector<ValidatorRule> rules);

    const ValidatorRule* find(std::string_view dotted_callee) const;

    // True when some validator relevant to `id` is called anywhere in the
    // enclosing function. A coarse signal, used only for confidence scoring.
    bool guards(std::string_view dotted_callee, VulnClass id) const;

    std::size_t size() const noexcept { return rules_.size(); }

private:
    std::vector<ValidatorRule> rules_;
};

}  // namespace sentinel

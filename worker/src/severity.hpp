// Severity and confidence scoring.
//
// A flat list of findings is not actionable. A reviewer with an hour needs the
// ones most likely to be both real and serious at the top, and the engine knows
// things that bear on that which the vulnerability class alone does not:
//
//   * a two-hop taint chain in one function is more certain than an eight-hop
//     chain that crosses three function boundaries
//   * a sink whose receiver type was inferred is more certain than one matched
//     on a bare name
//   * a file that failed to parse cleanly produces less trustworthy facts
//   * a validator called nearby suggests the developer already thought about it
//   * a test file is lower impact than a request handler
//
// So severity starts at the class baseline and is adjusted, and confidence is
// computed separately. The two are kept distinct on purpose: a Critical finding
// we are unsure of and a Low finding we are certain of need different handling,
// and collapsing them into one number loses exactly the information a triager
// needs.

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "taint.hpp"
#include "types.hpp"
#include "vulnerability.hpp"

namespace sentinel {

// The inputs to a scoring decision. Assembled by the analyzer at the point a
// finding is emitted.
struct ScoringContext {
    VulnClass vulnerability = VulnClass::Unknown;
    std::size_t trace_length = 1;         // hops from source to sink
    bool crosses_function_boundary = false;
    bool receiver_type_known = false;
    ReceiverType receiver_type = ReceiverType::Unknown;
    bool file_had_parse_errors = false;
    bool in_test_file = false;
    bool validator_seen_nearby = false;
    bool source_is_direct = false;        // the sink argument is the source itself
    bool sink_matched_full_path = false;  // matched `child_process.exec`, not `exec`
    bool partially_sanitized = false;     // some but not all paths were cleaned
    bool inside_conditional = false;      // guarded by an if, so may be unreachable
};

struct Score {
    Severity severity = Severity::Info;
    Confidence confidence = Confidence::Low;

    // Human-readable justification, attached to the finding so a reviewer can
    // see why it sorted where it did rather than trusting an opaque number.
    std::vector<std::string> factors;

    // A single sortable number combining both, for report ordering only.
    int priority() const;
};

// Computes severity and confidence for one finding.
Score score_finding(const ScoringContext& context);

// Orders findings for presentation: highest priority first, then by file and
// line so output is stable across runs.
bool higher_priority(const Score& a, const Score& b);

std::string_view describe(Confidence confidence) noexcept;

}  // namespace sentinel

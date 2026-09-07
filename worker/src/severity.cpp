#include "severity.hpp"

#include <algorithm>
#include <format>

namespace sentinel {
namespace {

// Confidence is computed as a point total rather than a chain of ifs so the
// individual contributions stay visible and tunable.
constexpr int kConfidenceHighThreshold = 5;
constexpr int kConfidenceMediumThreshold = 2;

}  // namespace

int Score::priority() const {
    // Severity dominates, confidence breaks ties. Scaling by 10 leaves room for
    // confidence to matter without ever letting a Low outrank a Critical.
    return static_cast<int>(severity) * 10 + static_cast<int>(confidence);
}

Score score_finding(const ScoringContext& context) {
    const VulnMetadata& meta = metadata_for(context.vulnerability);

    Score score;
    score.severity = meta.baseline;

    int points = 0;

    // ---- Confidence signals ------------------------------------------------

    if (context.source_is_direct) {
        points += 3;
        score.factors.emplace_back("source flows directly into the sink argument");
    } else if (context.trace_length <= 3) {
        points += 2;
        score.factors.push_back(
            std::format("short taint path ({} hops)", context.trace_length));
    } else if (context.trace_length >= 6) {
        points -= 1;
        score.factors.push_back(
            std::format("long taint path ({} hops), more room for a modelling error",
                        context.trace_length));
    }

    if (context.receiver_type_known) {
        points += 2;
        score.factors.push_back(
            std::format("sink receiver resolved as {}", to_string(context.receiver_type)));
    } else {
        points -= 1;
        score.factors.emplace_back(
            "sink matched by name only; receiver type could not be inferred");
    }

    if (context.sink_matched_full_path) {
        points += 1;
        score.factors.emplace_back("sink matched on its fully qualified name");
    }

    if (context.crosses_function_boundary) {
        // Interprocedural findings are real but rest on a summary, which is a
        // step further from the source text than a local flow.
        points -= 1;
        score.factors.emplace_back("flow crosses a function boundary via a summary");
    }

    if (context.file_had_parse_errors) {
        points -= 2;
        score.factors.emplace_back("file did not parse cleanly; facts may be incomplete");
    }

    if (context.validator_seen_nearby) {
        points -= 2;
        score.factors.emplace_back(
            "a validator for this class is called nearby; the input may already be checked");
    }

    if (context.partially_sanitized) {
        points -= 1;
        score.factors.emplace_back("some inbound paths were sanitized, others were not");
    }

    if (context.inside_conditional) {
        points -= 1;
        score.factors.emplace_back("sink is inside a conditional and may be unreachable");
    }

    if (points >= kConfidenceHighThreshold) {
        score.confidence = Confidence::High;
    } else if (points >= kConfidenceMediumThreshold) {
        score.confidence = Confidence::Medium;
    } else {
        score.confidence = Confidence::Low;
    }

    // ---- Severity adjustment ----------------------------------------------
    //
    // Order matters here. Evidence-quality adjustments come first, then
    // reachability. Doing it the other way round lets a strong-evidence bonus
    // cancel the test-path reduction exactly, so a fixture and a request
    // handler score identically -- which defeats the point of the reduction.

    // A direct, fully-resolved flow into a critical sink is the highest-value
    // thing this engine can find; make sure it sorts above everything else.
    if (context.source_is_direct && context.receiver_type_known &&
        !context.crosses_function_boundary &&
        (meta.baseline == Severity::Critical || meta.baseline == Severity::High)) {
        score.severity = raise(score.severity);
        score.factors.emplace_back("unambiguous direct flow into a high-impact sink");
    }

    // Test code is real code, but a vulnerability that only exists in a fixture
    // is not reachable by an attacker in production. Applied last so it always
    // moves the result.
    if (context.in_test_file) {
        score.severity = lower(score.severity);
        score.factors.emplace_back("in a test or fixture path; impact reduced");
    }

    if (score.factors.empty()) {
        score.factors.emplace_back("scored at the class baseline with no adjusting signals");
    }

    return score;
}

bool higher_priority(const Score& a, const Score& b) {
    return a.priority() > b.priority();
}

std::string_view describe(Confidence confidence) noexcept {
    switch (confidence) {
        case Confidence::High:
            return "corroborated by receiver type and a short taint path";
        case Confidence::Medium:
            return "consistent with a real flow, with some modelling uncertainty";
        case Confidence::Low:
            return "plausible but weakly corroborated; verify before acting";
    }
    return "";
}

}  // namespace sentinel

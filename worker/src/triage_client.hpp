// HTTP client for the Python AI triage layer.
//
// The worker asks the triage service whether each finding is a repeat of
// something a human already dismissed. That service is a network dependency in
// the hot path of every finding, so the client has to be deliberate about
// failure: retries with backoff for transient errors, a circuit breaker so a
// hard-down service does not add ten seconds of timeout to every finding, and
// -- most importantly -- failing toward *showing* the finding.
//
// Failing open is the only safe direction here. A triage outage that silently
// suppressed findings would be a security incident; one that shows a few extra
// findings is an inconvenience.

#pragma once

#include <chrono>
#include <cstddef>
#include <expected>
#include <string>

#include "analyzer.hpp"

namespace sentinel {

struct TriageVerdict {
    bool ok = false;           // false when the call failed; caller escalates
    bool suppress = false;
    double confidence = 0.0;
    std::string reason;
    std::string error;
    std::string nearest_snippet;

    // Set when the breaker was open and no request was attempted.
    bool skipped_by_breaker = false;
};

// Why a triage attempt produced no verdict. `retryable` separates a fault that
// might clear on its own (a timeout, a 503) from one that will not (a 4xx, or
// a 200 whose body breaks the contract), so the retry loop does not have to
// re-derive that from a status code it would otherwise need threaded through.
struct TriageError {
    std::string message;
    bool retryable = false;
};

struct TriageStats {
    std::size_t requests = 0;
    std::size_t successes = 0;
    std::size_t failures = 0;
    std::size_t retries = 0;
    std::size_t breaker_trips = 0;
    std::size_t skipped = 0;
    double total_latency_ms = 0.0;

    double mean_latency_ms() const {
        return successes == 0 ? 0.0 : total_latency_ms / static_cast<double>(successes);
    }
};

struct TriageConfig {
    std::string endpoint = "http://localhost:8000/api/v1/triage";
    long timeout_seconds = 10;
    int max_attempts = 3;

    // Consecutive failures before the breaker opens.
    int breaker_threshold = 5;

    // How long the breaker stays open before allowing a probe request.
    std::chrono::seconds breaker_cooldown{30};
};

class TriageClient {
public:
    explicit TriageClient(TriageConfig config);
    explicit TriageClient(std::string endpoint);
    ~TriageClient();

    TriageClient(const TriageClient&) = delete;
    TriageClient& operator=(const TriageClient&) = delete;

    TriageVerdict triage(const Finding& finding);

    // True when the service answered at least once this run.
    bool healthy() const;

    const TriageStats& stats() const noexcept { return stats_; }
    const TriageConfig& config() const noexcept { return config_; }

private:
    bool breaker_open();
    void record_success();
    void record_failure();

    // One HTTP attempt: the raw response body, or why there is not one.
    std::expected<std::string, TriageError> perform(const std::string& body);

    TriageConfig config_;
    void* curl_ = nullptr;
    TriageStats stats_;

    int consecutive_failures_ = 0;
    std::chrono::steady_clock::time_point breaker_opened_at_{};
    bool breaker_is_open_ = false;
};

// Serialises a finding into the triage request payload. Split out so the
// contract with the Python service is testable without a network call.
std::string triage_payload(const Finding& finding);

// Parses a triage response body. Exposed for the same reason. A body that does
// not parse is never retryable: the service would send the same bytes again.
std::expected<TriageVerdict, TriageError> parse_triage_response(const std::string& body);

}  // namespace sentinel

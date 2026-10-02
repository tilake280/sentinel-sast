#include "triage_client.hpp"

#include <curl/curl.h>

#include <chrono>
#include <format>
#include <thread>
#include <utility>

#include <nlohmann/json.hpp>

#include "version.hpp"

using json = nlohmann::json;

namespace sentinel {
namespace {

std::size_t append_body(void* contents, std::size_t size, std::size_t nmemb, void* userp) {
    const std::size_t total = size * nmemb;
    static_cast<std::string*>(userp)->append(static_cast<char*>(contents), total);
    return total;
}

// Exponential backoff with a low ceiling: this sits in the hot path of every
// finding, so a slow retry storm would stall the whole job.
std::chrono::milliseconds backoff_for(int attempt) {
    return std::chrono::milliseconds(50 * (1 << (attempt - 1)));
}

// 5xx and connection errors are worth retrying; 4xx means we sent something the
// service will reject again just as fast.
bool is_retryable(long status) { return status == 0 || status >= 500 || status == 429; }

}  // namespace

std::string triage_payload(const Finding& finding) {
    // The trace is included so the triage layer can eventually embed the whole
    // flow rather than just the sink line. The Python side ignores unknown
    // fields, so adding this did not require a coordinated deploy.
    json trace = json::array();
    for (const auto& step : finding.trace) {
        trace.push_back({{"line", step.line},
                         {"snippet", step.snippet},
                         {"description", step.description}});
    }

    const json payload = {
        {"repository", finding.repository},
        {"file", finding.file},
        {"vulnerability_type", finding.vulnerability_type},
        {"snippet", finding.snippet},
        {"line", finding.line},
        {"rule_id", finding.rule_id},
        {"cwe", finding.cwe},
        {"severity", std::string(to_string(finding.severity))},
        {"confidence", std::string(to_string(finding.confidence))},
        {"taint_source", finding.taint_source},
        {"crosses_function_boundary", finding.crosses_function_boundary},
        {"trace", std::move(trace)},
    };
    return payload.dump();
}

std::expected<TriageVerdict, TriageError> parse_triage_response(const std::string& body) {
    try {
        const json parsed = json::parse(body);

        TriageVerdict verdict;
        verdict.ok = true;
        verdict.suppress = parsed.value("suppress", false);
        verdict.confidence = parsed.value("confidence", 0.0);
        verdict.reason = parsed.value("reason", "");

        if (parsed.contains("nearest_match") && parsed["nearest_match"].is_object()) {
            verdict.nearest_snippet = parsed["nearest_match"].value("snippet", "");
        }
        return verdict;
    } catch (const json::exception& e) {
        return std::unexpected(
            TriageError{std::format("malformed triage response: {}", e.what()), false});
    }
}

TriageClient::TriageClient(TriageConfig config) : config_(std::move(config)) {
    curl_ = curl_easy_init();
}

TriageClient::TriageClient(std::string endpoint) {
    config_.endpoint = std::move(endpoint);
    curl_ = curl_easy_init();
}

TriageClient::~TriageClient() {
    if (curl_ != nullptr) curl_easy_cleanup(static_cast<CURL*>(curl_));
}

bool TriageClient::healthy() const { return stats_.successes > 0 && !breaker_is_open_; }

bool TriageClient::breaker_open() {
    if (!breaker_is_open_) return false;

    const auto elapsed = std::chrono::steady_clock::now() - breaker_opened_at_;
    if (elapsed >= config_.breaker_cooldown) {
        // Half-open: allow a single probe. If it fails, record_failure trips
        // the breaker again immediately.
        breaker_is_open_ = false;
        consecutive_failures_ = config_.breaker_threshold - 1;
        return false;
    }
    return true;
}

void TriageClient::record_success() {
    consecutive_failures_ = 0;
    breaker_is_open_ = false;
    ++stats_.successes;
}

void TriageClient::record_failure() {
    ++stats_.failures;
    ++consecutive_failures_;
    if (consecutive_failures_ >= config_.breaker_threshold && !breaker_is_open_) {
        breaker_is_open_ = true;
        breaker_opened_at_ = std::chrono::steady_clock::now();
        ++stats_.breaker_trips;
    }
}

std::expected<std::string, TriageError> TriageClient::perform(const std::string& body) {
    auto* curl = static_cast<CURL*>(curl_);
    if (curl == nullptr) {
        // No handle means no status either, which is_retryable treats as a
        // transport fault -- the same classification this path always had.
        return std::unexpected(TriageError{"curl handle not initialised", is_retryable(0)});
    }

    std::string response;
    long status = 0;

    curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");
    headers = curl_slist_append(
        headers, std::format("User-Agent: sentinel-worker/{}", kVersion).c_str());
    headers = curl_slist_append(headers, "Accept: application/json");

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, config_.endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, config_.timeout_seconds);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    // Without this, a curl built with signal-based timeouts is not thread-safe.
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    const CURLcode rc = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);

    if (rc != CURLE_OK) {
        return std::unexpected(TriageError{curl_easy_strerror(rc), is_retryable(status)});
    }
    if (status < 200 || status >= 300) {
        return std::unexpected(
            TriageError{std::format("triage layer returned HTTP {}: {}", status, response),
                        is_retryable(status)});
    }
    return response;
}

TriageVerdict TriageClient::triage(const Finding& finding) {
    TriageVerdict verdict;

    if (breaker_open()) {
        ++stats_.skipped;
        verdict.skipped_by_breaker = true;
        verdict.error = "triage circuit breaker is open; escalating without a verdict";
        return verdict;
    }

    const std::string body = triage_payload(finding);
    const auto started = std::chrono::steady_clock::now();

    TriageError last_error;

    for (int attempt = 1; attempt <= config_.max_attempts; ++attempt) {
        ++stats_.requests;

        // Transport and parsing fail differently but lead to the same place, so
        // they are one chain: a body, then a verdict, or the first error.
        const auto outcome = perform(body).and_then(parse_triage_response);
        if (outcome) {
            const auto elapsed = std::chrono::steady_clock::now() - started;
            stats_.total_latency_ms +=
                std::chrono::duration<double, std::milli>(elapsed).count();
            record_success();
            return *outcome;
        }

        last_error = outcome.error();

        // A 200 with a body we cannot parse is a contract violation, not a
        // transient fault -- retrying will produce the same bytes. That, and
        // every 4xx, arrive here marked non-retryable.
        if (attempt < config_.max_attempts && last_error.retryable) {
            ++stats_.retries;
            std::this_thread::sleep_for(backoff_for(attempt));
            continue;
        }
        break;
    }

    record_failure();
    verdict.ok = false;
    verdict.error =
        last_error.message.empty() ? "triage request failed" : std::move(last_error.message);
    return verdict;
}

}  // namespace sentinel

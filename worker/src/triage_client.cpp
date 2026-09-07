#include "triage_client.hpp"

#include <curl/curl.h>

#include <chrono>
#include <format>
#include <thread>
#include <utility>

#include <nlohmann/json.hpp>

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

TriageVerdict parse_triage_response(const std::string& body) {
    TriageVerdict verdict;
    try {
        const json parsed = json::parse(body);
        verdict.ok = true;
        verdict.suppress = parsed.value("suppress", false);
        verdict.confidence = parsed.value("confidence", 0.0);
        verdict.reason = parsed.value("reason", "");

        if (parsed.contains("nearest_match") && parsed["nearest_match"].is_object()) {
            verdict.nearest_snippet = parsed["nearest_match"].value("snippet", "");
        }
    } catch (const json::exception& e) {
        verdict.ok = false;
        verdict.error = std::format("malformed triage response: {}", e.what());
    }
    return verdict;
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

bool TriageClient::perform(const std::string& body, std::string& response, std::string& error,
                           long& status) {
    auto* curl = static_cast<CURL*>(curl_);
    if (curl == nullptr) {
        error = "curl handle not initialised";
        return false;
    }

    response.clear();
    status = 0;

    curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");
    headers = curl_slist_append(headers, "User-Agent: sentinel-worker/0.2.0");
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
        error = curl_easy_strerror(rc);
        return false;
    }
    if (status < 200 || status >= 300) {
        error = std::format("triage layer returned HTTP {}: {}", status, response);
        return false;
    }
    return true;
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

    std::string response;
    std::string error;
    long status = 0;

    for (int attempt = 1; attempt <= config_.max_attempts; ++attempt) {
        ++stats_.requests;

        if (perform(body, response, error, status)) {
            verdict = parse_triage_response(response);
            if (verdict.ok) {
                const auto elapsed = std::chrono::steady_clock::now() - started;
                stats_.total_latency_ms +=
                    std::chrono::duration<double, std::milli>(elapsed).count();
                record_success();
                return verdict;
            }
            // A 200 with a body we cannot parse is a contract violation, not a
            // transient fault -- retrying will produce the same bytes.
            record_failure();
            return verdict;
        }

        if (attempt < config_.max_attempts && is_retryable(status)) {
            ++stats_.retries;
            std::this_thread::sleep_for(backoff_for(attempt));
            continue;
        }
        break;
    }

    record_failure();
    verdict.ok = false;
    verdict.error = error.empty() ? "triage request failed" : error;
    return verdict;
}

}  // namespace sentinel

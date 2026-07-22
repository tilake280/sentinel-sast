#include "triage_client.hpp"

#include <curl/curl.h>

#include <nlohmann/json.hpp>
#include <utility>

using json = nlohmann::json;

namespace sentinel {
namespace {

size_t append_body(void* contents, size_t size, size_t nmemb, void* userp) {
    const size_t total = size * nmemb;
    static_cast<std::string*>(userp)->append(static_cast<char*>(contents), total);
    return total;
}

}  // namespace

TriageClient::TriageClient(std::string endpoint) : endpoint_(std::move(endpoint)) {
    curl_ = curl_easy_init();
}

TriageClient::~TriageClient() {
    if (curl_) curl_easy_cleanup(static_cast<CURL*>(curl_));
}

TriageVerdict TriageClient::triage(const Finding& finding) {
    TriageVerdict verdict;
    auto* curl = static_cast<CURL*>(curl_);
    if (!curl) {
        verdict.error = "curl handle not initialised";
        return verdict;
    }

    const json payload = {{"repository", finding.repository},
                          {"file", finding.file},
                          {"vulnerability_type", finding.vulnerability_type},
                          {"snippet", finding.snippet},
                          {"line", finding.line}};
    const std::string body = payload.dump();
    std::string response;

    curl_slist* headers = curl_slist_append(nullptr, "Content-Type: application/json");

    curl_easy_reset(curl);
    curl_easy_setopt(curl, CURLOPT_URL, endpoint_.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_body);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    const CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);

    if (rc != CURLE_OK) {
        verdict.error = curl_easy_strerror(rc);
        return verdict;
    }
    if (status < 200 || status >= 300) {
        verdict.error = "triage layer returned HTTP " + std::to_string(status) + ": " + response;
        return verdict;
    }

    try {
        const json parsed = json::parse(response);
        verdict.ok = true;
        verdict.suppress = parsed.value("suppress", false);
        verdict.confidence = parsed.value("confidence", 0.0);
        verdict.reason = parsed.value("reason", "");
    } catch (const json::exception& e) {
        verdict.error = std::string("malformed triage response: ") + e.what();
    }
    return verdict;
}

}  // namespace sentinel

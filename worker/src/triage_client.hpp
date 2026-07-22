// Thin libcurl wrapper for asking the Python AI layer to triage a finding.

#pragma once

#include <string>

#include "analyzer.hpp"

namespace sentinel {

struct TriageVerdict {
    bool ok = false;          // false if the call itself failed
    bool suppress = false;
    double confidence = 0.0;
    std::string reason;
    std::string error;
};

class TriageClient {
public:
    explicit TriageClient(std::string endpoint);
    ~TriageClient();

    TriageClient(const TriageClient&) = delete;
    TriageClient& operator=(const TriageClient&) = delete;

    TriageVerdict triage(const Finding& finding);

private:
    std::string endpoint_;
    void* curl_;  // CURL*
};

}  // namespace sentinel

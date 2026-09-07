// A minimal test harness.
//
// Deliberately dependency-free: the analysis core links only against
// Tree-sitter, and the test binary keeps that property so `make test` works on
// a clean checkout with no package manager involved. That matters more than the
// conveniences a real framework would add -- a test suite nobody can run is
// worth nothing.

#pragma once

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace harness {

struct Stats {
    int passed = 0;
    int failed = 0;
    int total() const { return passed + failed; }
};

inline Stats& stats() {
    static Stats instance;
    return instance;
}

inline std::vector<std::string>& failures() {
    static std::vector<std::string> instance;
    return instance;
}

inline bool color_enabled() {
    static const bool enabled = std::getenv("NO_COLOR") == nullptr;
    return enabled;
}

inline std::string_view green() { return color_enabled() ? "\033[32m" : ""; }
inline std::string_view red() { return color_enabled() ? "\033[31m" : ""; }
inline std::string_view dim() { return color_enabled() ? "\033[2m" : ""; }
inline std::string_view bold() { return color_enabled() ? "\033[1m" : ""; }
inline std::string_view reset() { return color_enabled() ? "\033[0m" : ""; }

inline void section(std::string_view title) {
    std::cout << "\n" << bold() << "── " << title << " " << reset() << dim()
              << std::string(title.size() < 56 ? 56 - title.size() : 0, '-') << reset() << "\n";
}

inline void pass(std::string_view label) {
    ++stats().passed;
    std::cout << "  " << green() << "PASS" << reset() << "  " << label << "\n";
}

inline void fail(std::string_view label, std::string_view detail) {
    ++stats().failed;
    failures().emplace_back(std::string(label) + " -- " + std::string(detail));
    std::cout << "  " << red() << "FAIL" << reset() << "  " << label << "\n";
    if (!detail.empty()) {
        std::cout << "        " << dim() << detail << reset() << "\n";
    }
}

inline void check(bool condition, std::string_view label, std::string_view detail = "") {
    if (condition) {
        pass(label);
    } else {
        fail(label, detail);
    }
}

inline int report(std::string_view suite_name, int scans = 0) {
    const Stats& s = stats();

    std::cout << "\n" << bold() << "═══ " << suite_name << " ═══" << reset() << "\n";
    if (scans > 0) {
        std::cout << "  " << scans << " files analysed\n";
    }
    std::cout << "  " << s.total() << " assertions, " << green() << s.passed << " passed"
              << reset();
    if (s.failed > 0) {
        std::cout << ", " << red() << s.failed << " failed" << reset();
    }
    std::cout << "\n";

    if (s.failed > 0) {
        std::cout << "\n" << red() << "Failures:" << reset() << "\n";
        for (const auto& failure : failures()) {
            std::cout << "  - " << failure << "\n";
        }
        std::cout << "\n";
        return 1;
    }

    std::cout << "\n" << green() << "All tests passed." << reset() << "\n\n";
    return 0;
}

}  // namespace harness

// Scan jobs as they arrive off the queue.
//
// A job is untrusted input: it is whatever some publisher put on RabbitMQ. The
// worker used to pull fields out of the JSON inline, which meant a job shaped
// wrongly in a way the JSON library tolerated -- `files` as a string, an entry
// that was not an object -- surfaced as an exception from deep inside the
// processing loop rather than as "this job is malformed".
//
// Parsing is therefore its own step with one outcome: a ScanJob, or the reason
// there is not one. std::expected says exactly that in the signature, where the
// old `bool& ok` out-parameters and half-filled structs could not.
//
// Nothing here touches the broker, so it links into the test binary.

#pragma once

#include <version>

#if !defined(__cpp_lib_expected) || __cpp_lib_expected < 202202L
#error "sentinel-worker needs a C++23 standard library with std::expected (GCC 13 or later)"
#endif

#include <cstddef>
#include <cstdint>
#include <expected>
#include <string>
#include <string_view>
#include <vector>

#include "analyzer.hpp"

namespace sentinel {

struct ScanJob {
    std::string job_id = "-";
    std::string repository = "unknown/repo";
    std::string commit;
    std::vector<SourceFile> files;
};

// Parses a queue message body. A job with no files is valid -- it is an empty
// scan, not a malformed one -- so the only errors are structural.
std::expected<ScanJob, std::string> parse_job(std::string_view body);

// ---- Results ---------------------------------------------------------------

// What the triage layer said about one finding.
//
// Untriaged is its own state rather than a kind of Escalated. The worker fails
// open -- a finding with no verdict is still shown -- but "a human should look
// at this" and "nobody asked the triage layer" are different facts, and a
// count that merged them would overstate how much triage actually ran.
enum class Verdict : std::uint8_t {
    Untriaged,   // no verdict: triage disabled, unreachable, or it failed
    Escalated,   // triaged, and not similar to anything previously dismissed
    Suppressed,  // triaged, and matched a previously dismissed finding
};

std::string_view to_string(Verdict verdict) noexcept;

struct TriagedFinding {
    Finding finding;
    Verdict verdict = Verdict::Untriaged;
    double triage_confidence = 0.0;  // similarity to the nearest dismissed finding
    std::string triage_reason;       // the service's explanation, or why there is none
};

// What happened to one file. Carried in the result so a consumer can count
// files by language, or find the one that failed to parse, from what the worker
// actually did rather than from what it was asked to do.
struct ScannedFile {
    std::string path;
    Language language = Language::Unknown;
    bool parsed = false;
    bool had_parse_errors = false;
    bool skipped_minified = false;
    std::size_t functions = 0;
    std::size_t findings = 0;
    double analysis_ms = 0.0;

    static ScannedFile from(const FileReport& report);
};

// A finished scan: what the worker publishes for the gateway to store, and
// what `--format report` prints.
struct ScanResult {
    std::string job_id = "-";
    std::string repository = "unknown/repo";
    std::string commit;

    // Set when the job could not be processed at all. A failed result carries
    // no findings; it exists so the scan does not stay pending forever.
    bool failed = false;
    std::string error;

    ScanSummary summary;
    std::vector<ScannedFile> files;  // supported files only; skipped ones are counted in summary
    std::vector<TriagedFinding> findings;

    // Folds one file's analysis into the summary and the file list.
    void absorb(const FileReport& report);

    std::size_t count(Verdict verdict) const;
};

// `indent` < 0 gives the compact single-line form used on the queue.
std::string to_json(const ScanResult& result, int indent = -1);

}  // namespace sentinel

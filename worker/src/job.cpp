#include "job.hpp"

#include <algorithm>
#include <format>
#include <utility>

#include <nlohmann/json.hpp>

#include "version.hpp"

using json = nlohmann::json;

namespace sentinel {
namespace {

// A string field that may be absent, but must be a string when present.
std::expected<std::string, std::string> string_field(const json& object, const char* key,
                                                     std::string fallback) {
    const auto it = object.find(key);
    if (it == object.end() || it->is_null()) return fallback;
    if (!it->is_string()) return std::unexpected(std::format("'{}' must be a string", key));
    return it->get<std::string>();
}

std::expected<SourceFile, std::string> parse_file(const json& entry, std::size_t index) {
    if (!entry.is_object()) {
        return std::unexpected(std::format("files[{}] must be an object", index));
    }

    const auto prefix = [index](const std::string& error) {
        return std::format("files[{}]: {}", index, error);
    };

    return string_field(entry, "path", "unknown")
        .and_then([&](std::string path) {
            return string_field(entry, "content", "").transform([&](std::string content) {
                return SourceFile{std::move(path), std::move(content)};
            });
        })
        .transform_error(prefix);
}

}  // namespace

std::expected<ScanJob, std::string> parse_job(std::string_view body) {
    // The non-throwing parse: a malformed body is an expected outcome here, not
    // an exceptional one.
    const json document = json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (document.is_discarded()) return std::unexpected("body is not valid JSON");
    if (!document.is_object()) return std::unexpected("job must be a JSON object");

    ScanJob job;

    auto job_id = string_field(document, "job_id", job.job_id);
    if (!job_id) return std::unexpected(job_id.error());
    job.job_id = std::move(*job_id);

    auto repository = string_field(document, "repository", job.repository);
    if (!repository) return std::unexpected(repository.error());
    job.repository = std::move(*repository);

    auto commit = string_field(document, "commit", "");
    if (!commit) return std::unexpected(commit.error());
    job.commit = std::move(*commit);

    const auto files = document.find("files");
    if (files == document.end() || files->is_null()) return job;
    if (!files->is_array()) return std::unexpected("'files' must be an array");

    job.files.reserve(files->size());
    for (std::size_t index = 0; index < files->size(); ++index) {
        auto file = parse_file((*files)[index], index);
        if (!file) return std::unexpected(file.error());
        job.files.push_back(std::move(*file));
    }
    return job;
}

// ---- Results ---------------------------------------------------------------

std::string_view to_string(Verdict verdict) noexcept {
    switch (verdict) {
        case Verdict::Untriaged: return "UNTRIAGED";
        case Verdict::Escalated: return "ESCALATED";
        case Verdict::Suppressed: return "SUPPRESSED";
    }
    return "UNTRIAGED";
}

ScannedFile ScannedFile::from(const FileReport& report) {
    ScannedFile file;
    file.path = report.path;
    file.language = report.language;
    file.parsed = report.parsed;
    file.had_parse_errors = report.had_parse_errors;
    file.skipped_minified = report.skipped_minified;
    file.functions = report.functions_analyzed;
    file.findings = report.findings.size();
    file.analysis_ms = report.analysis_ms;
    return file;
}

void ScanResult::absorb(const FileReport& report) {
    summary.absorb(report);
    if (report.language_supported) files.push_back(ScannedFile::from(report));
}

std::size_t ScanResult::count(Verdict verdict) const {
    return static_cast<std::size_t>(
        std::ranges::count(findings, verdict, &TriagedFinding::verdict));
}

std::string to_json(const ScanResult& result, int indent) {
    json findings = json::array();
    for (const auto& [finding, verdict, triage_confidence, triage_reason] : result.findings) {
        json trace = json::array();
        for (const auto& step : finding.trace) {
            trace.push_back({{"line", step.line},
                             {"snippet", step.snippet},
                             {"description", step.description}});
        }

        findings.push_back({
            {"file", finding.file},
            {"line", finding.line},
            {"column", finding.column},
            {"vulnerability", finding.vulnerability_type},
            {"class", std::string(metadata_for(finding.vulnerability).slug)},
            {"rule_id", finding.rule_id},
            {"cwe", finding.cwe},
            {"severity", std::string(to_string(finding.severity))},
            {"confidence", std::string(to_string(finding.confidence))},
            {"message", finding.message},
            {"snippet", finding.snippet},
            {"remediation", finding.remediation},
            {"function", finding.function_name},
            {"crosses_function_boundary", finding.crosses_function_boundary},
            {"trace", std::move(trace)},
            {"verdict", std::string(to_string(verdict))},
            {"triage_confidence", triage_confidence},
            {"triage_reason", triage_reason},
        });
    }

    json files = json::array();
    for (const auto& file : result.files) {
        files.push_back({
            {"path", file.path},
            {"language", std::string(to_string(file.language))},
            {"parsed", file.parsed},
            {"had_parse_errors", file.had_parse_errors},
            {"skipped_minified", file.skipped_minified},
            {"functions", file.functions},
            {"findings", file.findings},
            {"analysis_ms", file.analysis_ms},
        });
    }

    const json document = {
        {"job_id", result.job_id},
        {"repository", result.repository},
        {"commit", result.commit},
        {"worker_version", std::string(kVersion)},
        {"status", result.failed ? "FAILED" : "COMPLETED"},
        {"error", result.error},
        {"summary",
         {
             {"files_scanned", result.summary.files_scanned},
             {"files_skipped", result.summary.files_skipped},
             {"files_minified", result.summary.files_minified},
             {"files_with_parse_errors", result.summary.files_with_parse_errors},
             {"functions_analyzed", result.summary.functions_analyzed},
             {"analysis_ms", result.summary.total_ms},
             {"findings", result.findings.size()},
             {"escalated", result.count(Verdict::Escalated)},
             {"suppressed", result.count(Verdict::Suppressed)},
             {"untriaged", result.count(Verdict::Untriaged)},
             {"suppressed_inline", result.summary.suppressed_inline},
         }},
        {"files", std::move(files)},
        {"findings", std::move(findings)},
    };

    // A snippet lifted from a file that is not valid UTF-8 would otherwise make
    // dump() throw and lose the whole result; replace the bad bytes instead.
    return document.dump(indent, ' ', false, json::error_handler_t::replace);
}

}  // namespace sentinel

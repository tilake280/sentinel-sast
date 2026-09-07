#include "sarif.hpp"

#include <algorithm>
#include <format>
#include <map>
#include <set>
#include <sstream>

namespace sentinel {
namespace {

// ANSI colours for the text report. Only emitted when the caller asks, so
// piping the output to a file stays clean.
constexpr std::string_view kReset = "\033[0m";
constexpr std::string_view kBold = "\033[1m";
constexpr std::string_view kDim = "\033[2m";
constexpr std::string_view kRed = "\033[31m";
constexpr std::string_view kYellow = "\033[33m";
constexpr std::string_view kBlue = "\033[34m";
constexpr std::string_view kGrey = "\033[90m";

std::string_view color_for(Severity severity) {
    switch (severity) {
        case Severity::Critical:
        case Severity::High:
            return kRed;
        case Severity::Medium:
            return kYellow;
        case Severity::Low:
            return kBlue;
        case Severity::Info:
            return kGrey;
    }
    return kReset;
}

void append_indent(std::string& out, int depth, bool pretty) {
    if (!pretty) return;
    out.append(static_cast<std::size_t>(depth) * 2, ' ');
}

void append_newline(std::string& out, bool pretty) {
    if (pretty) out.push_back('\n');
}

// Writes `"key": "value"`.
void append_string_field(std::string& out, std::string_view key, std::string_view value,
                         int depth, bool pretty, bool trailing_comma) {
    append_indent(out, depth, pretty);
    out += std::format("\"{}\": \"{}\"", key, json_escape(value));
    if (trailing_comma) out.push_back(',');
    append_newline(out, pretty);
}

void append_int_field(std::string& out, std::string_view key, long long value, int depth,
                      bool pretty, bool trailing_comma) {
    append_indent(out, depth, pretty);
    out += std::format("\"{}\": {}", key, value);
    if (trailing_comma) out.push_back(',');
    append_newline(out, pretty);
}

}  // namespace

std::string json_escape(std::string_view value) {
    std::string out;
    out.reserve(value.size() + 16);

    for (const unsigned char c : value) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) {
                    // Control characters must be escaped as \u00XX. Source code
                    // does contain these -- a stray vertical tab in a string
                    // literal would otherwise produce invalid JSON.
                    out += std::format("\\u{:04x}", static_cast<unsigned>(c));
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    return out;
}

std::string to_sarif(const std::vector<Finding>& findings, const SarifOptions& options) {
    const bool pretty = options.pretty;
    std::string out;
    out.reserve(4096 + findings.size() * 512);

    // Collect the distinct rules actually triggered. SARIF wants each rule
    // declared once in the driver, with results referencing it by id.
    std::map<std::string, const Finding*> rules;
    for (const auto& finding : findings) {
        rules.emplace(finding.rule_id, &finding);
    }

    out += "{";
    append_newline(out, pretty);
    append_string_field(out, "version", "2.1.0", 1, pretty, true);
    append_string_field(out, "$schema",
                        "https://json.schemastore.org/sarif-2.1.0.json", 1, pretty, true);

    append_indent(out, 1, pretty);
    out += "\"runs\": [";
    append_newline(out, pretty);
    append_indent(out, 2, pretty);
    out += "{";
    append_newline(out, pretty);

    // ---- tool.driver ------------------------------------------------------
    append_indent(out, 3, pretty);
    out += "\"tool\": {";
    append_newline(out, pretty);
    append_indent(out, 4, pretty);
    out += "\"driver\": {";
    append_newline(out, pretty);
    append_string_field(out, "name", options.tool_name, 5, pretty, true);
    append_string_field(out, "version", options.tool_version, 5, pretty, true);
    append_string_field(out, "informationUri", options.information_uri, 5, pretty, true);

    append_indent(out, 5, pretty);
    out += "\"rules\": [";
    append_newline(out, pretty);

    std::size_t rule_index = 0;
    for (const auto& [rule_id, sample] : rules) {
        const VulnMetadata& meta = metadata_for(sample->vulnerability);

        append_indent(out, 6, pretty);
        out += "{";
        append_newline(out, pretty);
        append_string_field(out, "id", rule_id, 7, pretty, true);
        append_string_field(out, "name", meta.name, 7, pretty, true);

        append_indent(out, 7, pretty);
        out += std::format("\"shortDescription\": {{\"text\": \"{}\"}},",
                           json_escape(meta.name));
        append_newline(out, pretty);

        append_indent(out, 7, pretty);
        out += std::format("\"fullDescription\": {{\"text\": \"{}\"}},",
                           json_escape(meta.description));
        append_newline(out, pretty);

        append_indent(out, 7, pretty);
        out += std::format("\"help\": {{\"text\": \"{}\"}},", json_escape(meta.remediation));
        append_newline(out, pretty);

        append_indent(out, 7, pretty);
        out += std::format("\"defaultConfiguration\": {{\"level\": \"{}\"}},",
                           sarif_level_for(meta.baseline));
        append_newline(out, pretty);

        // GitHub code scanning reads tags for filtering and the security
        // severity for its own ranking.
        append_indent(out, 7, pretty);
        out += "\"properties\": {";
        append_newline(out, pretty);
        append_indent(out, 8, pretty);
        out += std::format("\"tags\": [\"security\", \"{}\", \"{}\"],", json_escape(meta.cwe),
                           json_escape(meta.slug));
        append_newline(out, pretty);
        append_string_field(out, "precision",
                            sample->confidence == Confidence::High     ? "high"
                            : sample->confidence == Confidence::Medium ? "medium"
                                                                       : "low",
                            8, pretty, true);
        append_string_field(out, "security-severity",
                            std::format("{}.0", static_cast<int>(meta.baseline) * 2), 8, pretty,
                            false);
        append_newline(out, pretty);
        append_indent(out, 7, pretty);
        out += "}";
        append_newline(out, pretty);

        append_indent(out, 6, pretty);
        out += "}";
        if (++rule_index < rules.size()) out.push_back(',');
        append_newline(out, pretty);
    }

    append_indent(out, 5, pretty);
    out += "]";
    append_newline(out, pretty);
    append_indent(out, 4, pretty);
    out += "}";
    append_newline(out, pretty);
    append_indent(out, 3, pretty);
    out += "},";
    append_newline(out, pretty);

    // ---- results ----------------------------------------------------------
    append_indent(out, 3, pretty);
    out += "\"results\": [";
    append_newline(out, pretty);

    for (std::size_t i = 0; i < findings.size(); ++i) {
        const Finding& finding = findings[i];

        append_indent(out, 4, pretty);
        out += "{";
        append_newline(out, pretty);

        append_string_field(out, "ruleId", finding.rule_id, 5, pretty, true);
        append_string_field(out, "level", sarif_level_for(finding.severity), 5, pretty, true);

        append_indent(out, 5, pretty);
        out += std::format("\"message\": {{\"text\": \"{}\"}},", json_escape(finding.message));
        append_newline(out, pretty);

        // Location of the sink.
        append_indent(out, 5, pretty);
        out += "\"locations\": [{";
        append_newline(out, pretty);
        append_indent(out, 6, pretty);
        out += "\"physicalLocation\": {";
        append_newline(out, pretty);
        append_indent(out, 7, pretty);
        out += std::format("\"artifactLocation\": {{\"uri\": \"{}\"}},",
                           json_escape(finding.file));
        append_newline(out, pretty);
        append_indent(out, 7, pretty);
        out += "\"region\": {";
        append_newline(out, pretty);
        append_int_field(out, "startLine", finding.line, 8, pretty, true);
        append_int_field(out, "startColumn", std::max(finding.column, 1), 8, pretty, true);
        append_indent(out, 8, pretty);
        out += std::format("\"snippet\": {{\"text\": \"{}\"}}", json_escape(finding.snippet));
        append_newline(out, pretty);
        append_indent(out, 7, pretty);
        out += "}";
        append_newline(out, pretty);
        append_indent(out, 6, pretty);
        out += "}";
        append_newline(out, pretty);
        append_indent(out, 5, pretty);
        out += "}]";

        // Code flow -- the taint path. This is the part that turns a SARIF
        // upload into something a reviewer can actually follow.
        if (!finding.trace.empty()) {
            out.push_back(',');
            append_newline(out, pretty);
            append_indent(out, 5, pretty);
            out += "\"codeFlows\": [{";
            append_newline(out, pretty);
            append_indent(out, 6, pretty);
            out += "\"threadFlows\": [{";
            append_newline(out, pretty);
            append_indent(out, 7, pretty);
            out += "\"locations\": [";
            append_newline(out, pretty);

            for (std::size_t step = 0; step < finding.trace.size(); ++step) {
                const TaintStep& hop = finding.trace[step];

                append_indent(out, 8, pretty);
                out += "{";
                append_newline(out, pretty);
                append_indent(out, 9, pretty);
                out += "\"location\": {";
                append_newline(out, pretty);
                append_indent(out, 10, pretty);
                out += "\"physicalLocation\": {";
                append_newline(out, pretty);
                append_indent(out, 11, pretty);
                out += std::format("\"artifactLocation\": {{\"uri\": \"{}\"}},",
                                   json_escape(finding.file));
                append_newline(out, pretty);
                append_indent(out, 11, pretty);
                out += std::format("\"region\": {{\"startLine\": {}}}", hop.line);
                append_newline(out, pretty);
                append_indent(out, 10, pretty);
                out += "},";
                append_newline(out, pretty);
                append_indent(out, 10, pretty);
                out += std::format("\"message\": {{\"text\": \"{}\"}}",
                                   json_escape(hop.description));
                append_newline(out, pretty);
                append_indent(out, 9, pretty);
                out += "},";
                append_newline(out, pretty);
                append_int_field(out, "nestingLevel", static_cast<long long>(step), 9, pretty,
                                 false);
                append_indent(out, 8, pretty);
                out += "}";
                if (step + 1 < finding.trace.size()) out.push_back(',');
                append_newline(out, pretty);
            }

            append_indent(out, 7, pretty);
            out += "]";
            append_newline(out, pretty);
            append_indent(out, 6, pretty);
            out += "}]";
            append_newline(out, pretty);
            append_indent(out, 5, pretty);
            out += "}]";
        }

        // Sentinel-specific fields, namespaced under properties as SARIF
        // requires so consumers that do not know them ignore them cleanly.
        out.push_back(',');
        append_newline(out, pretty);
        append_indent(out, 5, pretty);
        out += "\"properties\": {";
        append_newline(out, pretty);
        append_string_field(out, "severity", to_string(finding.severity), 6, pretty, true);
        append_string_field(out, "confidence", to_string(finding.confidence), 6, pretty, true);
        append_string_field(out, "cwe", finding.cwe, 6, pretty, true);
        append_string_field(out, "owasp", finding.owasp, 6, pretty, true);
        append_string_field(out, "taintSource", finding.taint_source, 6, pretty, true);
        append_string_field(out, "remediation", finding.remediation, 6, pretty, true);
        append_indent(out, 6, pretty);
        out += std::format("\"crossesFunctionBoundary\": {}",
                           finding.crosses_function_boundary ? "true" : "false");
        append_newline(out, pretty);
        append_indent(out, 5, pretty);
        out += "}";
        append_newline(out, pretty);

        append_indent(out, 4, pretty);
        out += "}";
        if (i + 1 < findings.size()) out.push_back(',');
        append_newline(out, pretty);
    }

    append_indent(out, 3, pretty);
    out += "]";
    append_newline(out, pretty);
    append_indent(out, 2, pretty);
    out += "}";
    append_newline(out, pretty);
    append_indent(out, 1, pretty);
    out += "]";
    append_newline(out, pretty);
    out += "}";
    append_newline(out, pretty);

    return out;
}

std::string to_text_report(const std::vector<Finding>& findings, bool use_color) {
    const auto paint = [use_color](std::string_view code) -> std::string_view {
        return use_color ? code : std::string_view{};
    };

    std::ostringstream out;

    if (findings.empty()) {
        out << "No findings.\n";
        return out.str();
    }

    std::string current_file;
    for (const auto& finding : findings) {
        if (finding.file != current_file) {
            current_file = finding.file;
            out << "\n" << paint(kBold) << current_file << paint(kReset) << "\n";
        }

        out << "  " << paint(color_for(finding.severity)) << to_string(finding.severity)
            << paint(kReset) << " " << paint(kBold) << finding.vulnerability_type
            << paint(kReset) << " at line " << finding.line << " " << paint(kDim) << "["
            << finding.cwe << ", confidence " << to_string(finding.confidence) << "]"
            << paint(kReset) << "\n";

        out << "    " << paint(kDim) << finding.snippet << paint(kReset) << "\n";

        if (!finding.trace.empty()) {
            out << "    " << paint(kDim) << "taint path:" << paint(kReset) << "\n";
            for (const auto& hop : finding.trace) {
                out << "      " << paint(kDim) << "line " << hop.line << ": " << hop.description
                    << paint(kReset) << "\n";
            }
        }

        if (!finding.remediation.empty()) {
            out << "    " << paint(kDim) << "fix: " << finding.remediation << paint(kReset)
                << "\n";
        }
    }

    return out.str();
}

std::string to_line_report(const std::vector<Finding>& findings) {
    std::ostringstream out;
    for (const auto& finding : findings) {
        out << finding.file << ":" << finding.line << ":" << to_string(finding.severity) << ":"
            << to_string(finding.confidence) << ":" << finding.rule_id << ":"
            << finding.vulnerability_type << "\n";
    }
    return out.str();
}

}  // namespace sentinel

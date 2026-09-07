// Sentinel SAST analysis worker.
//
// Two modes:
//
//   sentinel-worker                      consume scan jobs from RabbitMQ
//   sentinel-worker --scan <path>        scan a file or directory locally
//
// The local mode exists so the engine is usable and demonstrable without any
// infrastructure at all -- no broker, no database, no triage service. That is
// what makes it runnable in CI as a plain binary, and it is the mode the
// demo script drives.

#if __has_include(<rabbitmq-c/amqp.h>)
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/framing.h>
#include <rabbitmq-c/tcp_socket.h>
#else
#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

#include "analyzer.hpp"
#include "sarif.hpp"
#include "triage_client.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;

namespace {

// ---- Shutdown handling ----------------------------------------------------

// Set from a signal handler, so it must be lock-free and nothing else may be
// done in the handler itself.
std::atomic<bool> g_shutdown_requested{false};

extern "C" void handle_signal(int) { g_shutdown_requested.store(true); }

void install_signal_handlers() {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
#ifdef SIGPIPE
    // A triage service dropping the connection mid-write must not kill the
    // worker; curl reports the error instead.
    std::signal(SIGPIPE, SIG_IGN);
#endif
}

// ---- Configuration --------------------------------------------------------

std::string env_or(const char* key, std::string fallback) {
    const char* value = std::getenv(key);
    return (value != nullptr && *value != '\0') ? std::string(value) : std::move(fallback);
}

int env_int(const char* key, int fallback) {
    const char* value = std::getenv(key);
    if (value == nullptr || *value == '\0') return fallback;
    try {
        return std::stoi(value);
    } catch (const std::exception&) {
        std::cerr << std::format("[worker] {} is not a number; using {}\n", key, fallback);
        return fallback;
    }
}

enum class OutputFormat { Text, Sarif, Line, Json };

struct Options {
    bool worker_mode = true;
    std::string scan_path;
    OutputFormat format = OutputFormat::Text;
    std::string output_file;
    sentinel::Severity fail_on = sentinel::Severity::Info;
    bool fail_on_set = false;
    bool use_triage = true;
    bool show_rules = false;
    bool show_help = false;
    bool show_version = false;
    bool quiet = false;
    bool no_color = false;
};

constexpr std::string_view kVersion = "0.2.0";

void print_help() {
    std::cout << R"(Sentinel SAST analysis worker

USAGE
  sentinel-worker                       Consume scan jobs from RabbitMQ (default)
  sentinel-worker --scan <path>         Scan a file or directory locally
  sentinel-worker --rules               Print ruleset statistics and exit

SCAN OPTIONS
  --scan <path>          File or directory to analyse
  --format <fmt>         text (default), sarif, line, json
  --output <file>        Write the report to a file instead of stdout
  --fail-on <severity>   Exit non-zero if any finding is at or above this level
                         (info, low, medium, high, critical)
  --no-triage            Skip the AI triage layer entirely
  --quiet                Suppress progress output
  --no-color             Disable ANSI colour

GENERAL
  --version              Print the version and exit
  --help                 Print this message

ENVIRONMENT
  RABBITMQ_HOST, RABBITMQ_PORT, RABBITMQ_USER, RABBITMQ_PASSWORD
  SCAN_QUEUE             Queue name (default: scan_jobs)
  TRIAGE_URL             AI triage endpoint (default: http://localhost:8000/api/v1/triage)

EXIT CODES
  0  success, and no finding met the --fail-on threshold
  1  a finding met the --fail-on threshold
  2  a configuration or connection error
)";
}

sentinel::Severity parse_severity(std::string_view value, bool& ok) {
    ok = true;
    if (value == "info") return sentinel::Severity::Info;
    if (value == "low") return sentinel::Severity::Low;
    if (value == "medium") return sentinel::Severity::Medium;
    if (value == "high") return sentinel::Severity::High;
    if (value == "critical") return sentinel::Severity::Critical;
    ok = false;
    return sentinel::Severity::Info;
}

// Returns false when parsing failed; the error is already printed.
bool parse_arguments(int argc, char** argv, Options& options) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view argument = argv[i];

        const auto next = [&](std::string_view name) -> const char* {
            if (i + 1 >= argc) {
                std::cerr << std::format("[worker] {} requires a value\n", name);
                return nullptr;
            }
            return argv[++i];
        };

        if (argument == "--help" || argument == "-h") {
            options.show_help = true;
        } else if (argument == "--version" || argument == "-V") {
            options.show_version = true;
        } else if (argument == "--rules") {
            options.show_rules = true;
        } else if (argument == "--quiet" || argument == "-q") {
            options.quiet = true;
        } else if (argument == "--no-color") {
            options.no_color = true;
        } else if (argument == "--no-triage") {
            options.use_triage = false;
        } else if (argument == "--scan") {
            const char* value = next("--scan");
            if (value == nullptr) return false;
            options.scan_path = value;
            options.worker_mode = false;
        } else if (argument == "--output" || argument == "-o") {
            const char* value = next("--output");
            if (value == nullptr) return false;
            options.output_file = value;
        } else if (argument == "--format" || argument == "-f") {
            const char* value = next("--format");
            if (value == nullptr) return false;
            const std::string_view format = value;
            if (format == "text") {
                options.format = OutputFormat::Text;
            } else if (format == "sarif") {
                options.format = OutputFormat::Sarif;
            } else if (format == "line") {
                options.format = OutputFormat::Line;
            } else if (format == "json") {
                options.format = OutputFormat::Json;
            } else {
                std::cerr << std::format("[worker] unknown format '{}'\n", format);
                return false;
            }
        } else if (argument == "--fail-on") {
            const char* value = next("--fail-on");
            if (value == nullptr) return false;
            bool ok = false;
            options.fail_on = parse_severity(value, ok);
            options.fail_on_set = true;
            if (!ok) {
                std::cerr << std::format("[worker] unknown severity '{}'\n", value);
                return false;
            }
        } else {
            std::cerr << std::format("[worker] unknown argument '{}'\n", argument);
            return false;
        }
    }
    return true;
}

// ---- Ruleset diagnostics --------------------------------------------------

void print_rules() {
    std::cout << std::format("Sentinel SAST {} — ruleset\n\n", kVersion);
    std::cout << std::format("  {} vulnerability classes\n",
                             sentinel::all_vulnerability_classes().size() - 1);
    std::cout << std::format("  {} total rules across {} languages\n\n",
                             sentinel::total_rule_count(),
                             sentinel::supported_languages().size());

    std::cout << "  Languages:\n";
    for (const auto language : sentinel::supported_languages()) {
        const auto* spec = sentinel::spec_for(language);
        if (spec == nullptr) continue;
        std::cout << std::format(
            "    {:<12} {:>3} sources  {:>3} sinks  {:>3} sanitizers  {:>3} type rules\n",
            spec->name, spec->sources.size(),
            spec->call_sinks.size() + spec->property_sinks.size(), spec->sanitizers.size(),
            spec->type_rules.size());
    }

    std::cout << "\n  Vulnerability classes:\n";
    for (const auto& meta : sentinel::all_vulnerability_classes()) {
        if (meta.id == sentinel::VulnClass::Unknown) continue;
        std::cout << std::format("    {:<28} {:<10} {}\n", meta.name, meta.cwe,
                                 sentinel::to_string(meta.baseline));
    }
    std::cout << "\n";
}

// ---- Local scanning -------------------------------------------------------

// Directories that are never worth scanning. Walking node_modules turns a
// two-second scan into a two-minute one and produces findings nobody will fix.
bool is_excluded_directory(const std::string& name) {
    static const std::vector<std::string> kExcluded = {
        "node_modules", ".git",   "vendor",  "third_party", "dist",
        "build",        "target", "__pycache__", ".venv",   "venv",
        ".next",        "coverage", ".mypy_cache", ".pytest_cache",
    };
    return std::find(kExcluded.begin(), kExcluded.end(), name) != kExcluded.end();
}

std::string read_file(const fs::path& path, bool& ok) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) {
        ok = false;
        return {};
    }
    std::ostringstream buffer;
    buffer << stream.rdbuf();
    ok = true;
    return buffer.str();
}

std::vector<fs::path> collect_scan_targets(const fs::path& root, bool& ok) {
    std::vector<fs::path> targets;
    ok = true;

    std::error_code error;
    if (!fs::exists(root, error)) {
        std::cerr << std::format("[worker] path does not exist: {}\n", root.string());
        ok = false;
        return targets;
    }

    if (fs::is_regular_file(root, error)) {
        targets.push_back(root);
        return targets;
    }

    // recursive_directory_iterator with the skip_permission_denied option, so a
    // single unreadable directory does not abort the whole scan.
    fs::recursive_directory_iterator it(
        root, fs::directory_options::skip_permission_denied, error);
    if (error) {
        std::cerr << std::format("[worker] cannot walk {}: {}\n", root.string(),
                                 error.message());
        ok = false;
        return targets;
    }

    for (fs::recursive_directory_iterator end; it != end; it.increment(error)) {
        if (error) {
            error.clear();
            continue;
        }
        const fs::path& path = it->path();

        if (it->is_directory(error)) {
            if (is_excluded_directory(path.filename().string())) {
                it.disable_recursion_pending();
            }
            continue;
        }

        if (!it->is_regular_file(error)) continue;
        if (sentinel::language_for_path(path.string()) == sentinel::Language::Unknown) continue;
        targets.push_back(path);
    }

    std::sort(targets.begin(), targets.end());
    return targets;
}

int run_local_scan(const Options& options) {
    const fs::path root(options.scan_path);

    bool ok = false;
    const auto targets = collect_scan_targets(root, ok);
    if (!ok) return 2;

    if (!options.quiet) {
        std::cerr << std::format("[scan] {} file(s) under {}\n", targets.size(), root.string());
    }

    std::vector<sentinel::Finding> all_findings;
    sentinel::ScanSummary summary;

    for (const auto& path : targets) {
        if (g_shutdown_requested.load()) {
            std::cerr << "[scan] interrupted\n";
            break;
        }

        bool read_ok = false;
        const std::string content = read_file(path, read_ok);
        if (!read_ok) {
            if (!options.quiet) {
                std::cerr << std::format("[scan] skipping unreadable file: {}\n", path.string());
            }
            continue;
        }

        // Report paths relative to the scan root so output is stable across
        // machines and diffable between runs.
        std::error_code relative_error;
        fs::path display = fs::relative(path, fs::is_directory(root) ? root : root.parent_path(),
                                        relative_error);
        if (relative_error) display = path;

        const auto report =
            sentinel::analyze_file_detailed("local", {display.string(), content});
        summary.absorb(report);

        for (const auto& finding : report.findings) {
            all_findings.push_back(finding);
        }

        if (!options.quiet && !report.stale_suppressions.empty()) {
            std::cerr << std::format("[scan] {}: {} stale suppression(s)\n", display.string(),
                                     report.stale_suppressions.size());
        }
    }

    sentinel::sort_findings(all_findings);

    // Optional triage pass.
    std::size_t suppressed_by_ai = 0;
    if (options.use_triage && !all_findings.empty()) {
        sentinel::TriageConfig config;
        config.endpoint = env_or("TRIAGE_URL", "http://localhost:8000/api/v1/triage");
        sentinel::TriageClient triage(config);

        std::vector<sentinel::Finding> kept;
        kept.reserve(all_findings.size());

        for (auto& finding : all_findings) {
            const auto verdict = triage.triage(finding);
            if (verdict.ok && verdict.suppress) {
                ++suppressed_by_ai;
                continue;
            }
            kept.push_back(std::move(finding));
        }

        if (triage.stats().successes == 0 && !options.quiet) {
            std::cerr << "[scan] triage layer unreachable; all findings escalated\n";
        }
        all_findings = std::move(kept);
    }

    // Render.
    std::string rendered;
    switch (options.format) {
        case OutputFormat::Text:
            rendered = sentinel::to_text_report(all_findings, !options.no_color &&
                                                                  options.output_file.empty());
            break;
        case OutputFormat::Sarif: {
            sentinel::SarifOptions sarif_options;
            sarif_options.tool_version = std::string(kVersion);
            sarif_options.repository = root.string();
            rendered = sentinel::to_sarif(all_findings, sarif_options);
            break;
        }
        case OutputFormat::Line:
            rendered = sentinel::to_line_report(all_findings);
            break;
        case OutputFormat::Json: {
            json out = json::array();
            for (const auto& finding : all_findings) {
                json trace = json::array();
                for (const auto& step : finding.trace) {
                    trace.push_back({{"line", step.line}, {"description", step.description}});
                }
                out.push_back({{"file", finding.file},
                               {"line", finding.line},
                               {"rule_id", finding.rule_id},
                               {"vulnerability", finding.vulnerability_type},
                               {"severity", std::string(to_string(finding.severity))},
                               {"confidence", std::string(to_string(finding.confidence))},
                               {"cwe", finding.cwe},
                               {"message", finding.message},
                               {"snippet", finding.snippet},
                               {"remediation", finding.remediation},
                               {"trace", std::move(trace)}});
            }
            rendered = out.dump(2);
            break;
        }
    }

    if (options.output_file.empty()) {
        std::cout << rendered;
    } else {
        std::ofstream out(options.output_file);
        if (!out) {
            std::cerr << std::format("[scan] cannot write {}\n", options.output_file);
            return 2;
        }
        out << rendered;
        if (!options.quiet) {
            std::cerr << std::format("[scan] report written to {}\n", options.output_file);
        }
    }

    if (!options.quiet) {
        std::cerr << std::format(
            "\n[scan] {} file(s), {} finding(s) in {:.1f}ms"
            " — {} critical, {} high, {} medium, {} low\n",
            summary.files_scanned, all_findings.size(), summary.total_ms,
            summary.by_severity[static_cast<int>(sentinel::Severity::Critical)],
            summary.by_severity[static_cast<int>(sentinel::Severity::High)],
            summary.by_severity[static_cast<int>(sentinel::Severity::Medium)],
            summary.by_severity[static_cast<int>(sentinel::Severity::Low)]);

        if (summary.suppressed_inline > 0) {
            std::cerr << std::format("[scan] {} suppressed by inline directives\n",
                                     summary.suppressed_inline);
        }
        if (suppressed_by_ai > 0) {
            std::cerr << std::format("[scan] {} suppressed by AI triage\n", suppressed_by_ai);
        }
        if (summary.files_with_parse_errors > 0) {
            std::cerr << std::format("[scan] {} file(s) had parse errors\n",
                                     summary.files_with_parse_errors);
        }
    }

    // CI gate.
    if (options.fail_on_set) {
        for (const auto& finding : all_findings) {
            if (static_cast<int>(finding.severity) >= static_cast<int>(options.fail_on)) {
                if (!options.quiet) {
                    std::cerr << std::format("[scan] failing: {} finding at or above {}\n",
                                             to_string(finding.severity),
                                             to_string(options.fail_on));
                }
                return 1;
            }
        }
    }

    return 0;
}

// ---- Worker mode ----------------------------------------------------------

bool check_reply(const amqp_rpc_reply_t& reply, std::string_view context) {
    switch (reply.reply_type) {
        case AMQP_RESPONSE_NORMAL:
            return true;
        case AMQP_RESPONSE_NONE:
            std::cerr << std::format("[worker] {}: missing RPC reply\n", context);
            return false;
        case AMQP_RESPONSE_LIBRARY_EXCEPTION:
            std::cerr << std::format("[worker] {}: {}\n", context,
                                     amqp_error_string2(reply.library_error));
            return false;
        case AMQP_RESPONSE_SERVER_EXCEPTION:
            std::cerr << std::format("[worker] {}: server exception ({})\n", context,
                                     reply.reply.id);
            return false;
    }
    return false;
}

void process_job(const std::string& body, sentinel::TriageClient& triage, bool use_triage) {
    json job;
    try {
        job = json::parse(body);
    } catch (const json::exception& e) {
        std::cerr << std::format("[worker] skipping malformed job: {}\n", e.what());
        return;
    }

    const std::string repository = job.value("repository", "unknown/repo");
    const std::string job_id = job.value("job_id", "-");
    std::cout << std::format("\n[worker] job {} for {}\n", job_id, repository);

    std::vector<sentinel::SourceFile> files;
    for (const auto& entry : job.value("files", json::array())) {
        files.push_back({entry.value("path", "unknown"), entry.value("content", "")});
    }
    if (files.empty()) {
        std::cout << "[worker] job contained no files\n";
        return;
    }

    sentinel::ScanSummary summary;
    std::size_t suppressed = 0;
    std::size_t escalated = 0;
    std::size_t triage_failures = 0;

    for (const auto& file : files) {
        const auto report = sentinel::analyze_file_detailed(repository, file);
        summary.absorb(report);

        if (!report.language_supported) {
            std::cout << std::format("[worker] skipping unsupported file: {}\n", file.path);
            continue;
        }

        std::cout << std::format("[worker] parsed {} ({}, {} function(s), {:.1f}ms)\n", file.path,
                                 sentinel::to_string(report.language),
                                 report.functions_analyzed, report.analysis_ms);

        if (report.had_parse_errors) {
            std::cout << "[worker]   note: file had parse errors; confidence downgraded\n";
        }

        for (const auto& finding : report.findings) {
            std::cout << std::format("[worker]   {} {} at {}:{}\n",
                                     sentinel::to_string(finding.severity),
                                     finding.vulnerability_type, finding.file, finding.line);
            std::cout << std::format("[worker]     {}\n", finding.snippet);

            if (finding.trace.size() > 1) {
                std::cout << std::format("[worker]     taint path ({} hops):\n",
                                         finding.trace.size());
                for (const auto& step : finding.trace) {
                    std::cout << std::format("[worker]       line {}: {}\n", step.line,
                                             step.description);
                }
            }

            if (!use_triage) {
                ++escalated;
                continue;
            }

            const auto verdict = triage.triage(finding);
            if (!verdict.ok) {
                ++triage_failures;
                ++escalated;
                std::cerr << std::format("[worker]     TRIAGE FAILED: {} (escalating)\n",
                                         verdict.error);
                continue;
            }

            if (verdict.suppress) {
                ++suppressed;
                std::cout << std::format("[worker]     SUPPRESSED ({:.4f}) {}\n",
                                         verdict.confidence, verdict.reason);
            } else {
                ++escalated;
                std::cout << std::format("[worker]     ESCALATED ({:.4f}) {}\n",
                                         verdict.confidence, verdict.reason);
            }
        }
    }

    std::cout << std::format(
        "[worker] job {} complete: {} file(s), {} finding(s), {} suppressed by AI, "
        "{} escalated",
        job_id, summary.files_scanned, summary.total_findings, suppressed, escalated);
    if (summary.suppressed_inline > 0) {
        std::cout << std::format(", {} suppressed inline", summary.suppressed_inline);
    }
    if (triage_failures > 0) {
        std::cout << std::format(", {} triage failure(s)", triage_failures);
    }
    std::cout << "\n";
}

// Returns 0 on a clean shutdown, 2 on a connection error.
int run_worker(const Options& options) {
    const std::string host = env_or("RABBITMQ_HOST", "localhost");
    const int port = env_int("RABBITMQ_PORT", 5672);
    const std::string user = env_or("RABBITMQ_USER", "guest");
    const std::string password = env_or("RABBITMQ_PASSWORD", "guest");
    const std::string queue_name = env_or("SCAN_QUEUE", "scan_jobs");

    sentinel::TriageConfig triage_config;
    triage_config.endpoint = env_or("TRIAGE_URL", "http://localhost:8000/api/v1/triage");
    sentinel::TriageClient triage(triage_config);

    std::cout << std::format("[worker] Sentinel analysis worker {} online\n", kVersion);
    std::cout << std::format("[worker] ruleset  : {} rules, {} vulnerability classes\n",
                             sentinel::total_rule_count(),
                             sentinel::all_vulnerability_classes().size() - 1);
    std::cout << std::format("[worker] queue    : {} @ {}:{}\n", queue_name, host, port);
    std::cout << std::format("[worker] triage   : {}{}\n", triage_config.endpoint,
                             options.use_triage ? "" : " (disabled)");

    // Reconnect loop. A broker restart should not require restarting the
    // worker, which in a container means avoiding a crash-loop backoff.
    int reconnect_delay = 1;

    while (!g_shutdown_requested.load()) {
        amqp_connection_state_t conn = amqp_new_connection();
        amqp_socket_t* socket = amqp_tcp_socket_new(conn);

        const auto teardown = [&conn]() {
            amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
            amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
            amqp_destroy_connection(conn);
        };

        if (socket == nullptr) {
            std::cerr << "[worker] failed to create TCP socket\n";
            amqp_destroy_connection(conn);
            return 2;
        }

        if (amqp_socket_open(socket, host.c_str(), port) != AMQP_STATUS_OK) {
            std::cerr << std::format("[worker] cannot reach RabbitMQ at {}:{}; retrying in {}s\n",
                                     host, port, reconnect_delay);
            amqp_destroy_connection(conn);

            // Sleep in short slices so a shutdown signal is not ignored for the
            // whole backoff window.
            for (int slept = 0; slept < reconnect_delay && !g_shutdown_requested.load();
                 ++slept) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            reconnect_delay = std::min(reconnect_delay * 2, 30);
            continue;
        }

        if (!check_reply(amqp_login(conn, "/", 0, AMQP_DEFAULT_FRAME_SIZE, 0,
                                    AMQP_SASL_METHOD_PLAIN, user.c_str(), password.c_str()),
                         "login")) {
            amqp_destroy_connection(conn);
            return 2;  // bad credentials will not fix themselves
        }

        amqp_channel_open(conn, 1);
        if (!check_reply(amqp_get_rpc_reply(conn), "channel open")) {
            amqp_destroy_connection(conn);
            return 2;
        }

        // durable=1 so jobs survive a broker restart; must match the publisher.
        amqp_queue_declare(conn, 1, amqp_cstring_bytes(queue_name.c_str()), 0, 1, 0, 0,
                           amqp_empty_table);
        if (!check_reply(amqp_get_rpc_reply(conn), "queue declare")) {
            teardown();
            return 2;
        }

        // One unacked message at a time, so work spreads across workers.
        amqp_basic_qos(conn, 1, 0, 1, 0);
        if (!check_reply(amqp_get_rpc_reply(conn), "basic qos")) {
            teardown();
            return 2;
        }

        // no_ack=0: we ack manually once the job is fully processed, so a crash
        // mid-job redelivers rather than losing the work.
        amqp_basic_consume(conn, 1, amqp_cstring_bytes(queue_name.c_str()), amqp_empty_bytes, 0,
                           0, 0, amqp_empty_table);
        if (!check_reply(amqp_get_rpc_reply(conn), "basic consume")) {
            teardown();
            return 2;
        }

        std::cout << "[worker] connected; waiting for scan jobs...\n";
        reconnect_delay = 1;

        while (!g_shutdown_requested.load()) {
            amqp_maybe_release_buffers(conn);

            // A bounded wait rather than a blocking one, so the shutdown flag
            // is checked regularly instead of only when a job arrives.
            timeval timeout{};
            timeout.tv_sec = 1;
            timeout.tv_usec = 0;

            amqp_envelope_t envelope;
            const amqp_rpc_reply_t reply = amqp_consume_message(conn, &envelope, &timeout, 0);

            if (reply.reply_type == AMQP_RESPONSE_LIBRARY_EXCEPTION &&
                reply.library_error == AMQP_STATUS_TIMEOUT) {
                continue;  // idle tick
            }

            if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
                check_reply(reply, "consume");
                break;  // fall out to the reconnect loop
            }

            const std::string body(static_cast<char*>(envelope.message.body.bytes),
                                   envelope.message.body.len);

            try {
                process_job(body, triage, options.use_triage);
            } catch (const std::exception& e) {
                // A single bad job must not take down the worker. Ack it so it
                // is not redelivered forever into the same crash.
                std::cerr << std::format("[worker] job failed: {}\n", e.what());
            }

            amqp_basic_ack(conn, 1, envelope.delivery_tag, 0);
            amqp_destroy_envelope(&envelope);
        }

        teardown();
    }

    const auto& stats = triage.stats();
    std::cout << std::format(
        "\n[worker] shutting down. triage: {} request(s), {} ok, {} failed, "
        "{} retried, mean {:.1f}ms\n",
        stats.requests, stats.successes, stats.failures, stats.retries,
        stats.mean_latency_ms());

    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    // Line-buffered stdout would still hide progress behind a redirect, and this
    // process spends most of its life blocked on the broker. Flush every write
    // so logs are live under systemd and docker.
    std::cout << std::unitbuf;

    Options options;
    if (!parse_arguments(argc, argv, options)) return 2;

    if (options.show_help) {
        print_help();
        return 0;
    }
    if (options.show_version) {
        std::cout << std::format("sentinel-worker {}\n", kVersion);
        return 0;
    }
    if (options.show_rules) {
        print_rules();
        return 0;
    }

    install_signal_handlers();

    if (!options.worker_mode) return run_local_scan(options);
    return run_worker(options);
}

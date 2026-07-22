// Sentinel SAST analysis worker.
//
// Consumes scan jobs from RabbitMQ, runs the (simulated) AST/taint analysis over
// each file in the job, and asks the Python AI triage layer whether each finding
// is a repeat of a known false positive before reporting it.

#if __has_include(<rabbitmq-c/amqp.h>)
#include <rabbitmq-c/amqp.h>
#include <rabbitmq-c/framing.h>
#include <rabbitmq-c/tcp_socket.h>
#else
#include <amqp.h>
#include <amqp_framing.h>
#include <amqp_tcp_socket.h>
#endif

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "analyzer.hpp"
#include "triage_client.hpp"

using json = nlohmann::json;

namespace {

std::string env_or(const char* key, const std::string& fallback) {
    const char* value = std::getenv(key);
    return (value && *value) ? std::string(value) : fallback;
}

int env_int(const char* key, int fallback) {
    const char* value = std::getenv(key);
    return (value && *value) ? std::atoi(value) : fallback;
}

// Turns any non-success amqp_rpc_reply_t into a readable message.
bool check_reply(const amqp_rpc_reply_t& reply, const char* context) {
    switch (reply.reply_type) {
        case AMQP_RESPONSE_NORMAL:
            return true;
        case AMQP_RESPONSE_NONE:
            std::cerr << context << ": missing RPC reply\n";
            return false;
        case AMQP_RESPONSE_LIBRARY_EXCEPTION:
            std::cerr << context << ": " << amqp_error_string2(reply.library_error) << "\n";
            return false;
        case AMQP_RESPONSE_SERVER_EXCEPTION:
            std::cerr << context << ": server exception (" << reply.reply.id << ")\n";
            return false;
    }
    return false;
}

void process_job(const std::string& body, sentinel::TriageClient& triage) {
    json job;
    try {
        job = json::parse(body);
    } catch (const json::exception& e) {
        std::cerr << "[worker] skipping malformed job: " << e.what() << "\n";
        return;
    }

    const std::string repository = job.value("repository", "unknown/repo");
    const std::string job_id = job.value("job_id", "-");
    std::cout << "\n[worker] job " << job_id << " for " << repository << "\n";

    std::vector<sentinel::SourceFile> files;
    for (const auto& entry : job.value("files", json::array())) {
        files.push_back({entry.value("path", "unknown"), entry.value("content", "")});
    }
    if (files.empty()) {
        std::cout << "[worker] job contained no files\n";
        return;
    }

    int total = 0, suppressed = 0, escalated = 0;

    for (const auto& file : files) {
        std::cout << "[worker] parsing AST + running taint query: " << file.path << "\n";
        for (const auto& finding : sentinel::analyze_file(repository, file)) {
            ++total;
            std::cout << "[worker]   FINDING " << finding.vulnerability_type << " at "
                      << finding.file << ":" << finding.line << "\n"
                      << "[worker]     " << finding.snippet << "\n";

            const sentinel::TriageVerdict verdict = triage.triage(finding);
            if (!verdict.ok) {
                std::cerr << "[worker]     TRIAGE FAILED: " << verdict.error
                          << " (escalating by default)\n";
                ++escalated;
                continue;
            }

            if (verdict.suppress) {
                ++suppressed;
                std::cout << "[worker]     SUPPRESSED (" << verdict.confidence << ") "
                          << verdict.reason << "\n";
            } else {
                ++escalated;
                std::cout << "[worker]     ESCALATED (" << verdict.confidence << ") "
                          << verdict.reason << "\n";
            }
        }
    }

    std::cout << "[worker] job " << job_id << " complete: " << total << " findings, " << suppressed
              << " suppressed by AI, " << escalated << " escalated to humans\n";
}

}  // namespace

int main() {
    // Line-buffered stdout would still hide progress behind a redirect, and this
    // process spends most of its life blocked on the broker. Flush every write so
    // logs are live under systemd/docker.
    std::cout << std::unitbuf;

    const std::string host = env_or("RABBITMQ_HOST", "localhost");
    const int port = env_int("RABBITMQ_PORT", 5672);
    const std::string user = env_or("RABBITMQ_USER", "guest");
    const std::string password = env_or("RABBITMQ_PASSWORD", "guest");
    const std::string queue_name = env_or("SCAN_QUEUE", "scan_jobs");
    const std::string triage_url =
        env_or("TRIAGE_URL", "http://localhost:8000/api/v1/triage");

    sentinel::TriageClient triage(triage_url);

    amqp_connection_state_t conn = amqp_new_connection();
    amqp_socket_t* socket = amqp_tcp_socket_new(conn);
    if (!socket) {
        std::cerr << "failed to create TCP socket\n";
        return 1;
    }
    if (amqp_socket_open(socket, host.c_str(), port) != AMQP_STATUS_OK) {
        std::cerr << "failed to connect to RabbitMQ at " << host << ":" << port << "\n";
        return 1;
    }
    if (!check_reply(amqp_login(conn, "/", 0, AMQP_DEFAULT_FRAME_SIZE, 0,
                                AMQP_SASL_METHOD_PLAIN, user.c_str(), password.c_str()),
                     "login")) {
        return 1;
    }

    amqp_channel_open(conn, 1);
    if (!check_reply(amqp_get_rpc_reply(conn), "channel open")) return 1;

    // durable=1 so jobs survive a broker restart; must match the publisher.
    amqp_queue_declare(conn, 1, amqp_cstring_bytes(queue_name.c_str()), 0, 1, 0, 0,
                       amqp_empty_table);
    if (!check_reply(amqp_get_rpc_reply(conn), "queue declare")) return 1;

    // One unacked message at a time, so work spreads across workers.
    amqp_basic_qos(conn, 1, 0, 1, 0);
    if (!check_reply(amqp_get_rpc_reply(conn), "basic qos")) return 1;

    // no_ack=0: we ack manually once the job is fully processed.
    amqp_basic_consume(conn, 1, amqp_cstring_bytes(queue_name.c_str()), amqp_empty_bytes, 0, 0, 0,
                       amqp_empty_table);
    if (!check_reply(amqp_get_rpc_reply(conn), "basic consume")) return 1;

    std::cout << "[worker] Sentinel analysis worker online\n"
              << "[worker] queue    : " << queue_name << " @ " << host << ":" << port << "\n"
              << "[worker] triage   : " << triage_url << "\n"
              << "[worker] waiting for scan jobs...\n";

    for (;;) {
        amqp_maybe_release_buffers(conn);

        amqp_envelope_t envelope;
        const amqp_rpc_reply_t reply = amqp_consume_message(conn, &envelope, nullptr, 0);
        if (reply.reply_type != AMQP_RESPONSE_NORMAL) {
            check_reply(reply, "consume");
            break;
        }

        const std::string body(static_cast<char*>(envelope.message.body.bytes),
                               envelope.message.body.len);
        process_job(body, triage);

        amqp_basic_ack(conn, 1, envelope.delivery_tag, 0);
        amqp_destroy_envelope(&envelope);
    }

    amqp_channel_close(conn, 1, AMQP_REPLY_SUCCESS);
    amqp_connection_close(conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(conn);
    return 0;
}

#include "secrets.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <format>
#include <unordered_map>

namespace sentinel {
namespace {

// Substrings that make a binding name credential-ish. Checked against the
// lowercased name, so API_KEY, apiKey and api-key all hit.
constexpr std::string_view kSecretNameMarkers[] = {
    "password", "passwd", "pwd",       "secret",     "apikey",   "api_key",
    "token",    "auth",   "credential", "privatekey", "private_key",
    "access_key", "accesskey", "client_secret", "clientsecret",
    "encryption_key", "signing_key", "session_key", "master_key",
    "bearer",   "oauth",  "salt",     "passphrase",
};

// Names that contain a marker but are not themselves credentials. Without these
// the detector fires on every variable that merely *mentions* a token.
constexpr std::string_view kSecretNameExclusions[] = {
    "token_type",   "tokenizer",  "tokenize",   "token_count", "tokens_used",
    "auth_url",     "auth_type",  "auth_header_name", "password_field",
    "secret_name",  "key_name",   "token_name", "password_hash", "hashed_password",
    "password_regex", "password_policy", "min_password_length",
};

// Values that are obviously not real credentials.
constexpr std::string_view kPlaceholderMarkers[] = {
    "changeme",  "change_me", "your-",     "your_",    "yourkey",   "placeholder",
    "example",   "dummy",     "fake",      "test-key", "testkey",   "sample",
    "insert",    "replace",   "todo",      "fixme",    "xxxx",      "abc123",
    "foobar",    "notreal",   "do-not-use", "donotuse", "redacted", "<your",
    "my-secret", "mysecret",  "s3cr3t",    "hunter2",  "password123",
};

// Expressions that look like a literal but resolve at runtime.
constexpr std::string_view kEnvironmentMarkers[] = {
    "process.env", "os.environ", "os.getenv", "getenv",  "environ.get",
    "config.get",  "viper.get",  "secrets.",  "vault.",  "ssm.",
    "settings.",   "conf.get",   "dotenv",    "env.get", "${",
};

constexpr std::string_view kTestPathMarkers[] = {
    "test", "spec", "fixture", "mock", "example", "sample", "__tests__",
    "testdata", "e2e", "docs/", "doc/", ".md", "demo", "seed", "benchmark",
};

bool contains_any(std::string_view haystack, const std::string_view* list, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        if (haystack.find(list[i]) != std::string_view::npos) return true;
    }
    return false;
}

template <std::size_t N>
bool contains_any(std::string_view haystack, const std::string_view (&list)[N]) {
    return contains_any(haystack, list, N);
}

bool all_upper_alnum(std::string_view value) {
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return (std::isupper(c) != 0) || (std::isdigit(c) != 0);
    });
}

// A value made of very few distinct characters ("aaaaaaaaaaaa", "000000000000")
// has misleadingly moderate entropy for its length; reject it outright.
bool too_few_distinct_characters(std::string_view value) {
    bool seen[256] = {};
    std::size_t distinct = 0;
    for (const unsigned char c : value) {
        if (!seen[c]) {
            seen[c] = true;
            ++distinct;
        }
    }
    return distinct < 5;
}

// A dotted or slashed value is usually a path, URL or class name.
bool looks_structural(std::string_view value) {
    if (value.find("://") != std::string_view::npos) return true;
    if (value.find('/') != std::string_view::npos && value.find(' ') == std::string_view::npos &&
        value.size() < 64) {
        // Short slash-separated values are paths far more often than secrets.
        return true;
    }
    // A sentence, not a token.
    return std::count(value.begin(), value.end(), ' ') >= 2;
}

}  // namespace

double shannon_entropy(std::string_view value) {
    if (value.empty()) return 0.0;

    std::array<std::size_t, 256> counts{};
    for (const unsigned char c : value) ++counts[c];

    const double length = static_cast<double>(value.size());
    double entropy = 0.0;
    for (const std::size_t count : counts) {
        if (count == 0) continue;
        const double probability = static_cast<double>(count) / length;
        entropy -= probability * std::log2(probability);
    }
    return entropy;
}

namespace {

// Drops separators so api_key, apiKey and api-key all reduce to "apikey".
std::string strip_separators(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (const char c : value) {
        if (c != '-' && c != '_') out.push_back(c);
    }
    return out;
}

// The marker list has to be normalised too, not just the name: comparing the
// normalised name "signingkey" against the raw marker "signing_key" never
// matches, which silently lost every camelCase form of a two-word marker.
bool contains_any_normalised(std::string_view normalised_haystack,
                             const std::string_view* list, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        const std::string marker = strip_separators(list[i]);
        if (normalised_haystack.find(marker) != std::string_view::npos) return true;
    }
    return false;
}

template <std::size_t N>
bool contains_any_normalised(std::string_view haystack, const std::string_view (&list)[N]) {
    return contains_any_normalised(haystack, list, N);
}

}  // namespace

bool looks_like_secret_name(std::string_view name) {
    const std::string lowered = ast::to_lower(name);
    const std::string normalised = strip_separators(lowered);

    if (contains_any(lowered, kSecretNameExclusions)) return false;
    if (contains_any_normalised(normalised, kSecretNameExclusions)) return false;

    return contains_any(lowered, kSecretNameMarkers) ||
           contains_any_normalised(normalised, kSecretNameMarkers);
}

bool looks_like_placeholder(std::string_view value) {
    if (value.empty()) return true;

    const std::string lowered = ast::to_lower(value);
    if (contains_any(lowered, kPlaceholderMarkers)) return true;
    if (too_few_distinct_characters(value)) return true;

    // A value that is entirely one repeated character class, like "xxxxxxxx".
    const bool all_same = std::all_of(value.begin(), value.end(),
                                      [first = value.front()](char c) { return c == first; });
    if (all_same) return true;

    return false;
}

bool is_environment_reference(std::string_view expression) {
    const std::string lowered = ast::to_lower(expression);
    return contains_any(lowered, kEnvironmentMarkers);
}

bool is_test_context(std::string_view path) {
    const std::string lowered = ast::to_lower(path);
    return contains_any(lowered, kTestPathMarkers);
}

const std::vector<SecretPattern>& builtin_secret_patterns() {
    static const std::vector<SecretPattern> kPatterns = {
        {"AWS Access Key ID", "AKIA", 20, 20, true},
        {"AWS Access Key ID", "ASIA", 20, 20, true},
        {"GitHub Personal Access Token", "ghp_", 36, 44, false},
        {"GitHub OAuth Token", "gho_", 36, 44, false},
        {"GitHub App Token", "ghu_", 36, 44, false},
        {"GitHub Refresh Token", "ghr_", 36, 44, false},
        {"GitHub Fine-Grained Token", "github_pat_", 50, 100, false},
        {"Slack Bot Token", "xoxb-", 24, 80, false},
        {"Slack User Token", "xoxp-", 24, 80, false},
        {"Slack Webhook", "https://hooks.slack.com/services/", 60, 120, false},
        {"Stripe Live Secret Key", "sk_live_", 24, 80, false},
        {"Stripe Test Secret Key", "sk_test_", 24, 80, false},
        {"Stripe Restricted Key", "rk_live_", 24, 80, false},
        {"Google API Key", "AIza", 39, 39, false},
        {"Twilio Account SID", "AC", 34, 34, false},
        {"SendGrid API Key", "SG.", 40, 80, false},
        {"npm Access Token", "npm_", 36, 44, false},
        {"OpenAI API Key", "sk-", 40, 64, false},
        {"Anthropic API Key", "sk-ant-", 40, 120, false},
        {"PyPI Upload Token", "pypi-", 40, 200, false},
        {"Private Key Block", "-----BEGIN", 20, 100, false},
        {"JSON Web Token", "eyJ", 40, 400, false},
    };
    return kPatterns;
}

std::optional<SecretPattern> match_secret_pattern(std::string_view value) {
    for (const auto& pattern : builtin_secret_patterns()) {
        if (!ast::starts_with(value, pattern.prefix)) continue;
        if (pattern.min_length > 0 && value.size() < pattern.min_length) continue;
        if (pattern.max_length > 0 && value.size() > pattern.max_length) continue;
        if (pattern.require_all_upper_alnum && !all_upper_alnum(value)) continue;
        return pattern;
    }
    return std::nullopt;
}

std::vector<SecretCandidate> scan_for_secrets(const ast::ParsedFile& file, TSNode root,
                                              std::string_view path,
                                              const std::vector<std::string>& assignment_node_types,
                                              const std::vector<std::string>& pair_node_types) {
    std::vector<SecretCandidate> candidates;
    const std::string& source = file.source();
    const bool test_file = is_test_context(path);

    // Go wraps a const/var initialiser in an expression_list, and several
    // grammars wrap a single value in a one-child node. Descend through those
    // so the literal check sees the literal rather than its container.
    const auto unwrap_single_value = [](TSNode node) {
        for (int depth = 0; depth < 3; ++depth) {
            if (ts_node_is_null(node) || ast::is_string_literal(node)) break;
            const std::string_view type = ast::node_type(node);
            if (type != "expression_list" && type != "expression_statement" &&
                type != "parenthesized_expression") {
                break;
            }
            if (ast::named_child_count(node) != 1) break;
            node = ts_node_named_child(node, 0);
        }
        return node;
    };

    // Considers one name = value pair.
    const auto consider = [&](TSNode name_node, TSNode value_node) {
        if (ts_node_is_null(name_node) || ts_node_is_null(value_node)) return;
        value_node = unwrap_single_value(value_node);
        if (!ast::is_string_literal(value_node)) return;

        const std::string raw = ast::node_text(source, value_node);
        const std::string value = ast::string_literal_value(raw);

        // A template literal with an interpolation is computed, not hardcoded.
        if (value.find("${") != std::string::npos) return;
        if (is_environment_reference(raw)) return;

        // The binding name may itself be a string (a dict key) or an identifier.
        std::string binding = ast::node_text(source, name_node);
        if (ast::is_string_literal(name_node)) {
            binding = ast::string_literal_value(binding);
        }

        const std::optional<SecretPattern> pattern = match_secret_pattern(value);
        const bool named_like_secret = looks_like_secret_name(binding);

        // A recognised provider format is conclusive on its own; anything else
        // needs the name to suggest a credential.
        if (!pattern.has_value() && !named_like_secret) return;
        if (value.size() < kMinSecretLength && !pattern.has_value()) return;
        if (value.size() > kMaxSecretLength) return;

        SecretCandidate candidate;
        candidate.binding_name = binding;
        candidate.value = value;
        candidate.line = ast::start_line(value_node);
        candidate.entropy = shannon_entropy(value);

        if (pattern.has_value()) {
            candidate.pattern_name = pattern->name;
            candidate.confidence = Confidence::High;
            candidate.rationale =
                std::format("value matches the {} format", pattern->name);

            // A recognised format inside a test file is still worth reporting,
            // just less loudly -- these are the ones that turn out to be real.
            if (test_file) candidate.confidence = Confidence::Medium;
        } else {
            if (looks_like_placeholder(value)) return;
            if (looks_structural(value)) return;
            if (candidate.entropy < kEntropyThreshold) return;

            candidate.confidence = test_file ? Confidence::Low : Confidence::Medium;
            candidate.rationale = std::format(
                "'{}' is assigned a {}-character literal with {:.2f} bits/char of entropy",
                binding, value.size(), candidate.entropy);
        }

        if (test_file && candidate.rationale.find("test") == std::string::npos) {
            candidate.rationale += " (in a test or fixture path)";
        }

        candidates.push_back(std::move(candidate));
    };

    ast::walk(root, [&](TSNode node) {
        const std::string_view type = ast::node_type(node);

        const bool is_assignment = std::ranges::contains(assignment_node_types, type);
        const bool is_pair = std::ranges::contains(pair_node_types, type);

        if (!is_assignment && !is_pair) return;

        TSNode name_node = ast::child_by_field(node, "name");
        if (ts_node_is_null(name_node)) name_node = ast::child_by_field(node, "left");
        if (ts_node_is_null(name_node)) name_node = ast::child_by_field(node, "key");

        TSNode value_node = ast::child_by_field(node, "value");
        if (ts_node_is_null(value_node)) value_node = ast::child_by_field(node, "right");

        consider(name_node, value_node);
    });

    // Deduplicate by (line, value): a value assigned in a destructuring pattern
    // can be reached through more than one node type.
    std::sort(candidates.begin(), candidates.end(),
              [](const SecretCandidate& a, const SecretCandidate& b) {
                  return std::tie(a.line, a.value) < std::tie(b.line, b.value);
              });
    candidates.erase(std::unique(candidates.begin(), candidates.end(),
                                 [](const SecretCandidate& a, const SecretCandidate& b) {
                                     return a.line == b.line && a.value == b.value;
                                 }),
                     candidates.end());

    return candidates;
}

}  // namespace sentinel

// Hardcoded secret detection.
//
// This is the one detector that does not use taint analysis at all: a
// credential in source is dangerous because of what it *is*, not because of
// where it flows. It is included because it is consistently among the highest
// true-positive-rate findings in real scans -- and because the seed corpus in
// ai-layer/seed.py already contained a dismissed "Hardcoded Secret", which the
// engine had no way to produce.
//
// Naive secret detection is notorious for noise, so this uses three signals in
// combination rather than a name blocklist alone:
//
//   1. The binding name looks credential-ish   (api_key, password, secret, token)
//   2. The value is a string literal of plausible length
//   3. The value has high Shannon entropy, or matches a known provider format
//
// and then subtracts the contexts that produce almost all false positives:
// test files, obvious placeholders, environment lookups, and format strings.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <tree_sitter/api.h>

#include "ast.hpp"
#include "vulnerability.hpp"

namespace sentinel {

// A provider-specific credential format. These are matched directly and skip
// the entropy check, because the shape alone is conclusive.
struct SecretPattern {
    std::string name;          // "AWS Access Key ID"
    std::string prefix;        // "AKIA"
    std::size_t min_length = 0;
    std::size_t max_length = 0;
    bool require_all_upper_alnum = false;
};

struct SecretCandidate {
    std::string binding_name;
    std::string value;
    std::string pattern_name;   // empty when detected by entropy alone
    double entropy = 0.0;
    int line = 0;
    Confidence confidence = Confidence::Low;
    std::string rationale;
};

// Shannon entropy in bits per character. A random 32-char base64 token scores
// around 5.0; an English sentence around 3.5; "password123" around 3.0.
double shannon_entropy(std::string_view value);

// True when the name suggests the value is a credential.
bool looks_like_secret_name(std::string_view name);

// True when the value is one of the placeholder shapes that dominate false
// positives: "changeme", "xxx", "your-key-here", "${...}", "", repeated chars.
bool looks_like_placeholder(std::string_view value);

// True when the value is really an environment lookup or config reference
// rather than a literal, e.g. os.environ["KEY"] or process.env.KEY.
bool is_environment_reference(std::string_view expression);

// True when the path is a test, fixture, example or documentation file. Secrets
// there are nearly always fake, so findings are downgraded rather than dropped
// -- a real credential committed to a test file is still a real credential.
bool is_test_context(std::string_view path);

// The built-in provider formats.
const std::vector<SecretPattern>& builtin_secret_patterns();

// Matches a value against the provider table.
std::optional<SecretPattern> match_secret_pattern(std::string_view value);

// Scans one file for hardcoded credentials.
std::vector<SecretCandidate> scan_for_secrets(const ast::ParsedFile& file, TSNode root,
                                              std::string_view path,
                                              const std::vector<std::string>& assignment_node_types,
                                              const std::vector<std::string>& pair_node_types);

// Entropy above which a credential-named string literal is reported on entropy
// alone. Tuned so that "supersecret" (3.0) does not fire but a real 32-char
// token (>4.2) does.
inline constexpr double kEntropyThreshold = 4.0;

// Below this length a high-entropy string is too likely to be a short constant.
inline constexpr std::size_t kMinSecretLength = 12;

// Above this, it is almost certainly a blob of encoded data, a test fixture, or
// an embedded certificate rather than a credential to rotate.
inline constexpr std::size_t kMaxSecretLength = 512;

}  // namespace sentinel

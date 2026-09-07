// Inline suppression comments.
//
// Every SAST tool that people actually keep enabled has an escape hatch, because
// there is always a finding the tool cannot understand is safe. Without one, the
// team's only options are to disable the rule globally or to ignore the tool --
// and they pick the second.
//
// Supported forms, matched in a comment on the flagged line or the line above:
//
//     sentinel:ignore                          suppress everything here
//     sentinel:ignore sql-injection            suppress one class
//     sentinel:ignore sql-injection,xss        suppress several
//     sentinel:ignore-next-line                suppress the following line
//     sentinel:ignore-file                     suppress the whole file
//
// A reason is strongly encouraged and parsed out when present:
//
//     sentinel:ignore sql-injection -- table name is from an internal allowlist
//
// Suppressions are *reported*, not silently applied. An unexplained suppression
// is itself a finding worth surfacing at review time, and a suppression that
// matches nothing is stale and should be deleted -- both are tracked here.

#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <tree_sitter/api.h>

#include "ast.hpp"
#include "vulnerability.hpp"

namespace sentinel {

enum class SuppressionScope {
    ThisLine,
    NextLine,
    WholeFile,
};

struct Suppression {
    int line = 0;                        // where the comment itself is
    SuppressionScope scope = SuppressionScope::ThisLine;
    std::vector<VulnClass> classes;      // empty means "all classes"
    std::string reason;                  // text after `--`, if any
    std::string raw;                     // the original comment, for reporting
    bool has_reason = false;
    bool matched = false;                // set when it actually suppressed something

    bool covers(VulnClass id) const;
};

class SuppressionIndex {
public:
    SuppressionIndex() = default;
    explicit SuppressionIndex(std::vector<Suppression> suppressions);

    // True when a finding of `id` on `line` should be dropped. Marks the
    // matching suppression as used, so stale ones can be reported afterwards.
    bool suppresses(int line, VulnClass id);

    // Suppressions that never matched anything -- stale, safe to delete.
    std::vector<Suppression> unused() const;

    // Suppressions with no explanatory reason.
    std::vector<Suppression> without_reason() const;

    std::size_t size() const noexcept { return suppressions_.size(); }
    bool empty() const noexcept { return suppressions_.empty(); }

    const std::vector<Suppression>& all() const noexcept { return suppressions_; }

private:
    std::vector<Suppression> suppressions_;
    bool file_wide_ = false;
};

// Parses one comment's text. Returns nullopt when it is an ordinary comment.
std::optional<Suppression> parse_suppression_comment(std::string_view comment_text, int line);

// Collects every suppression comment in a parsed file.
SuppressionIndex collect_suppressions(const ast::ParsedFile& file, TSNode root,
                                      const std::vector<std::string>& comment_node_types);

}  // namespace sentinel

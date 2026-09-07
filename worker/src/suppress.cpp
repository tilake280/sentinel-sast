#include "suppress.hpp"

#include <algorithm>
#include <utility>

namespace sentinel {
namespace {

constexpr std::string_view kDirective = "sentinel:ignore";

// Splits a comma or space separated class list into VulnClass values. An
// unrecognised slug is skipped rather than treated as "all", so a typo narrows
// the suppression to nothing instead of silently widening it to everything.
std::vector<VulnClass> parse_class_list(std::string_view list, bool& saw_unknown) {
    std::vector<VulnClass> classes;
    std::size_t start = 0;

    while (start <= list.size()) {
        std::size_t end = list.find_first_of(", \t", start);
        if (end == std::string_view::npos) end = list.size();

        const std::string_view token = list.substr(start, end - start);
        if (!token.empty()) {
            const VulnClass id = vuln_class_from_slug(token);
            if (id == VulnClass::Unknown) {
                saw_unknown = true;
            } else if (std::find(classes.begin(), classes.end(), id) == classes.end()) {
                classes.push_back(id);
            }
        }

        if (end >= list.size()) break;
        start = end + 1;
    }
    return classes;
}

// Strips comment syntax so the directive parser sees only the text: `//`, `#`,
// `/* ... */` and the leading `*` of a continuation line.
std::string_view strip_comment_markers(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    if (ast::starts_with(text, "//")) {
        text.remove_prefix(2);
    } else if (ast::starts_with(text, "/*")) {
        text.remove_prefix(2);
        if (ast::ends_with(text, "*/")) text.remove_suffix(2);
    } else if (ast::starts_with(text, "#")) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '*')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return text;
}

}  // namespace

bool Suppression::covers(VulnClass id) const {
    if (classes.empty()) return true;  // bare `sentinel:ignore` covers everything
    return std::find(classes.begin(), classes.end(), id) != classes.end();
}

std::optional<Suppression> parse_suppression_comment(std::string_view comment_text, int line) {
    const std::string_view body = strip_comment_markers(comment_text);

    const std::size_t directive_pos = body.find(kDirective);
    if (directive_pos == std::string_view::npos) return std::nullopt;

    Suppression suppression;
    suppression.line = line;
    suppression.raw = std::string(ast::trim(comment_text));

    std::string_view remainder = body.substr(directive_pos + kDirective.size());

    // Scope suffixes attach directly to the directive.
    if (ast::starts_with(remainder, "-next-line")) {
        suppression.scope = SuppressionScope::NextLine;
        remainder.remove_prefix(std::string_view("-next-line").size());
    } else if (ast::starts_with(remainder, "-file")) {
        suppression.scope = SuppressionScope::WholeFile;
        remainder.remove_prefix(std::string_view("-file").size());
    } else if (!remainder.empty() && remainder.front() == '-' &&
               !ast::starts_with(remainder, "--")) {
        // An unrecognised `-suffix`: not our directive after all.
        return std::nullopt;
    }

    // Everything after `--` is the human explanation.
    const std::size_t reason_pos = remainder.find("--");
    if (reason_pos != std::string_view::npos) {
        suppression.reason = ast::trim(remainder.substr(reason_pos + 2));
        suppression.has_reason = !suppression.reason.empty();
        remainder = remainder.substr(0, reason_pos);
    }

    bool saw_unknown = false;
    suppression.classes = parse_class_list(ast::trim(remainder), saw_unknown);

    // A directive naming only unrecognised classes suppresses nothing. Keeping
    // it in the index (rather than dropping it) means it shows up in the stale
    // report, which is how the author finds out about the typo.
    if (saw_unknown && suppression.classes.empty()) {
        suppression.classes.push_back(VulnClass::Unknown);
    }

    return suppression;
}

SuppressionIndex::SuppressionIndex(std::vector<Suppression> suppressions)
    : suppressions_(std::move(suppressions)) {
    file_wide_ = std::any_of(suppressions_.begin(), suppressions_.end(),
                             [](const Suppression& s) {
                                 return s.scope == SuppressionScope::WholeFile;
                             });
}

bool SuppressionIndex::suppresses(int line, VulnClass id) {
    bool suppressed = false;

    for (auto& suppression : suppressions_) {
        bool applies = false;
        switch (suppression.scope) {
            case SuppressionScope::WholeFile:
                applies = true;
                break;
            case SuppressionScope::ThisLine:
                // A trailing comment sits on the finding's line; a standalone
                // comment sits just above it. Accept both, which is what every
                // other tool does and what users expect.
                applies = (suppression.line == line) || (suppression.line + 1 == line);
                break;
            case SuppressionScope::NextLine:
                applies = (suppression.line + 1 == line);
                break;
        }

        if (!applies || !suppression.covers(id)) continue;

        suppression.matched = true;
        suppressed = true;
    }

    return suppressed;
}

std::vector<Suppression> SuppressionIndex::unused() const {
    std::vector<Suppression> stale;
    for (const auto& suppression : suppressions_) {
        if (!suppression.matched) stale.push_back(suppression);
    }
    return stale;
}

std::vector<Suppression> SuppressionIndex::without_reason() const {
    std::vector<Suppression> undocumented;
    for (const auto& suppression : suppressions_) {
        if (!suppression.has_reason) undocumented.push_back(suppression);
    }
    return undocumented;
}

SuppressionIndex collect_suppressions(const ast::ParsedFile& file, TSNode root,
                                      const std::vector<std::string>& comment_node_types) {
    std::vector<Suppression> suppressions;
    const std::string& source = file.source();

    ast::walk(root, [&](TSNode node) {
        const std::string_view type = ast::node_type(node);
        if (std::find(comment_node_types.begin(), comment_node_types.end(), type) ==
            comment_node_types.end()) {
            return;
        }

        const std::string text = ast::node_text(source, node);
        auto parsed = parse_suppression_comment(text, ast::start_line(node));
        if (parsed.has_value()) suppressions.push_back(std::move(*parsed));
    });

    return SuppressionIndex(std::move(suppressions));
}

}  // namespace sentinel

#include "ast.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <utility>

namespace sentinel::ast {
namespace {

// Node types that bind a name in at least one supported grammar. Kept together
// so collect_identifiers behaves the same across languages.
constexpr std::string_view kIdentifierTypes[] = {
    "identifier",
    "field_identifier",
    "property_identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
    "package_identifier",
    "type_identifier",
    "statement_identifier",
};

constexpr std::string_view kStringTypes[] = {
    "string",
    "string_literal",
    "template_string",
    "interpreted_string_literal",
    "raw_string_literal",
    "concatenated_string",
    "formatted_string",
};

constexpr std::string_view kConstantTypes[] = {
    "number", "integer", "float", "int_literal",  "float_literal",
    "true",   "false",   "null",  "none",         "nil",
    "boolean", "undefined",
};

bool one_of(std::string_view value, const std::string_view* list, std::size_t count) noexcept {
    for (std::size_t i = 0; i < count; ++i) {
        if (value == list[i]) return true;
    }
    return false;
}

template <std::size_t N>
bool one_of(std::string_view value, const std::string_view (&list)[N]) noexcept {
    return one_of(value, list, N);
}

}  // namespace

// ---- ParsedFile -----------------------------------------------------------

ParsedFile::ParsedFile(const TSLanguage* grammar, std::string source)
    : source_(std::move(source)) {
    if (grammar == nullptr) return;

    parser_ = ts_parser_new();
    if (parser_ == nullptr) return;

    if (!ts_parser_set_language(parser_, grammar)) {
        // Happens when the vendored grammar was built against a different
        // Tree-sitter ABI than the runtime we linked.
        ts_parser_delete(parser_);
        parser_ = nullptr;
        return;
    }

    tree_ = ts_parser_parse_string(parser_, nullptr, source_.c_str(),
                                   static_cast<uint32_t>(source_.size()));
}

ParsedFile::~ParsedFile() {
    if (tree_ != nullptr) ts_tree_delete(tree_);
    if (parser_ != nullptr) ts_parser_delete(parser_);
}

ParsedFile::ParsedFile(ParsedFile&& other) noexcept
    : parser_(std::exchange(other.parser_, nullptr)),
      tree_(std::exchange(other.tree_, nullptr)),
      source_(std::move(other.source_)),
      lines_(std::move(other.lines_)),
      lines_cached_(other.lines_cached_),
      parse_errors_(other.parse_errors_) {
    other.lines_cached_ = false;
}

ParsedFile& ParsedFile::operator=(ParsedFile&& other) noexcept {
    if (this != &other) {
        if (tree_ != nullptr) ts_tree_delete(tree_);
        if (parser_ != nullptr) ts_parser_delete(parser_);
        parser_ = std::exchange(other.parser_, nullptr);
        tree_ = std::exchange(other.tree_, nullptr);
        source_ = std::move(other.source_);
        lines_ = std::move(other.lines_);
        lines_cached_ = other.lines_cached_;
        parse_errors_ = other.parse_errors_;
        other.lines_cached_ = false;
    }
    return *this;
}

const std::vector<std::string>& ParsedFile::lines() const {
    if (!lines_cached_) {
        std::istringstream stream(source_);
        std::string line;
        while (std::getline(stream, line)) {
            // Normalise CRLF so snippets from Windows checkouts do not carry a
            // stray carriage return into the triage payload.
            if (!line.empty() && line.back() == '\r') line.pop_back();
            lines_.push_back(line);
        }
        lines_cached_ = true;
    }
    return lines_;
}

bool ParsedFile::has_parse_errors() const {
    if (parse_errors_.has_value()) return *parse_errors_;
    bool found = false;
    if (tree_ != nullptr) {
        // ts_node_has_error covers the whole subtree, so the root answers it.
        found = ts_node_has_error(ts_tree_root_node(tree_));
    }
    parse_errors_ = found;
    return found;
}

// ---- Node accessors -------------------------------------------------------

std::string_view node_type(TSNode node) noexcept {
    if (ts_node_is_null(node)) return {};
    const char* type = ts_node_type(node);
    return type != nullptr ? std::string_view(type) : std::string_view{};
}

std::string node_text(const std::string& source, TSNode node) {
    return std::string(node_view(source, node));
}

std::string_view node_view(const std::string& source, TSNode node) noexcept {
    if (ts_node_is_null(node)) return {};
    const uint32_t start = ts_node_start_byte(node);
    const uint32_t end = ts_node_end_byte(node);
    if (end <= start || end > source.size()) return {};
    return std::string_view(source).substr(start, end - start);
}

TSNode child_by_field(TSNode node, std::string_view field) noexcept {
    if (ts_node_is_null(node) || field.empty()) return {};
    return ts_node_child_by_field_name(node, field.data(),
                                       static_cast<uint32_t>(field.size()));
}

bool has_field(TSNode node, std::string_view field) noexcept {
    return !ts_node_is_null(child_by_field(node, field));
}

int start_line(TSNode node) noexcept {
    if (ts_node_is_null(node)) return 0;
    return static_cast<int>(ts_node_start_point(node).row) + 1;
}

int end_line(TSNode node) noexcept {
    if (ts_node_is_null(node)) return 0;
    return static_cast<int>(ts_node_end_point(node).row) + 1;
}

int start_column(TSNode node) noexcept {
    if (ts_node_is_null(node)) return 0;
    return static_cast<int>(ts_node_start_point(node).column) + 1;
}

std::vector<TSNode> named_children(TSNode node) {
    std::vector<TSNode> out;
    if (ts_node_is_null(node)) return out;
    const uint32_t count = ts_node_named_child_count(node);
    out.reserve(count);

    // ts_node_named_child(node, i) walks from the first child every time, so
    // indexing is quadratic in the number of children. That is nothing for the
    // usual handful, and everything for a minified file whose top level is one
    // declaration with a thousand declarators. A cursor steps sibling to
    // sibling in constant time; it costs an allocation, so it is used only
    // once a node is wide enough for the difference to show.
    constexpr uint32_t kWideNode = 16;
    if (count <= kWideNode) {
        for (uint32_t i = 0; i < count; ++i) {
            out.push_back(ts_node_named_child(node, i));
        }
        return out;
    }

    TSTreeCursor cursor = ts_tree_cursor_new(node);
    if (ts_tree_cursor_goto_first_child(&cursor)) {
        do {
            const TSNode child = ts_tree_cursor_current_node(&cursor);
            if (ts_node_is_named(child)) out.push_back(child);
        } while (ts_tree_cursor_goto_next_sibling(&cursor));
    }
    ts_tree_cursor_delete(&cursor);
    return out;
}

std::optional<TSNode> first_named_child(TSNode node) noexcept {
    if (ts_node_is_null(node) || ts_node_named_child_count(node) == 0) return std::nullopt;
    return ts_node_named_child(node, 0);
}

std::size_t named_child_count(TSNode node) noexcept {
    if (ts_node_is_null(node)) return 0;
    return ts_node_named_child_count(node);
}

// ---- Traversal ------------------------------------------------------------

void walk(TSNode root, const std::function<void(TSNode)>& visit) {
    if (ts_node_is_null(root)) return;

    // Explicit stack rather than recursion: minified JS bundles routinely nest
    // deeper than the default 8MB stack tolerates.
    std::vector<TSNode> stack{root};
    while (!stack.empty()) {
        const TSNode node = stack.back();
        stack.pop_back();
        visit(node);

        // Push in reverse so children are visited left to right.
        const auto children = named_children(node);
        stack.insert(stack.end(), children.rbegin(), children.rend());
    }
}

void walk_pruned(TSNode root, const std::function<bool(TSNode)>& visit) {
    if (ts_node_is_null(root)) return;

    std::vector<TSNode> stack{root};
    while (!stack.empty()) {
        const TSNode node = stack.back();
        stack.pop_back();
        if (!visit(node)) continue;  // caller declined this subtree

        const auto children = named_children(node);
        stack.insert(stack.end(), children.rbegin(), children.rend());
    }
}

std::optional<TSNode> find_ancestor(TSNode node, const std::vector<std::string_view>& types) {
    if (ts_node_is_null(node)) return std::nullopt;
    TSNode current = ts_node_parent(node);
    while (!ts_node_is_null(current)) {
        const std::string_view type = node_type(current);
        if (std::ranges::contains(types, type)) return current;
        current = ts_node_parent(current);
    }
    return std::nullopt;
}

std::vector<TSNode> find_all(TSNode root, std::string_view type) {
    std::vector<TSNode> out;
    walk(root, [&](TSNode node) {
        if (node_type(node) == type) out.push_back(node);
    });
    return out;
}

bool has_ancestor_of_type(TSNode node, const std::vector<std::string_view>& types) {
    return find_ancestor(node, types).has_value();
}

// ---- Identifier extraction ------------------------------------------------

void collect_identifiers(TSNode node, const std::string& source, std::vector<std::string>& out) {
    walk(node, [&](TSNode current) {
        if (one_of(node_type(current), kIdentifierTypes)) {
            std::string text = node_text(source, current);
            if (!text.empty() && !std::ranges::contains(out, text)) {
                out.push_back(std::move(text));
            }
        }
    });
}

std::vector<std::string> identifiers_in(TSNode node, const std::string& source) {
    std::vector<std::string> out;
    collect_identifiers(node, source, out);
    return out;
}

std::string dotted_name(const std::string& source, TSNode node) {
    if (ts_node_is_null(node)) return {};

    const std::string_view type = node_type(node);

    if (one_of(type, kIdentifierTypes)) return node_text(source, node);

    // `a.b` shapes: JS member_expression, Python attribute, Go selector_expression.
    if (type == "member_expression" || type == "attribute" || type == "selector_expression") {
        // Field names differ per grammar, so try each in turn.
        TSNode object = child_by_field(node, "object");
        if (ts_node_is_null(object)) object = child_by_field(node, "operand");
        if (ts_node_is_null(object)) {
            // Go's selector_expression, and a fallback for grammars that do not
            // name the receiver field.
            const auto children = named_children(node);
            if (!children.empty()) object = children.front();
        }

        TSNode property = child_by_field(node, "property");
        if (ts_node_is_null(property)) property = child_by_field(node, "attribute");
        if (ts_node_is_null(property)) property = child_by_field(node, "field");
        if (ts_node_is_null(property)) {
            const auto children = named_children(node);
            if (children.size() >= 2) property = children.back();
        }

        const std::string base = dotted_name(source, object);
        const std::string tail = ts_node_is_null(property) ? "" : node_text(source, property);
        if (base.empty()) return tail;
        if (tail.empty()) return base;
        return base + "." + tail;
    }

    // `a[b]` -- treat as the base name; the subscript is handled by callers that
    // care (prototype pollution wants the key expression itself).
    if (type == "subscript_expression" || type == "subscript" || type == "index_expression") {
        TSNode object = child_by_field(node, "object");
        if (ts_node_is_null(object)) object = child_by_field(node, "value");
        if (ts_node_is_null(object)) {
            const auto children = named_children(node);
            if (!children.empty()) object = children.front();
        }
        return dotted_name(source, object);
    }

    // A call in the middle of a chain: `foo().bar` -- name the called function so
    // `db.connect().query` still reports something useful.
    if (type == "call_expression" || type == "call") {
        return dotted_name(source, child_by_field(node, "function"));
    }

    // Parenthesised expressions are transparent for naming purposes.
    if (type == "parenthesized_expression") {
        const auto children = named_children(node);
        if (!children.empty()) return dotted_name(source, children.front());
    }

    return {};
}

std::string_view last_segment(std::string_view dotted) noexcept {
    const auto pos = dotted.find_last_of('.');
    return pos == std::string_view::npos ? dotted : dotted.substr(pos + 1);
}

std::string_view receiver_of(std::string_view dotted) noexcept {
    const auto pos = dotted.find_last_of('.');
    return pos == std::string_view::npos ? std::string_view{} : dotted.substr(0, pos);
}

// ---- Text helpers ---------------------------------------------------------

std::string trim(std::string_view value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string_view::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return std::string(value.substr(begin, end - begin + 1));
}

std::string to_lower(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool contains(std::string_view haystack, std::string_view needle) noexcept {
    return haystack.contains(needle);
}

bool starts_with(std::string_view value, std::string_view prefix) noexcept {
    return value.starts_with(prefix);
}

bool ends_with(std::string_view value, std::string_view suffix) noexcept {
    return value.ends_with(suffix);
}

std::string string_literal_value(std::string_view raw) {
    // Drop Python/JS literal prefixes: r'', b"", f'', u'', rb'' and so on.
    std::size_t begin = 0;
    while (begin < raw.size() && std::isalpha(static_cast<unsigned char>(raw[begin]))) {
        ++begin;
        if (begin > 2) break;  // no real prefix is longer than two characters
    }
    if (begin >= raw.size()) return std::string(raw);

    const char quote = raw[begin];
    if (quote != '"' && quote != '\'' && quote != '`') {
        return std::string(raw.substr(begin));
    }

    // Triple-quoted strings.
    std::size_t open = 1;
    if (raw.size() >= begin + 6 && raw.compare(begin, 3, std::string(3, quote)) == 0) {
        open = 3;
    }

    const std::size_t start = begin + open;
    if (start >= raw.size()) return {};

    std::size_t end = raw.size();
    if (end >= start + open && raw.compare(end - open, open, std::string(open, quote)) == 0) {
        end -= open;
    }
    if (end <= start) return {};
    return std::string(raw.substr(start, end - start));
}

bool is_string_literal(TSNode node) noexcept {
    return one_of(node_type(node), kStringTypes);
}

bool is_constant_literal(TSNode node) noexcept {
    return one_of(node_type(node), kConstantTypes);
}

}  // namespace sentinel::ast

// Tree-sitter conveniences shared by every analysis pass.
//
// Tree-sitter's C API is deliberately minimal: nodes are returned by value, text
// must be sliced out of the original buffer by byte offset, and traversal is
// manual. Every pass in this worker needs the same handful of operations, so
// they live here rather than being re-derived per module.
//
// Cursor is the important type. A naive recursive walk over a deep AST can blow
// the stack on machine-generated files (minified bundles nest thousands deep),
// so traversal here is iterative over an explicit worklist.

#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <tree_sitter/api.h>

namespace sentinel::ast {

// A parsed file plus the buffer its nodes point into. Nodes are only valid while
// the owning Tree is alive, which is why this owns both.
class ParsedFile {
public:
    ParsedFile(const TSLanguage* grammar, std::string source);
    ~ParsedFile();

    ParsedFile(const ParsedFile&) = delete;
    ParsedFile& operator=(const ParsedFile&) = delete;
    ParsedFile(ParsedFile&& other) noexcept;
    ParsedFile& operator=(ParsedFile&& other) noexcept;

    bool ok() const noexcept { return tree_ != nullptr; }
    TSNode root() const noexcept { return ts_tree_root_node(tree_); }
    const std::string& source() const noexcept { return source_; }

    // Physical lines, cached on first use for snippet extraction.
    const std::vector<std::string>& lines() const;

    // True when the parse produced any ERROR or MISSING node. Tree-sitter is
    // error-tolerant, so we still analyse the file -- but findings from a file
    // that did not parse cleanly get their confidence downgraded.
    bool has_parse_errors() const;

private:
    TSParser* parser_ = nullptr;
    TSTree* tree_ = nullptr;
    std::string source_;
    mutable std::vector<std::string> lines_;
    mutable bool lines_cached_ = false;
    mutable std::optional<bool> parse_errors_;
};

// ---- Node accessors -------------------------------------------------------

std::string_view node_type(TSNode node) noexcept;
std::string node_text(const std::string& source, TSNode node);

// Non-allocating variant for hot comparisons; the view borrows from `source`.
std::string_view node_view(const std::string& source, TSNode node) noexcept;

TSNode child_by_field(TSNode node, std::string_view field) noexcept;
bool has_field(TSNode node, std::string_view field) noexcept;

int start_line(TSNode node) noexcept;   // 1-indexed, matching editors
int end_line(TSNode node) noexcept;
int start_column(TSNode node) noexcept; // 1-indexed

// Named children only -- Tree-sitter also exposes anonymous tokens like `(` that
// no analysis pass cares about.
std::vector<TSNode> named_children(TSNode node);
std::optional<TSNode> first_named_child(TSNode node) noexcept;
std::size_t named_child_count(TSNode node) noexcept;

// ---- Traversal ------------------------------------------------------------

// Iterative pre-order walk. Safe on deeply nested trees where recursion is not.
void walk(TSNode root, const std::function<void(TSNode)>& visit);

// Stops descending into a subtree when `visit` returns false. Used to avoid
// walking nested function bodies when collecting facts for one function.
void walk_pruned(TSNode root, const std::function<bool(TSNode)>& visit);

// Nearest enclosing ancestor whose type is in `types`, if any.
std::optional<TSNode> find_ancestor(TSNode node, const std::vector<std::string_view>& types);

// Every descendant of the given type, in document order.
std::vector<TSNode> find_all(TSNode root, std::string_view type);

// True when `node` is inside a node of one of the given types.
bool has_ancestor_of_type(TSNode node, const std::vector<std::string_view>& types);

// ---- Identifier extraction ------------------------------------------------

// Every identifier-ish name appearing in the subtree. Used to decide whether an
// expression mentions a tainted variable.
void collect_identifiers(TSNode node, const std::string& source, std::vector<std::string>& out);
std::vector<std::string> identifiers_in(TSNode node, const std::string& source);

// The dotted path a callee or member expression spells out, e.g. `os.path.join`.
// Returns "" when the node is not a name-like expression (a call on the result
// of another call, say).
std::string dotted_name(const std::string& source, TSNode node);

// The final segment of a dotted name: `db.query` -> `query`.
std::string_view last_segment(std::string_view dotted) noexcept;

// Everything before the final segment: `os.path.join` -> `os.path`. Empty when
// the name has no dot.
std::string_view receiver_of(std::string_view dotted) noexcept;

// ---- Text helpers ---------------------------------------------------------

std::string trim(std::string_view value);
std::string to_lower(std::string_view value);
bool contains(std::string_view haystack, std::string_view needle) noexcept;
bool starts_with(std::string_view value, std::string_view prefix) noexcept;
bool ends_with(std::string_view value, std::string_view suffix) noexcept;

// Strips one layer of quotes from a string literal node's text, handling the
// prefixes Python and JS allow (r'', b"", f'', u'').
std::string string_literal_value(std::string_view raw);

// True when the node is a string/template literal in any supported language.
bool is_string_literal(TSNode node) noexcept;

// True when the node is a numeric, boolean or null constant.
bool is_constant_literal(TSNode node) noexcept;

}  // namespace sentinel::ast

// Lightweight receiver-type inference.
//
// The original engine matched sinks on the last dotted segment, so *any*
// `.exec(` was reported as command injection. That is wrong for the two most
// common `.exec(` receivers in real code:
//
//     /^[a-z]+$/.exec(req.query.name)     // RegExp.exec -- not a shell
//     db.exec("DELETE FROM sessions")     // SQLite -- SQL, not a shell
//     child_process.exec(cmd)             // actually command injection
//
// Full type inference needs a type checker. What this module does instead is
// track the small number of constructor patterns that produce a security-
// relevant receiver, which covers the overwhelming majority of real code:
// a variable is a Database if it was assigned from something that returns a
// database handle, and so on.
//
// Sink rules can then require a receiver type. When the type is Unknown the
// rule still fires -- being conservative here means we keep finding real bugs
// in code shaped in ways this module does not recognise, at the cost of the
// false positives it cannot rule out. Those findings get their confidence
// downgraded instead (see severity.cpp).

#pragma once

#include <map>
#include <string>
#include <string_view>
#include <vector>

#include <tree_sitter/api.h>

#include "ast.hpp"

namespace sentinel {

enum class ReceiverType {
    Unknown,
    Database,       // pg.Pool, mysql connection, sqlite3, cursor, *sql.DB
    PreparedStatement,  // *sql.Stmt: its Query/Exec arguments are bound values
    DomElement,     // document.getElementById(...), createElement
    ChildProcess,   // node child_process, python subprocess, go os/exec
    FileSystem,     // fs, os, io/ioutil
    HttpClient,     // axios, fetch wrapper, requests, http.Client
    HttpResponse,   // express res, flask response, http.ResponseWriter
    Logger,         // winston, logging.getLogger, log.Logger
    Regex,          // RegExp literal or constructor
    Template,       // template engines
    ScriptEngine,   // an embedded interpreter: goja, otto, yaegi, gopher-lua
    Crypto,         // crypto, hashlib
    Serializer,     // pickle, yaml, gob -- can construct arbitrary objects
    // JSON and friends are serializers too, but data-only: they cannot
    // instantiate arbitrary types, so json.loads(untrusted) is not the
    // vulnerability pickle.loads(untrusted) is. Separating them is what stops
    // the deserialization rule firing on every JSON parse.
    DataCodec,
    MongoCollection,// db.collection('users')
};

std::string_view to_string(ReceiverType type) noexcept;

// Per-language knowledge of which expressions produce which receiver type.
struct TypeRule {
    std::string pattern;   // substring matched against the initialising expression
    ReceiverType type = ReceiverType::Unknown;
};

// Tracks what each name in a file refers to.
class TypeEnvironment {
public:
    // Records `name = <expression>` and infers a type from the expression text.
    void observe_binding(const std::string& name, std::string_view initializer_text,
                         const std::vector<TypeRule>& rules);

    // Records an import so `subprocess.run(...)` knows what `subprocess` is.
    // Handles aliasing: `import subprocess as sp` binds sp.
    void observe_import(const std::string& bound_name, std::string_view module_path,
                        const std::vector<TypeRule>& rules);

    // Direct assertion, for a receiver whose type is known structurally rather
    // than by pattern (a RegExp literal, for instance).
    void assign(const std::string& name, ReceiverType type);

    ReceiverType type_of(std::string_view name) const;

    // Resolves the receiver of a dotted callee: for `db.query`, looks up `db`.
    // Falls back to matching the full dotted path against the rule table, so
    // `child_process.exec` resolves even with no local binding.
    ReceiverType receiver_type_of(std::string_view dotted_callee,
                                  const std::vector<TypeRule>& rules) const;

    std::size_t size() const noexcept { return bindings_.size(); }

private:
    std::map<std::string, ReceiverType, std::less<>> bindings_;
};

// Matches an expression against a rule table. Exposed for tests.
ReceiverType infer_from_expression(std::string_view expression,
                                   const std::vector<TypeRule>& rules);

// Walks a parsed file and populates a TypeEnvironment from its imports,
// assignments and regex literals.
//
// `typed_parameters` names the declarations that carry an explicit type, for
// languages that have them. In Go a handler's `w http.ResponseWriter` is the
// only place the type of `w` is ever written down, so without this pass the
// most reliable type information in the file went unused.
struct TypedParameterForm {
    std::string node_type;
    std::string name_field;
    std::string type_field;
};

TypeEnvironment build_type_environment(const ast::ParsedFile& file, TSNode root,
                                       const std::vector<TypeRule>& rules,
                                       const std::vector<std::string>& import_node_types,
                                       const std::vector<std::string>& assignment_node_types,
                                       const std::vector<TypedParameterForm>& typed_parameters = {});

}  // namespace sentinel

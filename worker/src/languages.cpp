#include "languages.hpp"

#include <algorithm>

#include "ast.hpp"

extern "C" const TSLanguage* tree_sitter_javascript(void);
extern "C" const TSLanguage* tree_sitter_python(void);
extern "C" const TSLanguage* tree_sitter_go(void);

namespace sentinel {
namespace {

// ===========================================================================
// JavaScript / TypeScript
// ===========================================================================

LanguageSpec make_javascript() {
    LanguageSpec s;
    s.id = Language::JavaScript;
    s.name = "javascript";
    s.grammar = tree_sitter_javascript();

    // ---- Structure --------------------------------------------------------

    s.assignment_forms = {
        {"variable_declarator", "name", "value"},
        {"assignment_expression", "left", "right"},
        {"augmented_assignment_expression", "left", "right"},
    };
    s.call_node_type = "call_expression";
    s.call_function_field = "function";
    s.call_arguments_field = "arguments";
    s.additional_call_forms = {
        {"new_expression", "constructor", "arguments"},
    };
    s.member_node_type = "member_expression";
    s.member_property_field = "property";

    s.function_definition_node_types = {
        "function_declaration", "function_expression", "arrow_function",
        "method_definition",    "generator_function_declaration",
    };
    s.function_name_field = "name";
    s.function_parameters_field = "parameters";
    s.function_body_field = "body";

    s.return_node_types = {"return_statement"};
    s.block_node_types = {"statement_block"};
    s.comment_node_types = {"comment"};
    s.import_node_types = {"import_statement", "lexical_declaration", "variable_declaration"};
    s.pair_node_types = {"pair"};
    s.concatenation_node_types = {"binary_expression", "template_string"};
    s.conditional_node_types = {"if_statement", "ternary_expression", "switch_statement"};
    s.subscript_node_types = {"subscript_expression"};

    // ---- Sources ----------------------------------------------------------

    s.sources = {
        {"req.query", "an HTTP query-string parameter", {}},
        {"req.body", "the HTTP request body", {}},
        {"req.params", "a URL path parameter", {}},
        {"req.headers", "an HTTP request header", {}},
        {"req.cookies", "an HTTP cookie", {}},
        {"req.url", "the raw request URL", {}},
        {"req.originalUrl", "the raw request URL", {}},
        {"request.query", "an HTTP query-string parameter", {}},
        {"request.body", "the HTTP request body", {}},
        {"request.params", "a URL path parameter", {}},
        {"request.headers", "an HTTP request header", {}},
        {"ctx.query", "a Koa query parameter", {}},
        {"ctx.request.body", "a Koa request body", {}},
        {"event.body", "a Lambda event body", {}},
        {"event.queryStringParameters", "a Lambda query parameter", {}},
        {"process.argv", "a command-line argument", {}, /*local=*/true},
        {"process.env", "an environment variable",
         {VulnClass::CommandInjection, VulnClass::PathTraversal}, /*local=*/true},
        {"location.search", "the browser URL query string", {}},
        {"location.hash", "the browser URL fragment", {}},
        {"location.href", "the browser URL", {}},
        {"document.URL", "the browser URL", {}},
        {"document.referrer", "the HTTP referrer", {}},
        {"window.name", "the window name, which a cross-origin opener controls", {}},
        {"localStorage.getItem", "browser local storage", {}},
        {"sessionStorage.getItem", "browser session storage", {}},
        // A file upload's declared filename is attacker-chosen and is the
        // classic path-traversal source, but is not a SQL or XSS source in the
        // same way, so it is scoped.
        {"file.originalname", "an uploaded file's declared name",
         {VulnClass::PathTraversal, VulnClass::CommandInjection}},
        {"req.file", "an uploaded file", {VulnClass::PathTraversal}},
        {"req.files", "uploaded files", {VulnClass::PathTraversal}},
        {"ctx.querystring", "the raw Koa query string", {}},
        {"ctx.params", "a Koa path parameter", {}},
        {"ctx.request.query", "a Koa query parameter", {}},
    };

    // ---- Call sinks -------------------------------------------------------

    s.call_sinks = {
        // Code execution.
        {"eval", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, "eval executes its argument as code"},
        {"Function", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, "the Function constructor compiles code from a string"},
        {"setTimeout", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, "a string first argument to setTimeout is evaluated"},
        {"setInterval", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, "a string first argument to setInterval is evaluated"},
        {"vm.runInNewContext", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},
        {"vm.runInThisContext", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},

        // SQL. Restricted to database receivers so `element.query` and
        // `regex.exec` do not fire. Only argument 0 -- the statement -- matters:
        // later arguments are the bound parameters, which the driver escapes,
        // and treating them as tainted would report every parameterised query.
        {"query", VulnClass::SqlInjection, ReceiverType::Database,
         ReceiverType::Unknown, 0, false, ""},
        {"execute", VulnClass::SqlInjection, ReceiverType::Database,
         ReceiverType::Unknown, 0, false, ""},
        {"raw", VulnClass::SqlInjection, ReceiverType::Database,
         ReceiverType::Unknown, 0, false, "knex .raw() interpolates directly"},
        {"whereRaw", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"sequelize.query", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},

        // Command execution. `exec` is only a shell call on a child_process
        // receiver -- this is the rule that used to fire on every RegExp.
        {"exec", VulnClass::CommandInjection, ReceiverType::ChildProcess,
         ReceiverType::Regex, -1, false, ""},
        {"execSync", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"spawn", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, "the command name is attacker-controlled"},
        {"spawnSync", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"execFile", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"child_process.exec", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},

        // Filesystem.
        {"readFile", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"readFileSync", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"writeFile", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"writeFileSync", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"unlink", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"createReadStream", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"createWriteStream", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"sendFile", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"readdir", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},

        // XSS through a call rather than a property write.
        {"document.write", VulnClass::CrossSiteScripting, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},
        {"insertAdjacentHTML", VulnClass::CrossSiteScripting, ReceiverType::Unknown,
         ReceiverType::Unknown, 1, false, ""},
        {"html", VulnClass::CrossSiteScripting, ReceiverType::DomElement,
         ReceiverType::Unknown, -1, false, "jQuery .html() parses its argument as HTML"},

        // SSRF.
        {"fetch", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"axios.get", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"axios.post", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"http.get", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"https.get", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"request", VulnClass::ServerSideRequestForgery, ReceiverType::HttpClient,
         ReceiverType::Unknown, 0, false, ""},

        // Open redirect.
        {"redirect", VulnClass::OpenRedirect, ReceiverType::HttpResponse,
         ReceiverType::Unknown, -1, false, ""},

        // Deserialization.
        {"deserialize", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"unserialize", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"load", VulnClass::InsecureDeserialization, ReceiverType::Serializer,
         ReceiverType::Unknown, -1, false, "js-yaml load() can construct arbitrary types",
         /*strict_receiver=*/true},

        // NoSQL. A tainted object reaching a Mongo filter allows operator
        // injection such as {"$ne": null}.
        {"find", VulnClass::NoSqlInjection, ReceiverType::MongoCollection,
         ReceiverType::Unknown, 0, false, "", false, -1, "where"},
        {"findOne", VulnClass::NoSqlInjection, ReceiverType::MongoCollection,
         ReceiverType::Unknown, 0, false, "", false, -1, "where"},
        {"deleteOne", VulnClass::NoSqlInjection, ReceiverType::MongoCollection,
         ReceiverType::Unknown, 0, false, "", false, -1, "where"},
        {"updateOne", VulnClass::NoSqlInjection, ReceiverType::MongoCollection,
         ReceiverType::Unknown, 0, false, "", false, -1, "where"},

        // Log injection.
        {"log", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, -1, false, ""},
        {"info", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, -1, false, ""},
        {"warn", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, -1, false, ""},
        {"error", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, -1, false, ""},
    };

    // ---- Property sinks ---------------------------------------------------

    s.property_sinks = {
        {"innerHTML", VulnClass::CrossSiteScripting, ReceiverType::Unknown,
         "innerHTML parses its value as HTML"},
        {"outerHTML", VulnClass::CrossSiteScripting, ReceiverType::Unknown, ""},
        {"dangerouslySetInnerHTML", VulnClass::CrossSiteScripting, ReceiverType::Unknown,
         "React's escape hatch bypasses JSX escaping"},
        {"srcdoc", VulnClass::CrossSiteScripting, ReceiverType::Unknown, ""},
        {"__proto__", VulnClass::PrototypePollution, ReceiverType::Unknown,
         "writing __proto__ mutates the prototype chain"},
    };

    // ---- Configuration rules (no taint required) --------------------------

    s.configuration_rules = {
        {"createHash('md5')", VulnClass::WeakCryptography, Severity::Medium,
         "MD5 is collision-broken and unsuitable for integrity or signatures"},
        {"createHash(\"md5\")", VulnClass::WeakCryptography, Severity::Medium,
         "MD5 is collision-broken and unsuitable for integrity or signatures"},
        {"createHash('sha1')", VulnClass::WeakCryptography, Severity::Medium,
         "SHA-1 is collision-broken and should not be used for signatures"},
        {"createHash(\"sha1\")", VulnClass::WeakCryptography, Severity::Medium,
         "SHA-1 is collision-broken and should not be used for signatures"},
        {"createCipher(", VulnClass::WeakCryptography, Severity::High,
         "createCipher derives a key with a broken KDF; use createCipheriv"},
        {"Math.random()", VulnClass::WeakCryptography, Severity::Low,
         "Math.random is not cryptographically secure; use crypto.randomBytes",
         /*needs_security_context=*/true},
        {"rejectUnauthorized: false", VulnClass::WeakCryptography, Severity::High,
         "TLS certificate verification is disabled"},
        {"NODE_TLS_REJECT_UNAUTHORIZED", VulnClass::WeakCryptography, Severity::High,
         "TLS certificate verification is disabled process-wide"},
    };

    // ---- Type rules -------------------------------------------------------

    s.type_rules = {
        {"child_process", ReceiverType::ChildProcess},
        {"require('child_process')", ReceiverType::ChildProcess},
        {"require(\"child_process\")", ReceiverType::ChildProcess},
        {"createConnection", ReceiverType::Database},
        {"createPool", ReceiverType::Database},
        {"new Pool", ReceiverType::Database},
        {"new Client", ReceiverType::Database},
        {"mysql.createConnection", ReceiverType::Database},
        {"pg.Pool", ReceiverType::Database},
        {"sqlite3.Database", ReceiverType::Database},
        {"knex(", ReceiverType::Database},
        {"sequelize", ReceiverType::Database},
        {"getConnection", ReceiverType::Database},
        {"document.getElementById", ReceiverType::DomElement},
        {"document.querySelector", ReceiverType::DomElement},
        {"document.createElement", ReceiverType::DomElement},
        {"$(", ReceiverType::DomElement},
        {"jquery", ReceiverType::DomElement},
        {"require('fs')", ReceiverType::FileSystem},
        {"require(\"fs\")", ReceiverType::FileSystem},
        {"axios", ReceiverType::HttpClient},
        {"node-fetch", ReceiverType::HttpClient},
        {"got(", ReceiverType::HttpClient},
        {"superagent", ReceiverType::HttpClient},
        {"winston", ReceiverType::Logger},
        {"pino", ReceiverType::Logger},
        {"bunyan", ReceiverType::Logger},
        {"createLogger", ReceiverType::Logger},
        {"new RegExp", ReceiverType::Regex},
        {"js-yaml", ReceiverType::Serializer},
        {"require('crypto')", ReceiverType::Crypto},
        {"db.collection", ReceiverType::MongoCollection},
        {"mongoClient", ReceiverType::MongoCollection},
        {"MongoClient", ReceiverType::MongoCollection},
    };

    // ---- Sanitizers -------------------------------------------------------

    s.sanitizers = SanitizerTable({
        // Numeric coercion is total: a number cannot carry a payload anywhere.
        {"parseInt", {}, "coerced to an integer", true},
        {"parseFloat", {}, "coerced to a float", true},
        {"Number", {}, "coerced to a number", true},
        {"Math.floor", {}, "coerced to a number", true},
        {"Math.abs", {}, "coerced to a number", true},
        {"toFixed", {}, "coerced to a fixed-point number", true},

        // HTML escaping fixes rendering only.
        {"escapeHtml", {VulnClass::CrossSiteScripting}, "HTML-escaped", false},
        {"escapeHTML", {VulnClass::CrossSiteScripting}, "HTML-escaped", false},
        {"sanitizeHtml", {VulnClass::CrossSiteScripting}, "run through sanitize-html", false},
        {"DOMPurify.sanitize", {VulnClass::CrossSiteScripting}, "sanitised by DOMPurify", false},
        {"he.encode", {VulnClass::CrossSiteScripting}, "HTML-entity encoded", false},
        {"he.escape", {VulnClass::CrossSiteScripting}, "HTML-entity encoded", false},
        // Matched by full dotted name only. A bare `escape` is not listed: in
        // JavaScript that is the deprecated percent-encoding global, and what a
        // user-defined `escape` does is anyone's guess.
        {"_.escape", {VulnClass::CrossSiteScripting}, "HTML-escaped by lodash", false},
        {"lodash.escape", {VulnClass::CrossSiteScripting}, "HTML-escaped by lodash", false},
        {"validator.escape", {VulnClass::CrossSiteScripting}, "HTML-escaped by validator",
         false},
        {"encodeURIComponent",
         {VulnClass::CrossSiteScripting, VulnClass::OpenRedirect,
          VulnClass::ServerSideRequestForgery},
         "URL-encoded", false},

        // Shell quoting fixes command injection only.
        {"shellQuote", {VulnClass::CommandInjection}, "shell-quoted", false},
        {"shellescape", {VulnClass::CommandInjection}, "shell-escaped", false},

        // Path normalisation fixes traversal only.
        {"path.basename", {VulnClass::PathTraversal}, "reduced to a basename", false},
        {"basename", {VulnClass::PathTraversal}, "reduced to a basename", false},
        {"sanitizeFilename", {VulnClass::PathTraversal}, "filename-sanitised", false},

        // SQL identifier escaping.
        {"escapeId", {VulnClass::SqlInjection}, "escaped as a SQL identifier", false},
        {"mysql.escape", {VulnClass::SqlInjection}, "escaped by the MySQL driver", false},
        {"connection.escape", {VulnClass::SqlInjection}, "escaped by the MySQL driver", false},
        {"pool.escape", {VulnClass::SqlInjection}, "escaped by the MySQL driver", false},
        {"db.escape", {VulnClass::SqlInjection}, "escaped by the database driver", false},
        {"sqlstring.escape", {VulnClass::SqlInjection}, "escaped by sqlstring", false},
        {"SqlString.escape", {VulnClass::SqlInjection}, "escaped by sqlstring", false},

        // A UUID or enum lookup constrains the value to a known set.
        {"validateUUID", {}, "constrained to a UUID", true},
        {"toUUID", {}, "constrained to a UUID", true},
    });

    // ---- Validators (confidence signal only) ------------------------------

    s.validators = ValidatorTable({
        {"isValid", {}},
        {"validate", {}},
        {"assert", {}},
        {"check", {}},
        {"isAllowed", {}},
        {"allowlist", {}},
        {"whitelist", {}},
        {"test", {VulnClass::PathTraversal, VulnClass::OpenRedirect}},
        {"startsWith", {VulnClass::PathTraversal, VulnClass::OpenRedirect,
                        VulnClass::ServerSideRequestForgery}},
        {"includes", {VulnClass::OpenRedirect, VulnClass::ServerSideRequestForgery}},
    });

    return s;
}

// ===========================================================================
// Python
// ===========================================================================

LanguageSpec make_python() {
    LanguageSpec s;
    s.id = Language::Python;
    s.name = "python";
    s.grammar = tree_sitter_python();

    s.assignment_forms = {
        {"assignment", "left", "right"},
        {"augmented_assignment", "left", "right"},
    };
    s.call_node_type = "call";
    s.call_function_field = "function";
    s.call_arguments_field = "arguments";
    s.member_node_type = "attribute";
    s.member_property_field = "attribute";

    s.function_definition_node_types = {"function_definition", "lambda"};
    s.function_name_field = "name";
    s.function_parameters_field = "parameters";
    s.function_body_field = "body";

    s.return_node_types = {"return_statement"};
    s.block_node_types = {"block"};
    s.comment_node_types = {"comment"};
    s.import_node_types = {"import_statement", "import_from_statement", "aliased_import"};
    s.pair_node_types = {"pair"};
    s.concatenation_node_types = {"binary_operator", "string", "concatenated_string"};
    s.conditional_node_types = {"if_statement", "conditional_expression"};
    s.subscript_node_types = {"subscript"};

    s.sources = {
        {"request.args", "a Flask query parameter", {}},
        {"request.form", "a Flask form field", {}},
        {"request.json", "a JSON request body", {}},
        {"request.data", "the raw request body", {}},
        {"request.values", "a request parameter", {}},
        {"request.files", "an uploaded file",
         {VulnClass::PathTraversal, VulnClass::CommandInjection}},
        {"request.cookies", "an HTTP cookie", {}},
        {"request.headers", "an HTTP request header", {}},
        {"request.GET", "a Django query parameter", {}},
        {"request.POST", "a Django form field", {}},
        {"request.body", "the Django request body", {}},
        {"request.query_params", "a DRF query parameter", {}},
        {"self.get_argument", "a Tornado request argument", {}},
        {"flask.request", "a Flask request object", {}},
        {"sys.argv", "a command-line argument", {}, /*local=*/true},
        {"input(", "interactive input", {}, /*local=*/true},
        {"os.environ", "an environment variable",
         {VulnClass::CommandInjection, VulnClass::PathTraversal}, /*local=*/true},
        {"event['body']", "a Lambda event body", {}},
        {"event.get('body')", "a Lambda event body", {}},
    };

    s.call_sinks = {
        {"eval", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, "eval executes its argument as Python"},
        {"exec", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Regex, -1, false, "exec executes its argument as Python"},
        {"compile", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"__import__", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},

        {"system", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, "os.system runs its argument through a shell"},
        {"popen", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"Popen", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"getoutput", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"check_output", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"check_call", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"subprocess.run", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"subprocess.call", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},

        {"execute", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"executemany", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"executescript", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"raw", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, "Django .raw() does not parameterise"},
        {"extra", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"text", VulnClass::SqlInjection, ReceiverType::Database,
         ReceiverType::Unknown, 0, false, "SQLAlchemy text() builds raw SQL"},

        {"open", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"send_file", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"send_from_directory", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 1, false, ""},
        {"remove", VulnClass::PathTraversal, ReceiverType::FileSystem,
         ReceiverType::Unknown, 0, false, ""},
        {"rmtree", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},

        // Requires an object-constructing serializer. json.loads is a
        // DataCodec, so it resolves to a known non-matching receiver and the
        // rule is skipped rather than firing on every JSON parse.
        // Strict: `loads` is what every serializer calls it, and most are
        // not pickle. itsdangerous verifies a signature and yields JSON;
        // reporting `s.loads(cookie)` there as CWE-502 is simply wrong. The
        // dangerous modules are matched by type here and by full name below.
        {"loads", VulnClass::InsecureDeserialization, ReceiverType::Serializer,
         ReceiverType::DataCodec, -1, false, "", /*strict_receiver=*/true},
        {"pickle.loads", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, "pickle can instantiate arbitrary objects"},
        {"pickle.load", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},
        {"cPickle.loads", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},
        {"yaml.load", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, "yaml.load without SafeLoader constructs objects"},
        {"marshal.loads", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},
        {"shelve.open", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},

        {"requests.get", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"requests.post", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"urlopen", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"urlretrieve", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},

        {"redirect", VulnClass::OpenRedirect, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},

        {"render_template_string", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, "Jinja SSTI leads to code execution"},
        {"Markup", VulnClass::CrossSiteScripting, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, "Markup() marks a string as trusted HTML"},

        {"find", VulnClass::NoSqlInjection, ReceiverType::MongoCollection,
         ReceiverType::Unknown, 0, false, "", false, -1, "where"},
        {"find_one", VulnClass::NoSqlInjection, ReceiverType::MongoCollection,
         ReceiverType::Unknown, 0, false, "", false, -1, "where"},

        {"xpath", VulnClass::XPathInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},

        {"info", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, -1, false, ""},
        {"warning", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, -1, false, ""},
        {"error", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, -1, false, ""},
    };

    s.property_sinks = {};

    s.configuration_rules = {
        {"hashlib.md5", VulnClass::WeakCryptography, Severity::Medium,
         "MD5 is collision-broken and unsuitable for integrity or signatures"},
        {"hashlib.sha1", VulnClass::WeakCryptography, Severity::Medium,
         "SHA-1 is collision-broken and should not be used for signatures"},
        {"hashlib.new('md5')", VulnClass::WeakCryptography, Severity::Medium,
         "MD5 is collision-broken"},
        {"DES.new", VulnClass::WeakCryptography, Severity::High,
         "DES has a 56-bit key and is trivially brute-forced"},
        {"ARC4.new", VulnClass::WeakCryptography, Severity::High,
         "RC4 is broken and must not be used"},
        {"ssl._create_unverified_context", VulnClass::WeakCryptography, Severity::High,
         "TLS certificate verification is disabled"},
        {"verify=False", VulnClass::WeakCryptography, Severity::High,
         "requests is configured to skip TLS certificate verification"},
        {"random.random()", VulnClass::WeakCryptography, Severity::Low,
         "random is not cryptographically secure; use the secrets module",
         /*needs_security_context=*/true},
        {"shell=True", VulnClass::CommandInjection, Severity::Medium,
         "shell=True routes the command through a shell interpreter"},
    };

    s.type_rules = {
        {"subprocess", ReceiverType::ChildProcess},
        {"os.popen", ReceiverType::ChildProcess},
        {"psycopg2", ReceiverType::Database},
        {"sqlite3", ReceiverType::Database},
        {"pymysql", ReceiverType::Database},
        {"cursor", ReceiverType::Database},
        {"connection.cursor", ReceiverType::Database},
        {"create_engine", ReceiverType::Database},
        {"sqlalchemy", ReceiverType::Database},
        {"os.path", ReceiverType::FileSystem},
        {"shutil", ReceiverType::FileSystem},
        {"pathlib", ReceiverType::FileSystem},
        {"requests", ReceiverType::HttpClient},
        {"httpx", ReceiverType::HttpClient},
        {"urllib", ReceiverType::HttpClient},
        {"logging", ReceiverType::Logger},
        {"getLogger", ReceiverType::Logger},
        {"loguru", ReceiverType::Logger},
        {"re.compile", ReceiverType::Regex},
        {"pickle", ReceiverType::Serializer},
        {"yaml", ReceiverType::Serializer},
        {"marshal", ReceiverType::Serializer},
        {"json", ReceiverType::DataCodec},
        {"simplejson", ReceiverType::DataCodec},
        {"ujson", ReceiverType::DataCodec},
        {"orjson", ReceiverType::DataCodec},
        {"hashlib", ReceiverType::Crypto},
        {"pymongo", ReceiverType::MongoCollection},
        {"MongoClient", ReceiverType::MongoCollection},
        {"db.collection", ReceiverType::MongoCollection},
    };

    s.sanitizers = SanitizerTable({
        {"int", {}, "coerced to an integer", true},
        {"float", {}, "coerced to a float", true},
        {"bool", {}, "coerced to a boolean", true},
        {"abs", {}, "coerced to a number", true},
        {"len", {}, "reduced to a length", true},

        {"html.escape", {VulnClass::CrossSiteScripting}, "HTML-escaped", false},
        {"escape", {VulnClass::CrossSiteScripting}, "HTML-escaped", false},
        {"bleach.clean", {VulnClass::CrossSiteScripting}, "sanitised by bleach", false},
        {"markupsafe.escape", {VulnClass::CrossSiteScripting}, "HTML-escaped", false},

        {"shlex.quote", {VulnClass::CommandInjection}, "shell-quoted", false},
        {"pipes.quote", {VulnClass::CommandInjection}, "shell-quoted", false},

        {"os.path.basename", {VulnClass::PathTraversal}, "reduced to a basename", false},
        {"secure_filename", {VulnClass::PathTraversal},
         "normalised by werkzeug secure_filename", false},
        {"werkzeug.utils.secure_filename", {VulnClass::PathTraversal},
         "normalised by werkzeug secure_filename", false},

        {"quote", {VulnClass::ServerSideRequestForgery, VulnClass::OpenRedirect},
         "URL-quoted", false},
        {"quote_plus", {VulnClass::ServerSideRequestForgery, VulnClass::OpenRedirect},
         "URL-quoted", false},

        {"uuid.UUID", {}, "constrained to a UUID", true},
        {"ObjectId", {}, "constrained to an ObjectId", true},
    });

    s.validators = ValidatorTable({
        {"isinstance", {}},
        {"validate", {}},
        {"assert", {}},
        {"is_safe_url", {VulnClass::OpenRedirect}},
        {"startswith", {VulnClass::PathTraversal, VulnClass::OpenRedirect,
                        VulnClass::ServerSideRequestForgery}},
        {"match", {}},
        {"fullmatch", {}},
        {"in", {}},
    });

    return s;
}

// ===========================================================================
// Go
// ===========================================================================

LanguageSpec make_go() {
    LanguageSpec s;
    s.id = Language::Go;
    s.name = "go";
    s.grammar = tree_sitter_go();

    s.assignment_forms = {
        {"short_var_declaration", "left", "right"},
        {"assignment_statement", "left", "right"},
        {"var_spec", "name", "value"},
        {"const_spec", "name", "value"},
    };
    s.call_node_type = "call_expression";
    s.call_function_field = "function";
    s.call_arguments_field = "arguments";
    s.member_node_type = "selector_expression";
    s.member_property_field = "field";

    s.function_definition_node_types = {"function_declaration", "method_declaration",
                                        "func_literal"};
    s.function_name_field = "name";
    s.function_parameters_field = "parameters";
    s.function_body_field = "body";

    s.return_node_types = {"return_statement"};
    s.block_node_types = {"block"};
    s.comment_node_types = {"comment"};
    s.import_node_types = {"import_declaration", "import_spec"};
    s.pair_node_types = {"keyed_element", "literal_element"};
    s.concatenation_node_types = {"binary_expression"};
    s.conditional_node_types = {"if_statement", "expression_switch_statement"};
    s.subscript_node_types = {"index_expression"};
    s.typed_parameter_forms = {{"parameter_declaration", "name", "type"}};

    // r.URL.Query() reads as a SQL sink by its last segment, so the analyzer
    // checks sources before sinks. These entries are what make that work.
    s.sources = {
        {"r.URL.Query", "a URL query parameter", {}},
        {"req.URL.Query", "a URL query parameter", {}},
        {"request.URL.Query", "a URL query parameter", {}},
        {"r.URL.Path", "the request path", {}},
        {"r.FormValue", "a form field", {}},
        {"req.FormValue", "a form field", {}},
        {"r.PostFormValue", "a form field", {}},
        {"r.Form", "the parsed form", {}},
        {"r.PostForm", "the parsed form", {}},
        {"r.MultipartForm", "a multipart form",
         {VulnClass::PathTraversal, VulnClass::CommandInjection}},
        {"r.Header.Get", "an HTTP request header", {}},
        {"r.Cookie", "an HTTP cookie", {}},
        {"r.Body", "the request body", {}},
        {"mux.Vars", "a gorilla/mux path variable", {}},
        {"c.Param", "a gin path parameter", {}},
        {"c.Query", "a gin query parameter", {}},
        {"c.PostForm", "a gin form field", {}},
        {"chi.URLParam", "a chi path parameter", {}},
        {"os.Args", "a command-line argument", {}, /*local=*/true},
        {"os.Getenv", "an environment variable",
         {VulnClass::CommandInjection, VulnClass::PathTraversal}, /*local=*/true},

        // Spelled out because sources match whole name segments: `c.Param`
        // does not cover `c.Params`, nor `r.Cookie` `r.Cookies`.
        {"c.Params", "gin path parameters", {}},
        {"c.DefaultQuery", "a gin query parameter", {}},
        {"c.GetQuery", "a gin query parameter", {}},
        {"c.QueryArray", "a gin query parameter", {}},
        {"c.DefaultPostForm", "a gin form field", {}},
        {"c.GetHeader", "an HTTP request header", {}},
        {"r.Cookies", "the request's cookies", {}},
        {"r.URL.RawQuery", "the raw query string", {}},
        {"r.RequestURI", "the raw request URI", {}},
    };

    s.call_sinks = {
        // On a prepared statement these take the bound parameters, not SQL:
        // `stmt.QueryRow(username)` is the safe form, so that receiver is
        // excluded. The statement text went to Prepare, which is still a sink.
        {"Query", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::PreparedStatement, 0, false, ""},
        {"QueryRow", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::PreparedStatement, 0, false, ""},
        {"QueryContext", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::PreparedStatement, 1, false, ""},
        {"QueryRowContext", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::PreparedStatement, 1, false, ""},
        {"Exec", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::PreparedStatement, 0, false, ""},
        {"ExecContext", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::PreparedStatement, 1, false, ""},
        {"Prepare", VulnClass::SqlInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"Raw", VulnClass::SqlInjection, ReceiverType::Database,
         ReceiverType::Unknown, 0, false, "gorm Raw() does not parameterise"},

        {"Command", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"CommandContext", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"exec.Command", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, ""},
        {"StartProcess", VulnClass::CommandInjection, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},

        {"Open", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"OpenFile", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"ReadFile", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"WriteFile", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"Remove", VulnClass::PathTraversal, ReceiverType::FileSystem,
         ReceiverType::Unknown, 0, false, ""},
        {"RemoveAll", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, false, ""},
        {"ServeFile", VulnClass::PathTraversal, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"Create", VulnClass::PathTraversal, ReceiverType::FileSystem,
         ReceiverType::Unknown, 0, false, ""},

        {"HTML", VulnClass::CrossSiteScripting, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, "template.HTML marks a string as trusted markup"},
        {"HTMLAttr", VulnClass::CrossSiteScripting, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        {"JS", VulnClass::CrossSiteScripting, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, false, ""},
        // Writing to a response is only an HTML sink when the writer really is
        // the response. Every hash, file, buffer and socket in Go has a Write
        // method, and Fprintf is how programs print to stderr, so these are
        // strict: the writer's type has to resolve, which for a handler it
        // does, from the `w http.ResponseWriter` parameter.
        {"Write", VulnClass::CrossSiteScripting, ReceiverType::HttpResponse,
         ReceiverType::Unknown, -1, false, "", /*strict_receiver=*/true},
        {"WriteString", VulnClass::CrossSiteScripting, ReceiverType::HttpResponse,
         ReceiverType::Unknown, -1, false, "", /*strict_receiver=*/true},
        // The writer is argument 0 here, and any later argument can carry the
        // payload -- the format string or the values interpolated into it.
        {"Fprintf", VulnClass::CrossSiteScripting, ReceiverType::HttpResponse,
         ReceiverType::Unknown, -1, false, "", /*strict_receiver=*/true, /*typed_argument=*/0},
        {"Fprint", VulnClass::CrossSiteScripting, ReceiverType::HttpResponse,
         ReceiverType::Unknown, -1, false, "", /*strict_receiver=*/true, /*typed_argument=*/0},
        {"Fprintln", VulnClass::CrossSiteScripting, ReceiverType::HttpResponse,
         ReceiverType::Unknown, -1, false, "", /*strict_receiver=*/true, /*typed_argument=*/0},
        {"io.WriteString", VulnClass::CrossSiteScripting, ReceiverType::HttpResponse,
         ReceiverType::Unknown, -1, true, "", /*strict_receiver=*/true, /*typed_argument=*/0},

        {"Get", VulnClass::ServerSideRequestForgery, ReceiverType::HttpClient,
         ReceiverType::Unknown, 0, false, ""},
        {"Post", VulnClass::ServerSideRequestForgery, ReceiverType::HttpClient,
         ReceiverType::Unknown, 0, false, ""},
        {"http.Get", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"http.Post", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, ""},
        {"NewRequest", VulnClass::ServerSideRequestForgery, ReceiverType::Unknown,
         ReceiverType::Unknown, 1, false, ""},

        {"Redirect", VulnClass::OpenRedirect, ReceiverType::Unknown,
         ReceiverType::Unknown, 2, false, ""},

        // Strict, because Unmarshal is the name every Go codec uses and almost
        // all of them -- encoding/json, xml, protobuf -- are data-only. Left
        // lenient, this reported every JSON request body as a CWE-502.
        {"Unmarshal", VulnClass::InsecureDeserialization, ReceiverType::Serializer,
         ReceiverType::Unknown, 0, false, "", /*strict_receiver=*/true},
        {"gob.NewDecoder", VulnClass::InsecureDeserialization, ReceiverType::Unknown,
         ReceiverType::Unknown, -1, true, "gob decoding of untrusted data is unsafe"},

        // Code injection. Go has no eval, so the equivalents are the places a
        // program hands a string to something that executes it: a template
        // engine, an embedded interpreter, or the plugin loader.
        {"Parse", VulnClass::RemoteCodeExecution, ReceiverType::Template,
         ReceiverType::Unknown, 0, false,
         "a template parsed from request data can call any method reachable from its inputs",
         /*strict_receiver=*/true},
        {"RunString", VulnClass::RemoteCodeExecution, ReceiverType::ScriptEngine,
         ReceiverType::Unknown, 0, false, "goja executes its argument as JavaScript"},
        {"DoString", VulnClass::RemoteCodeExecution, ReceiverType::ScriptEngine,
         ReceiverType::Unknown, 0, false, "gopher-lua executes its argument as Lua"},
        {"Run", VulnClass::RemoteCodeExecution, ReceiverType::ScriptEngine,
         ReceiverType::Unknown, 0, false, "the interpreter executes its argument as source",
         /*strict_receiver=*/true},
        {"Eval", VulnClass::RemoteCodeExecution, ReceiverType::ScriptEngine,
         ReceiverType::Unknown, 0, false, "the interpreter executes its argument as source",
         /*strict_receiver=*/true},
        {"expr.Eval", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, "expr evaluates its argument as an expression"},
        {"govaluate.NewEvaluableExpression", VulnClass::RemoteCodeExecution,
         ReceiverType::Unknown, ReceiverType::Unknown, 0, true, ""},
        {"plugin.Open", VulnClass::RemoteCodeExecution, ReceiverType::Unknown,
         ReceiverType::Unknown, 0, true, "loads and runs a shared object chosen by the request"},

        {"Printf", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, 1, false, ""},
        {"Println", VulnClass::LogInjection, ReceiverType::Logger,
         ReceiverType::Unknown, -1, false, ""},
    };

    s.property_sinks = {};

    s.configuration_rules = {
        {"md5.New()", VulnClass::WeakCryptography, Severity::Medium,
         "MD5 is collision-broken and unsuitable for integrity or signatures"},
        {"md5.Sum", VulnClass::WeakCryptography, Severity::Medium,
         "MD5 is collision-broken"},
        {"sha1.New()", VulnClass::WeakCryptography, Severity::Medium,
         "SHA-1 is collision-broken and should not be used for signatures"},
        {"des.NewCipher", VulnClass::WeakCryptography, Severity::High,
         "DES has a 56-bit key and is trivially brute-forced"},
        {"rc4.NewCipher", VulnClass::WeakCryptography, Severity::High,
         "RC4 is broken and must not be used"},
        {"InsecureSkipVerify: true", VulnClass::WeakCryptography, Severity::High,
         "TLS certificate verification is disabled"},
        {"math/rand", VulnClass::WeakCryptography, Severity::Low,
         "math/rand is not cryptographically secure; use crypto/rand"},
    };

    s.type_rules = {
        // Matches the initialiser `db.Prepare(q)` and the chained receiver
        // in `db.Prepare(q).QueryRow(x)`, and covers PrepareContext/Preparex.
        {".Prepare", ReceiverType::PreparedStatement},
        {"sql.Stmt", ReceiverType::PreparedStatement},
        {"sql.Open", ReceiverType::Database},
        {"sql.DB", ReceiverType::Database},
        {"sqlx", ReceiverType::Database},
        {"gorm", ReceiverType::Database},
        {"pgx", ReceiverType::Database},
        {"os/exec", ReceiverType::ChildProcess},
        {"exec.Command", ReceiverType::ChildProcess},
        {"os.Open", ReceiverType::FileSystem},
        {"ioutil", ReceiverType::FileSystem},
        {"filepath", ReceiverType::FileSystem},
        {"http.Client", ReceiverType::HttpClient},
        {"http.DefaultClient", ReceiverType::HttpClient},
        {"ResponseWriter", ReceiverType::HttpResponse},
        {"log.New", ReceiverType::Logger},
        {"logrus", ReceiverType::Logger},
        {"zap", ReceiverType::Logger},
        {"regexp.MustCompile", ReceiverType::Regex},
        {"regexp.Compile", ReceiverType::Regex},
        {"encoding/gob", ReceiverType::Serializer},
        {"crypto", ReceiverType::Crypto},
        {"mongo.Collection", ReceiverType::MongoCollection},
        {"log.Logger", ReceiverType::Logger},
        {"template.New", ReceiverType::Template},
        {"template.Must", ReceiverType::Template},
        {"template.Template", ReceiverType::Template},
        {"goja.New", ReceiverType::ScriptEngine},
        {"otto.New", ReceiverType::ScriptEngine},
        {"interp.New", ReceiverType::ScriptEngine},
        {"lua.NewState", ReceiverType::ScriptEngine},
    };

    s.sanitizers = SanitizerTable({
        {"strconv.Atoi", {}, "parsed as an integer", true},
        {"strconv.ParseInt", {}, "parsed as an integer", true},
        {"strconv.ParseFloat", {}, "parsed as a float", true},
        {"strconv.ParseBool", {}, "parsed as a boolean", true},

        {"template.HTMLEscapeString", {VulnClass::CrossSiteScripting}, "HTML-escaped", false},
        {"html.EscapeString", {VulnClass::CrossSiteScripting}, "HTML-escaped", false},

        {"filepath.Base", {VulnClass::PathTraversal}, "reduced to a basename", false},
        {"filepath.Clean", {VulnClass::PathTraversal}, "path-normalised", false},
        {"path.Base", {VulnClass::PathTraversal}, "reduced to a basename", false},

        {"url.QueryEscape", {VulnClass::ServerSideRequestForgery, VulnClass::OpenRedirect},
         "URL-escaped", false},
        {"url.PathEscape", {VulnClass::PathTraversal, VulnClass::OpenRedirect},
         "URL-escaped", false},

        {"uuid.Parse", {}, "constrained to a UUID", true},
        {"uuid.MustParse", {}, "constrained to a UUID", true},
    });

    s.validators = ValidatorTable({
        {"Validate", {}},
        {"IsValid", {}},
        {"HasPrefix", {VulnClass::PathTraversal, VulnClass::OpenRedirect,
                       VulnClass::ServerSideRequestForgery}},
        {"Contains", {VulnClass::OpenRedirect, VulnClass::ServerSideRequestForgery}},
        {"MatchString", {}},
    });

    return s;
}

const LanguageSpec kJavaScript = make_javascript();
const LanguageSpec kPython = make_python();
const LanguageSpec kGo = make_go();

}  // namespace

// ---- LanguageSpec helpers -------------------------------------------------

std::vector<std::string> LanguageSpec::assignment_node_types() const {
    std::vector<std::string> types;
    types.reserve(assignment_forms.size());
    for (const auto& form : assignment_forms) {
        if (!std::ranges::contains(types, form.node_type)) {
            types.push_back(form.node_type);
        }
    }
    return types;
}

bool source_pattern_matches(std::string_view expression, std::string_view pattern) noexcept {
    if (pattern.empty()) return false;

    const auto is_identifier_char = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '$';
    };
    // A boundary is only required on a side where the pattern itself ends in
    // an identifier character: `input(` already ends at a boundary.
    const bool check_left = is_identifier_char(pattern.front());
    const bool check_right = is_identifier_char(pattern.back());

    for (std::size_t at = expression.find(pattern); at != std::string_view::npos;
         at = expression.find(pattern, at + 1)) {
        const std::size_t end = at + pattern.size();
        const bool left_ok = !check_left || at == 0 || !is_identifier_char(expression[at - 1]);
        const bool right_ok =
            !check_right || end == expression.size() || !is_identifier_char(expression[end]);
        if (left_ok && right_ok) return true;
    }
    return false;
}

const SourceRule* LanguageSpec::match_source(std::string_view expression) const {
    // Longest pattern wins, so `request.URL.Query` beats `request` if both are
    // present and the more specific description reaches the trace.
    const SourceRule* best = nullptr;
    for (const auto& rule : sources) {
        if (!source_pattern_matches(expression, rule.pattern)) continue;
        if (best == nullptr || rule.pattern.size() > best->pattern.size()) best = &rule;
    }
    return best;
}

bool LanguageSpec::is_source_for(std::string_view expression, VulnClass id) const {
    // Any matching rule scoped to this class counts, not just the longest --
    // a broad source and a narrow one can both match the same expression.
    for (const auto& rule : sources) {
        if (!source_pattern_matches(expression, rule.pattern)) continue;
        if (rule.classes.empty()) return true;
        if (std::ranges::contains(rule.classes, id)) {
            return true;
        }
    }
    return false;
}

// ---- Registry -------------------------------------------------------------

std::string_view to_string(Language language) noexcept {
    switch (language) {
        case Language::JavaScript: return "javascript";
        case Language::Python: return "python";
        case Language::Go: return "go";
        case Language::Unknown: return "unknown";
    }
    return "unknown";
}

Language language_for_path(std::string_view path) {
    // Strip a query string or fragment; scan jobs sometimes carry URLs.
    const auto cut = path.find_first_of("?#");
    if (cut != std::string_view::npos) path = path.substr(0, cut);

    if (ast::ends_with(path, ".js") || ast::ends_with(path, ".jsx") ||
        ast::ends_with(path, ".mjs") || ast::ends_with(path, ".cjs") ||
        ast::ends_with(path, ".ts") || ast::ends_with(path, ".tsx")) {
        // The JavaScript grammar parses the great majority of TypeScript; the
        // type annotations it cannot handle become ERROR nodes, which downgrade
        // confidence rather than losing the file entirely.
        return Language::JavaScript;
    }
    if (ast::ends_with(path, ".py") || ast::ends_with(path, ".pyi")) return Language::Python;
    if (ast::ends_with(path, ".go")) return Language::Go;
    return Language::Unknown;
}

const LanguageSpec* spec_for(Language language) {
    switch (language) {
        case Language::JavaScript: return &kJavaScript;
        case Language::Python: return &kPython;
        case Language::Go: return &kGo;
        case Language::Unknown: return nullptr;
    }
    return nullptr;
}

std::vector<Language> supported_languages() {
    return {Language::JavaScript, Language::Python, Language::Go};
}

std::vector<ClassCoverage> class_coverage(const LanguageSpec& spec) {
    std::vector<ClassCoverage> coverage;
    for (const auto& meta : all_vulnerability_classes()) {
        if (meta.id == VulnClass::Unknown) continue;

        ClassCoverage entry;
        entry.id = meta.id;
        entry.by_taint =
            std::ranges::contains(spec.call_sinks, meta.id, &SinkRule::vulnerability) ||
            std::ranges::contains(spec.property_sinks, meta.id, &PropertySinkRule::vulnerability);
        entry.by_pattern = std::ranges::contains(spec.configuration_rules, meta.id,
                                                 &ConfigurationRule::vulnerability);

        // Secret detection lives in secrets.cpp and runs on every language; it
        // has no row in these tables.
        if (meta.id == VulnClass::HardcodedSecret) entry.by_pattern = true;

        coverage.push_back(entry);
    }
    return coverage;
}

std::size_t total_rule_count() {
    std::size_t total = 0;
    for (const Language language : supported_languages()) {
        const LanguageSpec* spec = spec_for(language);
        if (spec == nullptr) continue;
        total += spec->sources.size();
        total += spec->call_sinks.size();
        total += spec->property_sinks.size();
        total += spec->configuration_rules.size();
        total += spec->type_rules.size();
        total += spec->sanitizers.size();
        total += spec->validators.size();
    }
    return total;
}

}  // namespace sentinel

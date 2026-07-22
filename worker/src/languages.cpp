#include "languages.hpp"

#include <algorithm>

extern "C" const TSLanguage* tree_sitter_javascript(void);
extern "C" const TSLanguage* tree_sitter_python(void);
extern "C" const TSLanguage* tree_sitter_go(void);

namespace sentinel {
namespace {

LanguageSpec make_javascript() {
    LanguageSpec s;
    s.id = Language::JavaScript;
    s.name = "javascript";
    s.grammar = tree_sitter_javascript();
    s.assignment_forms = {
        {"variable_declarator", "name", "value"},
        {"assignment_expression", "left", "right"},
        {"augmented_assignment_expression", "left", "right"},
    };
    s.call_node_type = "call_expression";
    s.call_function_field = "function";
    s.call_arguments_field = "arguments";
    s.member_node_type = "member_expression";
    s.member_property_field = "property";
    s.source_patterns = {
        "req.query", "req.body", "req.params", "req.headers",
        "request.query", "request.body", "request.params",
        "process.argv", "location.search", "location.hash", "document.URL",
    };
    s.call_sinks = {
        {"eval", "Remote Code Execution"},
        {"Function", "Remote Code Execution"},
        {"query", "SQL Injection"},
        {"execute", "SQL Injection"},
        {"raw", "SQL Injection"},
        {"exec", "Command Injection"},
        {"execSync", "Command Injection"},
        {"spawn", "Command Injection"},
        {"spawnSync", "Command Injection"},
        {"write", "Cross-Site Scripting"},   // document.write
        {"readFile", "Path Traversal"},
        {"readFileSync", "Path Traversal"},
        {"createReadStream", "Path Traversal"},
        {"sendFile", "Path Traversal"},
    };
    s.property_sinks = {
        {"innerHTML", "Cross-Site Scripting"},
        {"outerHTML", "Cross-Site Scripting"},
        {"dangerouslySetInnerHTML", "Cross-Site Scripting"},
    };
    return s;
}

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
    s.source_patterns = {
        "request.args", "request.form", "request.json", "request.data",
        "request.values", "request.GET", "request.POST", "request.cookies",
        "sys.argv", "input(", "os.environ",
    };
    s.call_sinks = {
        {"eval", "Remote Code Execution"},
        {"exec", "Remote Code Execution"},
        {"system", "Command Injection"},        // os.system
        {"popen", "Command Injection"},
        {"Popen", "Command Injection"},
        {"call", "Command Injection"},          // subprocess.call
        {"run", "Command Injection"},           // subprocess.run
        {"check_output", "Command Injection"},
        {"execute", "SQL Injection"},
        {"executemany", "SQL Injection"},
        {"raw", "SQL Injection"},
        {"open", "Path Traversal"},
        {"send_file", "Path Traversal"},
    };
    return s;
}

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
    // Note: r.URL.Query() is a *source*; the analyzer checks source patterns
    // before sink rules so it is not mistaken for a database Query() sink.
    s.source_patterns = {
        "r.URL.Query", "req.URL.Query", "request.URL.Query",
        "r.FormValue", "req.FormValue", "r.PostFormValue",
        "r.Form", "r.PostForm", "mux.Vars", "os.Args", "r.Header.Get",
    };
    s.call_sinks = {
        {"Query", "SQL Injection"},
        {"QueryRow", "SQL Injection"},
        {"QueryContext", "SQL Injection"},
        {"Exec", "SQL Injection"},
        {"ExecContext", "SQL Injection"},
        {"Command", "Command Injection"},       // exec.Command
        {"CommandContext", "Command Injection"},
        {"Open", "Path Traversal"},
        {"ReadFile", "Path Traversal"},
        {"OpenFile", "Path Traversal"},
        {"ServeFile", "Path Traversal"},
        {"HTML", "Cross-Site Scripting"},       // template.HTML
        {"Write", "Cross-Site Scripting"},
    };
    return s;
}

const LanguageSpec kJavaScript = make_javascript();
const LanguageSpec kPython = make_python();
const LanguageSpec kGo = make_go();

bool ends_with(const std::string& value, const std::string& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}  // namespace

Language language_for_path(const std::string& path) {
    if (ends_with(path, ".js") || ends_with(path, ".jsx") || ends_with(path, ".mjs") ||
        ends_with(path, ".cjs")) {
        return Language::JavaScript;
    }
    if (ends_with(path, ".py")) return Language::Python;
    if (ends_with(path, ".go")) return Language::Go;
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

}  // namespace sentinel

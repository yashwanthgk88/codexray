/**
 * PHP knowledge base: sinks, taint sources (superglobals), and blind-spot calls.
 * Facts to surface for manual review — not severities, not verdicts.
 */
import { Knowledge } from "../adapters/types";

export const phpKnowledge: Knowledge = {
  sinks: {
    // OS command execution
    "system": ["command_exec", "runs a shell command"],
    "exec": ["command_exec", "runs a shell command"],
    "shell_exec": ["command_exec", "runs a shell command (backtick operator)"],
    "passthru": ["command_exec", "runs a shell command, streams output"],
    "popen": ["command_exec", "opens a process pipe"],
    "proc_open": ["command_exec", "spawns a process"],
    "pcntl_exec": ["command_exec", "executes a program"],
    // Code execution
    "eval": ["code_exec", "evaluates a string as PHP code"],
    "assert": ["code_exec", "evaluates a string as PHP code (assert)"],
    "create_function": ["code_exec", "creates a function from a string"],
    "call_user_func": ["code_exec", "calls a function named by a string"],
    "call_user_func_array": ["code_exec", "calls a function named by a string"],
    "preg_replace": ["code_exec", "with the /e modifier, evaluates code"],
    // SQL
    "mysqli_query": ["sql", "executes a SQL statement"],
    "mysql_query": ["sql", "executes a SQL statement (legacy)"],
    "mysqli_multi_query": ["sql", "executes multiple SQL statements"],
    "pg_query": ["sql", "executes a SQL statement (postgres)"],
    "query": ["sql", "executes a SQL statement (db object)"],
    "real_query": ["sql", "executes a SQL statement"],
    "prepare": ["sql", "prepares a SQL statement (db object)"],
    // File inclusion (PHP language constructs, handled specially)
    "include": ["file_inclusion", "includes and executes a PHP file"],
    "include_once": ["file_inclusion", "includes and executes a PHP file"],
    "require": ["file_inclusion", "includes and executes a PHP file"],
    "require_once": ["file_inclusion", "includes and executes a PHP file"],
    // File I/O
    "fopen": ["file_io", "opens a file path"],
    "file_get_contents": ["file_io", "reads a file / URL"],
    "file_put_contents": ["file_io", "writes a file"],
    "readfile": ["file_io", "reads and outputs a file"],
    "file": ["file_io", "reads a file into an array"],
    "fwrite": ["file_io", "writes to a file handle"],
    "unlink": ["file_io", "deletes a file"],
    "copy": ["file_io", "copies a file"],
    "move_uploaded_file": ["file_io", "moves an uploaded file"],
    "scandir": ["file_io", "lists a directory"],
    // Deserialization
    "unserialize": ["deserialization", "deserializes untrusted data"],
    // Output / XSS
    "echo": ["xss", "writes to the HTTP response body"],
    "print": ["xss", "writes to the HTTP response body"],
    "printf": ["xss", "writes formatted output to the response"],
    "print_r": ["xss", "writes a variable to output"],
    "var_dump": ["xss", "writes a variable to output"],
    // Headers / redirect
    "header": ["header_injection", "sets an HTTP response header"],
    "setcookie": ["header_injection", "sets a cookie header"],
    // SSRF / outbound
    "curl_exec": ["ssrf", "makes an outbound request"],
    "fsockopen": ["ssrf", "opens a network socket"],
    // Variable injection
    "extract": ["variable_injection", "imports names into the symbol table"],
    "parse_str": ["variable_injection", "parses a string into variables"],
    // LDAP / XPath
    "ldap_search": ["ldap", "runs an LDAP query"],
  },
  // PHP superglobals that carry attacker-controlled input. Deliberately excludes
  // $GLOBALS (usually app state / DB handles) and $_SESSION (server-side) to keep
  // the taint signal high — the analyst can widen this if their app warrants it.
  sources: new Set<string>([
    "_GET", "_POST", "_REQUEST", "_COOKIE", "_SERVER", "_FILES",
    "HTTP_RAW_POST_DATA",
  ]),
  // Dynamic dispatch / reflection static analysis cannot resolve.
  blindspots: {
    "call_user_func": "dynamic function dispatch",
    "call_user_func_array": "dynamic function dispatch",
    "extract": "runtime symbol table mutation",
    "variable_variable": "variable variable ($$x) — dynamic name",
    "variable_function": "variable function ($fn()) — dynamic dispatch",
  },
  // Existing defenses: if a tainted value passes through one of these before the
  // sink, the flow is (at least partially) controlled. `cats` says which sink
  // classes it actually defends; "*" = generic neutralizer (e.g. numeric cast).
  sanitizers: {
    // command execution
    "escapeshellarg": { label: "escapeshellarg()", cats: ["command_exec"] },
    "escapeshellcmd": { label: "escapeshellcmd()", cats: ["command_exec"] },
    // SQL
    "mysqli_real_escape_string": { label: "mysqli_real_escape_string()", cats: ["sql"] },
    "real_escape_string": { label: "->real_escape_string()", cats: ["sql"] },
    "pg_escape_string": { label: "pg_escape_string()", cats: ["sql"] },
    "pg_escape_literal": { label: "pg_escape_literal()", cats: ["sql"] },
    "addslashes": { label: "addslashes()", cats: ["sql"] },
    "quote": { label: "->quote()", cats: ["sql"] },
    // XSS / output
    "htmlspecialchars": { label: "htmlspecialchars()", cats: ["xss"] },
    "htmlentities": { label: "htmlentities()", cats: ["xss"] },
    "strip_tags": { label: "strip_tags()", cats: ["xss"] },
    // headers / redirects / URLs
    "urlencode": { label: "urlencode()", cats: ["header_injection", "ssrf"] },
    "rawurlencode": { label: "rawurlencode()", cats: ["header_injection", "ssrf"] },
    // file paths
    "basename": { label: "basename()", cats: ["file_inclusion", "file_io"] },
    "realpath": { label: "realpath()", cats: ["file_inclusion", "file_io"] },
    // generic validators / neutralizers (defend most classes when they pass)
    "intval": { label: "intval()", cats: ["*"] },
    "floatval": { label: "floatval()", cats: ["*"] },
    "abs": { label: "abs()", cats: ["*"] },
    "filter_var": { label: "filter_var()", cats: ["*"] },
    "preg_match": { label: "preg_match() allow-list check", cats: ["*"] },
    "ctype_digit": { label: "ctype_digit() check", cats: ["*"] },
    "ctype_alnum": { label: "ctype_alnum() check", cats: ["*"] },
    "is_numeric": { label: "is_numeric() check", cats: ["*"] },
    "in_array": { label: "in_array() allow-list check", cats: ["*"] },
  },
};

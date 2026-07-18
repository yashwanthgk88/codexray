/**
 * TypeScript / JavaScript knowledge base (Node.js / Express / NestJS).
 * Facts to surface for manual review — not severities.
 */
import { Knowledge } from "../adapters/types";

/** Objects whose members carry untrusted request input (Express/Koa/serverless). */
export const REQUEST_OBJECTS = new Set<string>(["req", "request", "ctx", "process", "event"]);

/** Members of a request object that are untrusted. */
export const REQUEST_MEMBERS = new Set<string>([
  "query", "body", "params", "headers", "cookies", "url", "originalUrl",
  "env", "argv", // process.env / process.argv
  "queryStringParameters", "pathParameters", // lambda event
]);

/** Route-registration methods on app/router that mark the callback as an entry. */
export const ROUTE_METHODS = new Set<string>([
  "get", "post", "put", "delete", "patch", "all", "use", "options", "head",
]);

/** LHS member properties that write to the DOM / response (XSS sinks). */
export const DOM_SINK_PROPS = new Set<string>(["innerHTML", "outerHTML"]);

export const typescriptKnowledge: Knowledge = {
  sinks: {
    // OS command execution
    "exec": ["command_exec", "runs a shell command (child_process)"],
    "execSync": ["command_exec", "runs a shell command synchronously"],
    "spawn": ["command_exec", "spawns a process"],
    "spawnSync": ["command_exec", "spawns a process synchronously"],
    "execFile": ["command_exec", "executes a file"],
    // Code execution
    "eval": ["code_exec", "evaluates a string as code"],
    "Function": ["code_exec", "constructs a function from a string"],
    "runInContext": ["code_exec", "runs code in a VM context"],
    "runInNewContext": ["code_exec", "runs code in a VM context"],
    // SQL
    "query": ["sql", "executes a database query"],
    "execute": ["sql", "executes a database statement"],
    "raw": ["sql", "builds a raw SQL fragment"],
    // File I/O
    "readFile": ["file_io", "reads a file"],
    "readFileSync": ["file_io", "reads a file"],
    "writeFile": ["file_io", "writes a file"],
    "writeFileSync": ["file_io", "writes a file"],
    "createReadStream": ["file_io", "opens a file stream"],
    "unlink": ["file_io", "deletes a file"],
    "sendFile": ["file_io", "returns a file to the client"],
    // Response / XSS
    "send": ["xss", "writes to the HTTP response"],
    "write": ["xss", "writes to the HTTP response / document"],
    "end": ["xss", "writes and ends the HTTP response"],
    // Headers / redirect
    "redirect": ["header_injection", "sets a redirect Location header"],
    "setHeader": ["header_injection", "sets an HTTP response header"],
    "header": ["header_injection", "sets an HTTP response header"],
    // SSRF / outbound
    "fetch": ["ssrf", "makes an outbound HTTP request"],
    "request": ["ssrf", "makes an outbound HTTP request"],
  },
  // Simple member names; adapter's directSource resolves req.<member>.
  sources: new Set<string>([...REQUEST_MEMBERS]),
  blindspots: {
    "eval": "runtime code construction",
    "Function": "dynamic function construction",
    "require": "dynamic module require (if argument is dynamic)",
    "import": "dynamic import",
  },
  sanitizers: {
    // XSS
    "sanitize": { label: "DOMPurify.sanitize()", cats: ["xss"] },
    "escape": { label: "escape()", cats: ["xss", "sql"] },
    "escapeHtml": { label: "escapeHtml()", cats: ["xss"] },
    // URL / headers / SSRF
    "encodeURIComponent": { label: "encodeURIComponent()", cats: ["header_injection", "ssrf"] },
    "encodeURI": { label: "encodeURI()", cats: ["header_injection", "ssrf"] },
    // path
    "basename": { label: "path.basename()", cats: ["file_io"] },
    "normalize": { label: "path.normalize()", cats: ["file_io"] },
    // generic validators / neutralisers
    "parseInt": { label: "parseInt()", cats: ["*"] },
    "parseFloat": { label: "parseFloat()", cats: ["*"] },
    "Number": { label: "Number()", cats: ["*"] },
    "test": { label: "RegExp.test() allow-list check", cats: ["*"] },
    "parse": { label: "validator/zod parse()", cats: ["*"] },
  },
};

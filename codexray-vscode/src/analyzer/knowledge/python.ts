/**
 * Python knowledge base: entry-point decorators, sinks, taint sources, blind spots.
 * Ported verbatim from xray.py. These are FACTS to surface, not judgments.
 */
import { Knowledge } from "../adapters/types";

// Decorators that mark HTTP route entry points, by framework.
export const ROUTE_DECORATORS = new Set<string>([
  "route", "get", "post", "put", "delete", "patch", // flask / fastapi
  "api_route", "websocket",
]);

// Methods that mark HTTP verbs (for decorator method inference).
export const HTTP_VERBS = new Set<string>(["get", "post", "put", "delete", "patch"]);

export const pythonKnowledge: Knowledge = {
  sinks: {
    "os.system": ["command_exec", "runs a shell command"],
    "os.popen": ["command_exec", "runs a shell command"],
    "subprocess.call": ["command_exec", "spawns a process"],
    "subprocess.run": ["command_exec", "spawns a process"],
    "subprocess.Popen": ["command_exec", "spawns a process"],
    "subprocess.check_output": ["command_exec", "spawns a process"],
    "eval": ["code_exec", "evaluates a string as code"],
    "exec": ["code_exec", "executes a string as code"],
    "pickle.load": ["deserialization", "deserializes untrusted data"],
    "pickle.loads": ["deserialization", "deserializes untrusted data"],
    "yaml.load": ["deserialization", "deserializes untrusted data"],
    "cursor.execute": ["sql", "executes a SQL statement"],
    "execute": ["sql", "executes a SQL statement (db cursor)"],
    "executemany": ["sql", "executes SQL statements"],
    "open": ["file_io", "opens a file path"],
    "send_file": ["file_io", "returns a file to the client"],
    "render_template_string": ["template_injection", "renders a template from a string"],
    "Markup": ["xss", "marks a string as safe HTML"],
    "make_response": ["response_write", "writes an HTTP response"],
    "requests.get": ["ssrf", "makes an outbound HTTP request"],
    "requests.post": ["ssrf", "makes an outbound HTTP request"],
    "urllib.request.urlopen": ["ssrf", "makes an outbound HTTP request"],
  },
  sources: new Set<string>([
    "request", "args", "form", "json", "get_json", "values", "cookies",
    "headers", "params", "query_params", "input", "argv", "environ",
  ]),
  blindspots: {
    "getattr": "dynamic attribute / method dispatch",
    "setattr": "dynamic attribute assignment",
    "__import__": "dynamic import",
    "importlib.import_module": "dynamic import",
    "globals": "runtime symbol table access",
    "locals": "runtime symbol table access",
    "eval": "runtime code construction",
    "exec": "runtime code construction",
  },
};

/**
 * Java knowledge base: HTTP entry annotations, sinks, taint sources, blind
 * spots and sanitizers. Facts to surface for manual review — not severities.
 */
import { Knowledge } from "../adapters/types";

/** Annotations that mark an HTTP route entry point (Spring MVC + JAX-RS). */
export const ROUTE_ANNOTATIONS = new Set<string>([
  "RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
  "PatchMapping", "Path", "GET", "POST", "PUT", "DELETE", "PATCH",
]);

/** Parameter annotations that bind untrusted request data to a method argument. */
export const SOURCE_PARAM_ANNOTATIONS = new Set<string>([
  "RequestParam", "PathVariable", "RequestBody", "RequestHeader", "CookieValue",
  "RequestPart", "MatrixVariable", "ModelAttribute",
  "QueryParam", "PathParam", "HeaderParam", "FormParam", "CookieParam", // JAX-RS
]);

export const javaKnowledge: Knowledge = {
  sinks: {
    // OS command execution
    "exec": ["command_exec", "runs a shell command (Runtime.exec / ProcessBuilder)"],
    "command": ["command_exec", "builds a process command line"],
    "start": ["command_exec", "starts a process (ProcessBuilder.start)"],
    // Code / expression execution
    "eval": ["code_exec", "evaluates a script string (ScriptEngine)"],
    "forName": ["code_exec", "loads a class by name (reflection)"],
    "newInstance": ["code_exec", "instantiates a class by name (reflection)"],
    "getMethod": ["code_exec", "resolves a method by name (reflection)"],
    "invoke": ["code_exec", "invokes a method reflectively"],
    // SQL
    "executeQuery": ["sql", "executes a SQL query"],
    "executeUpdate": ["sql", "executes a SQL update"],
    "execute": ["sql", "executes a SQL statement"],
    "prepareStatement": ["sql", "prepares a SQL statement (safe only if parameterised)"],
    "createQuery": ["sql", "creates a JPA/HQL query"],
    "createNativeQuery": ["sql", "creates a native SQL query"],
    "createSQLQuery": ["sql", "creates a native SQL query (Hibernate)"],
    // Deserialization
    "readObject": ["deserialization", "deserializes an object stream"],
    "readUnshared": ["deserialization", "deserializes an object stream"],
    // File I/O
    "getResource": ["file_io", "resolves a resource path"],
    // XXE / XML
    "parse": ["deserialization", "parses XML (XXE risk if unconfigured)"],
    // Response / XSS
    "getWriter": ["response_write", "obtains the HTTP response writer"],
    "print": ["xss", "writes to the HTTP response"],
    "println": ["xss", "writes to the HTTP response"],
    "sendRedirect": ["header_injection", "sets a redirect Location header"],
    "setHeader": ["header_injection", "sets an HTTP response header"],
    "addHeader": ["header_injection", "adds an HTTP response header"],
    "addCookie": ["header_injection", "sets a cookie header"],
    // SSRF / outbound
    "openConnection": ["ssrf", "opens an outbound URL connection"],
    "openStream": ["ssrf", "opens an outbound URL stream"],
    // Template injection (SpEL / OGNL)
    "parseExpression": ["template_injection", "parses an expression (SpEL/OGNL)"],
    "getValue": ["template_injection", "evaluates an expression"],
  },
  // Java taint enters through request-accessor CALLS and request-bound params.
  // These are method names on request-like objects (see adapter's directSource).
  sources: new Set<string>([
    "getParameter", "getParameterValues", "getParameterMap",
    "getHeader", "getHeaders", "getQueryString", "getCookies",
    "getInputStream", "getReader", "getRequestURI", "getRequestURL",
    "getPathInfo", "getRemoteUser", "getRemoteAddr",
  ]),
  blindspots: {
    "forName": "dynamic class loading (reflection)",
    "newInstance": "reflective instantiation",
    "invoke": "reflective method dispatch",
    "getMethod": "reflective method resolution",
    "getDeclaredMethod": "reflective method resolution",
    "loadClass": "dynamic class loading",
  },
  sanitizers: {
    // SQL — parameter binding neutralises injection
    "setString": { label: "PreparedStatement.setString()", cats: ["sql"] },
    "setInt": { label: "PreparedStatement.setInt()", cats: ["sql", "*"] },
    "setLong": { label: "PreparedStatement.setLong()", cats: ["sql", "*"] },
    // XSS / output encoding (OWASP Java Encoder, ESAPI, Spring)
    "htmlEscape": { label: "HtmlUtils.htmlEscape()", cats: ["xss"] },
    "forHtml": { label: "Encode.forHtml()", cats: ["xss"] },
    "forHtmlAttribute": { label: "Encode.forHtmlAttribute()", cats: ["xss"] },
    "encodeForHTML": { label: "ESAPI encodeForHTML()", cats: ["xss"] },
    "escapeHtml4": { label: "StringEscapeUtils.escapeHtml4()", cats: ["xss"] },
    // command
    "escapeShell": { label: "escapeShell()", cats: ["command_exec"] },
    // path
    "getCanonicalPath": { label: "getCanonicalPath()", cats: ["file_io"] },
    "normalize": { label: "Path.normalize()", cats: ["file_io"] },
    // generic validators / neutralisers
    "parseInt": { label: "Integer.parseInt()", cats: ["*"] },
    "parseLong": { label: "Long.parseLong()", cats: ["*"] },
    "valueOf": { label: "Integer.valueOf()", cats: ["*"] },
    "matches": { label: "String.matches() allow-list check", cats: ["*"] },
    "isAlphanumeric": { label: "isAlphanumeric() check", cats: ["*"] },
  },
};

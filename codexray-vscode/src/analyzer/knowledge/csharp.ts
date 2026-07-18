/**
 * C# / .NET knowledge base: ASP.NET entry attributes, sinks, taint sources,
 * blind spots and sanitizers. Facts to surface for manual review.
 */
import { Knowledge } from "../adapters/types";

/** Attributes that mark an HTTP action entry point (ASP.NET MVC / Web API). */
export const ROUTE_ATTRIBUTES = new Set<string>([
  "HttpGet", "HttpPost", "HttpPut", "HttpDelete", "HttpPatch", "Route",
]);

/** Attributes that bind untrusted request data to an action parameter. */
export const SOURCE_PARAM_ATTRIBUTES = new Set<string>([
  "FromQuery", "FromBody", "FromForm", "FromRoute", "FromHeader",
]);

/** Members of `Request`/`HttpContext.Request` that carry untrusted input. */
export const REQUEST_MEMBERS = new Set<string>([
  "Query", "QueryString", "Form", "Cookies", "Headers", "Params",
  "Body", "InputStream", "Url", "RawUrl", "UserAgent", "UrlReferrer",
]);

export const csharpKnowledge: Knowledge = {
  sinks: {
    // OS command execution
    "Start": ["command_exec", "starts a process (Process.Start)"],
    // Code / reflection
    "GetType": ["code_exec", "resolves a type by name (reflection)"],
    "CreateInstance": ["code_exec", "instantiates a type by name (reflection)"],
    "Load": ["code_exec", "loads an assembly (reflection)"],
    "InvokeMember": ["code_exec", "invokes a member reflectively"],
    "Compile": ["code_exec", "compiles/executes code at runtime"],
    // SQL
    "ExecuteReader": ["sql", "executes a SQL query"],
    "ExecuteNonQuery": ["sql", "executes a SQL statement"],
    "ExecuteScalar": ["sql", "executes a SQL query"],
    "FromSqlRaw": ["sql", "executes raw SQL (EF Core)"],
    "ExecuteSqlRaw": ["sql", "executes raw SQL (EF Core)"],
    // Deserialization
    "Deserialize": ["deserialization", "deserializes untrusted data"],
    "ReadObject": ["deserialization", "deserializes untrusted data"],
    // File I/O
    "ReadAllText": ["file_io", "reads a file"],
    "WriteAllText": ["file_io", "writes a file"],
    "ReadAllBytes": ["file_io", "reads a file"],
    "OpenRead": ["file_io", "opens a file for reading"],
    "OpenWrite": ["file_io", "opens a file for writing"],
    // Response / XSS
    "Write": ["xss", "writes to the HTTP response"],
    "WriteAsync": ["xss", "writes to the HTTP response"],
    "Redirect": ["header_injection", "sets a redirect Location header"],
    "AppendHeader": ["header_injection", "adds an HTTP response header"],
    "Append": ["header_injection", "adds a response header/cookie"],
    // SSRF / outbound
    "GetAsync": ["ssrf", "makes an outbound HTTP request"],
    "GetStringAsync": ["ssrf", "makes an outbound HTTP request"],
    "DownloadString": ["ssrf", "makes an outbound HTTP request"],
    "PostAsync": ["ssrf", "makes an outbound HTTP request"],
  },
  // C# taint enters through Request.* members and request-bound params. Simple
  // member names surface here; the adapter's directSource resolves Request.X.
  sources: new Set<string>([...REQUEST_MEMBERS]),
  blindspots: {
    "GetType": "reflective type resolution",
    "CreateInstance": "reflective instantiation",
    "InvokeMember": "reflective member dispatch",
    "Invoke": "reflective method dispatch",
    "Load": "dynamic assembly loading",
  },
  sanitizers: {
    // SQL — parameterisation
    "Add": { label: "SqlParameter Add()", cats: ["sql"] },
    "AddWithValue": { label: "Parameters.AddWithValue()", cats: ["sql"] },
    // XSS / output encoding
    "HtmlEncode": { label: "HttpUtility.HtmlEncode()", cats: ["xss"] },
    "Encode": { label: "HtmlEncoder.Encode()", cats: ["xss"] },
    "HtmlAttributeEncode": { label: "HtmlAttributeEncode()", cats: ["xss"] },
    // URL / headers
    "UrlEncode": { label: "HttpUtility.UrlEncode()", cats: ["header_injection", "ssrf"] },
    // path
    "GetFileName": { label: "Path.GetFileName()", cats: ["file_io"] },
    "GetFullPath": { label: "Path.GetFullPath()", cats: ["file_io"] },
    // generic validators / neutralisers
    "Parse": { label: "int.Parse()", cats: ["*"] },
    "TryParse": { label: "int.TryParse()", cats: ["*"] },
    "IsMatch": { label: "Regex.IsMatch() allow-list check", cats: ["*"] },
  },
};

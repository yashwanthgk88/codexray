/**
 * C# / .NET language adapter (ASP.NET MVC / Web API).
 *
 * Entry points are action methods carrying a route attribute ([HttpGet],
 * [Route], …). Taint enters through Request.* members (Request.Query[...]) and
 * request-bound parameters ([FromQuery] etc.). Propagation is delegated to the
 * shared TaintTracker.
 *
 * Node types verified via scratch/probe-langs.js against tree-sitter-c_sharp:
 * class_declaration (name|bases|body), method_declaration (type|name|parameters|
 * body) with attribute_list -> attribute (name), parameter (type|name),
 * local_declaration_statement -> variable_declaration -> variable_declarator
 * (identifier + equals_value_clause), invocation_expression (function|arguments),
 * member_access_expression (expression|name), element_access_expression
 * (expression|subscript), object_creation_expression (type|arguments),
 * assignment_expression (left|right).
 */
import Parser from "web-tree-sitter";
import { FunctionInfo } from "../model";
import { LanguageAdapter } from "./types";
import {
  csharpKnowledge, ROUTE_ATTRIBUTES, SOURCE_PARAM_ATTRIBUTES, REQUEST_MEMBERS,
} from "../knowledge/csharp";
import { TaintTracker, TaintProfile } from "../taint";

type Node = Parser.SyntaxNode;

const SINKS = csharpKnowledge.sinks;
const BLINDSPOTS = csharpKnowledge.blindspots;
const SANITIZERS = csharpKnowledge.sanitizers || {};

/** Constructor calls that are themselves sinks. */
const CTOR_SINKS: Record<string, [string, string]> = {
  SqlCommand: ["sql", "constructs a SQL command"],
  SqlDataAdapter: ["sql", "constructs a SQL data adapter"],
  Process: ["command_exec", "constructs a process to start"],
};

const lineOf = (node: Node): number => node.startPosition.row + 1;

/** The short method name of an invocation_expression's `function`. */
function invocationName(node: Node): string | null {
  const fn = node.childForFieldName("function");
  if (!fn) return null;
  if (fn.type === "identifier") return fn.text;
  if (fn.type === "member_access_expression") {
    const n = fn.childForFieldName("name");
    return n ? n.text : null;
  }
  return null;
}

const csharpProfile: TaintProfile = {
  sanitizers: SANITIZERS,
  varName(node: Node): string | null {
    return node.type === "identifier" ? node.text : null;
  },
  directSource(node: Node): string | null {
    // Request.Query / HttpContext.Request.Form / etc.
    if (node.type === "member_access_expression") {
      const nameNode = node.childForFieldName("name");
      const exprNode = node.childForFieldName("expression");
      if (nameNode && REQUEST_MEMBERS.has(nameNode.text) && exprNode && /Request/.test(exprNode.text)) {
        return `Request.${nameNode.text}`;
      }
    }
    return null;
  },
  callName(node: Node): string | null {
    return node.type === "invocation_expression" ? invocationName(node) : null;
  },
};

/** Attribute simple-names on a declaration (from its attribute_list children). */
function attributesOf(node: Node): string[] {
  const out: string[] = [];
  for (const c of node.namedChildren) {
    if (c.type !== "attribute_list") continue;
    for (const a of c.namedChildren) {
      if (a.type === "attribute") {
        const n = a.childForFieldName("name");
        if (n) out.push(n.text);
      }
    }
  }
  return out;
}

/** The initialiser expression inside a variable_declarator, if present. */
function declaratorValue(decl: Node): Node | null {
  const eq = decl.namedChildren.find((c) => c.type === "equals_value_clause");
  return eq ? eq.namedChildren[0] ?? null : null;
}

function visitModule(root: Node, relpath: string): Map<string, FunctionInfo> {
  const functions = new Map<string, FunctionInfo>();
  const scope: string[] = [];
  const tracker = new TaintTracker(csharpProfile);
  const funcStack: FunctionInfo[] = [];
  const cur = (): FunctionInfo | null => (funcStack.length ? funcStack[funcStack.length - 1] : null);

  const qual = (name: string) => (scope.length ? `${scope.join(".")}.${name}` : name);

  function noteCallFacts(short: string, dotted: string, ln: number, args: Node | null): void {
    const fi = cur();
    if (!fi) return;
    fi.calls.push([short, dotted, ln]);
    const s = SINKS[short];
    if (s) {
      fi.sinks.push([short, s[0], s[1], ln]);
      tracker.recordSink(fi, short, s[0], ln, args);
    }
    const b = BLINDSPOTS[short];
    if (b) fi.blindspots.push([short, b, ln]);
  }

  function handleMethod(node: Node): void {
    const nameNode = node.childForFieldName("name");
    const name = nameNode ? nameNode.text : "<anon>";
    const q = qual(name);
    const fi = new FunctionInfo(q, relpath, lineOf(node), node.endPosition.row + 1, "csharp");

    const attrs = attributesOf(node);
    for (const a of attrs) {
      if (ROUTE_ATTRIBUTES.has(a)) {
        fi.isEntry = true;
        fi.entryKind = "http";
        const method = /Get/.test(a) ? "GET" : /Post/.test(a) ? "POST" : /Put/.test(a) ? "PUT"
          : /Delete/.test(a) ? "DELETE" : /Patch/.test(a) ? "PATCH" : "ANY";
        fi.entryMeta = { method, path: `${qual(name)}`, decorator: `[${a}]` };
      }
    }
    if (name === "Main") {
      fi.isEntry = true;
      fi.entryKind = "cli";
      fi.entryMeta = { method: "CLI", path: `${qual(name)}()`, decorator: "Main()" };
    }

    // Parameters + seed request-bound ones.
    const params = node.childForFieldName("parameters");
    const seeds: string[] = [];
    if (params) {
      for (const p of params.namedChildren) {
        if (p.type !== "parameter") continue;
        const pn = p.childForFieldName("name");
        if (pn) fi.params.push(pn.text);
        const bound = attributesOf(p).some((a) => SOURCE_PARAM_ATTRIBUTES.has(a));
        if (pn && bound) seeds.push(pn.text);
      }
    }

    functions.set(q, fi);
    scope.push(name);
    funcStack.push(fi);
    tracker.enter();
    for (const s of seeds) {
      tracker.seedParam(s, `[FromQuery] ${s}`, lineOf(node));
      fi.sources.push([s, lineOf(node)]);
    }
    const body = node.childForFieldName("body");
    if (body) visit(body);
    tracker.exit();
    funcStack.pop();
    scope.pop();
  }

  function handleInvocation(node: Node): void {
    const short = invocationName(node);
    const ln = lineOf(node);
    const args = node.childForFieldName("arguments");
    if (short) {
      const fn = node.childForFieldName("function");
      noteCallFacts(short, fn ? fn.text : short, ln, args);
    }
    const fn = node.childForFieldName("function");
    if (fn) visit(fn);
    if (args) visit(args);
  }

  function handleObjectCreation(node: Node): void {
    const typeNode = node.childForFieldName("type");
    const ln = lineOf(node);
    const args = node.childForFieldName("arguments");
    const fi = cur();
    if (typeNode && fi) {
      const cls = typeNode.text;
      const s = CTOR_SINKS[cls];
      if (s) {
        fi.sinks.push([`new ${cls}`, s[0], s[1], ln]);
        tracker.recordSink(fi, `new ${cls}`, s[0], ln, args);
      }
    }
    if (args) visit(args);
  }

  function handleLocalDecl(node: Node): void {
    const stack: Node[] = [node];
    while (stack.length) {
      const n = stack.pop()!;
      if (n.type === "variable_declarator") {
        const nameNode = n.namedChildren.find((c) => c.type === "identifier");
        const value = declaratorValue(n);
        if (value) visit(value);
        if (nameNode) tracker.assign(nameNode.text, value, false);
        continue;
      }
      for (const c of n.namedChildren) stack.push(c);
    }
  }

  function handleAssignment(node: Node): void {
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (right) visit(right);
    if (left && left.type === "identifier") {
      tracker.assign(left.text, right, false);
    } else if (left) {
      visit(left);
    }
  }

  function recordMemberSource(node: Node): void {
    const src = csharpProfile.directSource(node);
    const fi = cur();
    if (src && fi) fi.sources.push([src, lineOf(node)]);
  }

  function visit(node: Node): void {
    switch (node.type) {
      case "class_declaration":
      case "interface_declaration":
      case "struct_declaration":
      case "record_declaration": {
        const nameNode = node.childForFieldName("name");
        scope.push(nameNode ? nameNode.text : "<type>");
        const body = node.childForFieldName("body");
        if (body) visit(body);
        scope.pop();
        return;
      }
      case "method_declaration":
      case "constructor_declaration":
        handleMethod(node);
        return;
      case "invocation_expression":
        handleInvocation(node);
        return;
      case "object_creation_expression":
        handleObjectCreation(node);
        return;
      case "local_declaration_statement":
        handleLocalDecl(node);
        return;
      case "assignment_expression":
        handleAssignment(node);
        return;
      case "member_access_expression":
        recordMemberSource(node);
        for (const c of node.namedChildren) visit(c);
        return;
      default:
        for (const c of node.namedChildren) visit(c);
        return;
    }
  }

  visit(root);
  return functions;
}

export const csharpAdapter: LanguageAdapter = {
  id: "csharp",
  label: "C#",
  extensions: [".cs"],
  wasm: "tree-sitter-c_sharp.wasm",
  knowledge: csharpKnowledge,
  extract: visitModule,
};

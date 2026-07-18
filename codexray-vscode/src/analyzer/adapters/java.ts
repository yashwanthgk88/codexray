/**
 * Java language adapter (Spring MVC / JAX-RS / Servlets).
 *
 * Entry points are methods annotated with a route annotation (@GetMapping,
 * @Path, …) and `public static void main`. Taint enters through request-bound
 * parameters (@RequestParam etc.) and request-accessor calls
 * (request.getParameter(...)). Propagation is delegated to the shared
 * TaintTracker; this adapter supplies the Java grammar specifics.
 *
 * Node types verified via scratch/probe-langs.js against tree-sitter-java:
 * class_declaration (name|body), method_declaration (modifiers|type|name|
 * parameters|body), method_invocation (object|name|arguments),
 * local_variable_declaration -> variable_declarator (name|value),
 * assignment_expression (left|right), object_creation_expression (type|
 * arguments), formal_parameter (modifiers|type|name), annotation/marker_annotation.
 */
import Parser from "web-tree-sitter";
import { FunctionInfo } from "../model";
import { LanguageAdapter } from "./types";
import { javaKnowledge, ROUTE_ANNOTATIONS, SOURCE_PARAM_ANNOTATIONS } from "../knowledge/java";
import { TaintTracker, TaintProfile } from "../taint";

type Node = Parser.SyntaxNode;

const SINKS = javaKnowledge.sinks;
const SOURCES = javaKnowledge.sources;
const BLINDSPOTS = javaKnowledge.blindspots;
const SANITIZERS = javaKnowledge.sanitizers || {};

/** Constructor calls that are themselves sinks (class simple name -> sink). */
const CTOR_SINKS: Record<string, [string, string]> = {
  ProcessBuilder: ["command_exec", "builds a process to run"],
  URL: ["ssrf", "constructs a URL for an outbound request"],
};

const lineOf = (node: Node): number => node.startPosition.row + 1;

/** The `name`-field text of a method_invocation, if any. */
function invocationName(node: Node): string | null {
  const n = node.childForFieldName("name");
  return n ? n.text : null;
}

const javaProfile: TaintProfile = {
  sanitizers: SANITIZERS,
  varName(node: Node): string | null {
    return node.type === "identifier" ? node.text : null;
  },
  directSource(node: Node): string | null {
    // A request-accessor call is a direct source: request.getParameter("x").
    if (node.type === "method_invocation") {
      const name = invocationName(node);
      if (name && SOURCES.has(name)) return `${name}()`;
    }
    return null;
  },
  callName(node: Node): string | null {
    return node.type === "method_invocation" ? invocationName(node) : null;
  },
};

/** Annotation nodes directly on a declaration's `modifiers` child. */
function annotationsOf(node: Node): Array<{ name: string; node: Node }> {
  const out: Array<{ name: string; node: Node }> = [];
  const mods = node.childForFieldName("modifiers") ?? node.namedChildren.find((c) => c.type === "modifiers");
  if (!mods) return out;
  for (const c of mods.namedChildren) {
    if (c.type === "annotation" || c.type === "marker_annotation") {
      const nameNode = c.childForFieldName("name");
      if (nameNode) out.push({ name: nameNode.text, node: c });
    }
  }
  return out;
}

/** First string-literal argument of an annotation (the route path). */
function annotationPath(anno: Node): string | null {
  const args = anno.childForFieldName("arguments");
  if (!args) return null;
  const stack: Node[] = [args];
  while (stack.length) {
    const n = stack.pop()!;
    if (n.type === "string_fragment") return n.text;
    for (const c of n.namedChildren) stack.push(c);
  }
  return null;
}

function visitModule(root: Node, relpath: string): Map<string, FunctionInfo> {
  const functions = new Map<string, FunctionInfo>();
  const scope: string[] = [];
  const tracker = new TaintTracker(javaProfile);
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
    if (SOURCES.has(short)) fi.sources.push([`${short}()`, ln]);
    const b = BLINDSPOTS[short];
    if (b) fi.blindspots.push([short, b, ln]);
  }

  function handleMethod(node: Node): void {
    const nameNode = node.childForFieldName("name");
    const name = nameNode ? nameNode.text : "<anon>";
    const q = qual(name);
    const fi = new FunctionInfo(q, relpath, lineOf(node), node.endPosition.row + 1, "java");

    // Entry detection: route annotation, or `main`.
    let path: string | null = null;
    for (const a of annotationsOf(node)) {
      if (ROUTE_ANNOTATIONS.has(a.name)) {
        fi.isEntry = true;
        fi.entryKind = "http";
        path = path ?? annotationPath(a.node);
        const method = /Get|GET/.test(a.name) ? "GET"
          : /Post|POST/.test(a.name) ? "POST"
          : /Put|PUT/.test(a.name) ? "PUT"
          : /Delete|DELETE/.test(a.name) ? "DELETE"
          : /Patch|PATCH/.test(a.name) ? "PATCH" : "ANY";
        fi.entryMeta = { method, path: path || "?", decorator: `@${a.name}` };
      }
    }
    if (name === "main") {
      fi.isEntry = true;
      fi.entryKind = "cli";
      fi.entryMeta = { method: "CLI", path: `${qual(name)}()`, decorator: "main()" };
    }

    // Parameters + seed request-bound ones as taint sources.
    const params = node.childForFieldName("parameters");
    const seeds: string[] = [];
    if (params) {
      for (const p of params.namedChildren) {
        if (p.type !== "formal_parameter" && p.type !== "spread_parameter") continue;
        const pn = p.childForFieldName("name");
        if (pn) fi.params.push(pn.text);
        const annotated = annotationsOf(p).some((a) => SOURCE_PARAM_ANNOTATIONS.has(a.name));
        if (pn && annotated) seeds.push(pn.text);
      }
    }

    functions.set(q, fi);
    scope.push(name);
    funcStack.push(fi);
    tracker.enter();
    for (const s of seeds) {
      tracker.seedParam(s, `@RequestParam ${s}`, lineOf(node));
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
      const obj = node.childForFieldName("object");
      const dotted = obj ? `${obj.text}.${short}` : short;
      noteCallFacts(short, dotted, ln, args);
    }
    const obj = node.childForFieldName("object");
    if (obj) visit(obj);
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

  function handleLocalVarDecl(node: Node): void {
    for (const d of node.namedChildren) {
      if (d.type !== "variable_declarator") continue;
      const nameNode = d.childForFieldName("name");
      const value = d.childForFieldName("value");
      if (value) visit(value);
      if (nameNode) tracker.assign(nameNode.text, value, false);
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

  function visit(node: Node): void {
    switch (node.type) {
      case "class_declaration":
      case "interface_declaration":
      case "enum_declaration":
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
      case "method_invocation":
        handleInvocation(node);
        return;
      case "object_creation_expression":
        handleObjectCreation(node);
        return;
      case "local_variable_declaration":
        handleLocalVarDecl(node);
        return;
      case "assignment_expression":
        handleAssignment(node);
        return;
      default:
        for (const c of node.namedChildren) visit(c);
        return;
    }
  }

  visit(root);
  return functions;
}

export const javaAdapter: LanguageAdapter = {
  id: "java",
  label: "Java",
  extensions: [".java"],
  wasm: "tree-sitter-java.wasm",
  knowledge: javaKnowledge,
  extract: visitModule,
};

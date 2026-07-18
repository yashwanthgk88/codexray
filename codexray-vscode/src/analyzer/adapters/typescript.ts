/**
 * TypeScript / JavaScript language adapter (Node.js / Express / NestJS).
 *
 * Entry points are Express/Koa route-registration callbacks (app.get("/x", h))
 * and exported/handler functions. Taint enters through req.query / req.body /
 * req.params / process.env, including via object-DESTRUCTURING
 * (`const { id } = req.query`) — which a naive walker loses. Propagation is
 * delegated to the shared TaintTracker.
 *
 * Node types verified via scratch/probe-langs.js against tree-sitter-typescript:
 * call_expression (function|arguments), member_expression (object|property),
 * arrow_function (parameters|body), lexical_declaration/variable_declaration ->
 * variable_declarator (name|value), object_pattern with
 * shorthand_property_identifier_pattern, assignment_expression (left|right),
 * subscript_expression (object|index), function_declaration, method_definition.
 */
import Parser from "web-tree-sitter";
import { FunctionInfo } from "../model";
import { LanguageAdapter } from "./types";
import {
  typescriptKnowledge, REQUEST_OBJECTS, REQUEST_MEMBERS, ROUTE_METHODS, DOM_SINK_PROPS,
} from "../knowledge/typescript";
import { TaintTracker, TaintProfile } from "../taint";

type Node = Parser.SyntaxNode;

const SINKS = typescriptKnowledge.sinks;
const BLINDSPOTS = typescriptKnowledge.blindspots;
const SANITIZERS = typescriptKnowledge.sanitizers || {};

const lineOf = (node: Node): number => node.startPosition.row + 1;

/** Short callee name of a call_expression (`fetch`, `exec`, `res.send` -> "send"). */
function calleeName(node: Node): string | null {
  const fn = node.childForFieldName("function");
  if (!fn) return null;
  if (fn.type === "identifier") return fn.text;
  if (fn.type === "member_expression") {
    const p = fn.childForFieldName("property");
    return p ? p.text : null;
  }
  return null;
}

/** Is this member_expression a request source? `req.query` -> "req.query". */
function memberSource(node: Node): string | null {
  if (node.type !== "member_expression") return null;
  const obj = node.childForFieldName("object");
  const prop = node.childForFieldName("property");
  if (obj && obj.type === "identifier" && prop &&
      REQUEST_OBJECTS.has(obj.text) && REQUEST_MEMBERS.has(prop.text)) {
    return `${obj.text}.${prop.text}`;
  }
  return null;
}

const tsProfile: TaintProfile = {
  sanitizers: SANITIZERS,
  varName(node: Node): string | null {
    return node.type === "identifier" ? node.text : null;
  },
  directSource(node: Node): string | null {
    return memberSource(node);
  },
  callName(node: Node): string | null {
    return node.type === "call_expression" ? calleeName(node) : null;
  },
};

function visitModule(root: Node, relpath: string): Map<string, FunctionInfo> {
  const functions = new Map<string, FunctionInfo>();
  const scope: string[] = [];
  const tracker = new TaintTracker(tsProfile);
  const funcStack: FunctionInfo[] = [];
  const cur = (): FunctionInfo | null => (funcStack.length ? funcStack[funcStack.length - 1] : null);
  // Callback nodes already claimed as route-handler entry points (avoid re-walking).
  const claimed = new Set<number>();
  let anon = 0;

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

  /** Names bound by a pattern (identifier or destructuring), for param taint. */
  function patternNames(node: Node): string[] {
    const out: string[] = [];
    const stack: Node[] = [node];
    while (stack.length) {
      const n = stack.pop()!;
      if (n.type === "identifier" || n.type === "shorthand_property_identifier_pattern") {
        out.push(n.text);
      }
      for (const c of n.namedChildren) stack.push(c);
    }
    return out;
  }

  function handleFunctionLike(
    node: Node,
    nameHint: string | null,
    entry?: { kind: "http" | "cli"; method: string; path: string; decorator: string }
  ): void {
    const name = nameHint ?? `<anon@${lineOf(node)}#${anon++}>`;
    const q = qual(name);
    const fi = new FunctionInfo(q, relpath, lineOf(node), node.endPosition.row + 1, "typescript");
    if (entry) {
      fi.isEntry = true;
      fi.entryKind = entry.kind;
      fi.entryMeta = { method: entry.method, path: entry.path, decorator: entry.decorator };
    }
    const params = node.childForFieldName("parameters");
    if (params) for (const p of params.namedChildren) fi.params.push(...patternNames(p));

    functions.set(q, fi);
    scope.push(name);
    funcStack.push(fi);
    tracker.enter();
    const body = node.childForFieldName("body");
    if (body) visit(body);
    tracker.exit();
    funcStack.pop();
    scope.pop();
  }

  /** Detect `app.get("/path", handler)` and claim the callback as an entry. */
  function tryRouteRegistration(node: Node): boolean {
    const fn = node.childForFieldName("function");
    if (!fn || fn.type !== "member_expression") return false;
    const obj = fn.childForFieldName("object");
    const prop = fn.childForFieldName("property");
    if (!obj || !prop || !ROUTE_METHODS.has(prop.text)) return false;
    if (!/^(app|router|route|server)$/i.test(obj.text)) return false;
    const args = node.childForFieldName("arguments");
    if (!args) return false;
    const argNodes = args.namedChildren;
    let path = "?";
    for (const a of argNodes) {
      if (a.type === "string") { path = a.text.replace(/^['"`]|['"`]$/g, ""); break; }
    }
    const method = prop.text.toUpperCase();
    let claimedAny = false;
    for (const a of argNodes) {
      if (a.type === "arrow_function" || a.type === "function_expression") {
        claimed.add(a.startIndex);
        handleFunctionLike(a, `${method} ${path}`, {
          kind: "http", method, path, decorator: `${obj.text}.${prop.text}()`,
        });
        claimedAny = true;
      }
    }
    return claimedAny;
  }

  function handleCall(node: Node): void {
    if (tryRouteRegistration(node)) {
      // Still record the call itself on the current function.
      const short = calleeName(node);
      if (short && cur()) cur()!.calls.push([short, short, lineOf(node)]);
      return;
    }
    const short = calleeName(node);
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

  function handleDeclarator(node: Node): void {
    const nameNode = node.childForFieldName("name");
    const value = node.childForFieldName("value");
    if (value) visit(value);
    if (!nameNode) return;
    if (nameNode.type === "identifier") {
      tracker.assign(nameNode.text, value, false);
    } else if (nameNode.type === "object_pattern" || nameNode.type === "array_pattern") {
      // Destructuring: `const { id } = req.query` — each binding inherits taint.
      if (value) {
        const t = tracker.scan(value);
        if (t) for (const b of patternNames(nameNode)) tracker.seedVar(b, { ...t, via: t.via });
      }
    }
  }

  function handleAssignment(node: Node): void {
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (right) visit(right);
    // DOM/response write sink: `el.innerHTML = <tainted>`.
    if (left && left.type === "member_expression") {
      const prop = left.childForFieldName("property");
      const fi = cur();
      if (prop && DOM_SINK_PROPS.has(prop.text) && fi) {
        fi.sinks.push([prop.text, "xss", "writes to the DOM (XSS)", lineOf(node)]);
        tracker.recordSink(fi, prop.text, "xss", lineOf(node), right);
      }
    }
    if (left && left.type === "identifier") {
      tracker.assign(left.text, right, false);
    } else if (left) {
      visit(left);
    }
  }

  function recordMemberSource(node: Node): void {
    const src = memberSource(node);
    const fi = cur();
    if (src && fi) fi.sources.push([src, lineOf(node)]);
  }

  function visit(node: Node): void {
    if (claimed.has(node.startIndex) && (node.type === "arrow_function" || node.type === "function_expression")) {
      return; // already walked as a route handler
    }
    switch (node.type) {
      case "class_declaration":
      case "class": {
        const nameNode = node.childForFieldName("name");
        scope.push(nameNode ? nameNode.text : "<class>");
        const body = node.childForFieldName("body");
        if (body) visit(body);
        scope.pop();
        return;
      }
      case "function_declaration":
      case "generator_function_declaration": {
        const nameNode = node.childForFieldName("name");
        handleFunctionLike(node, nameNode ? nameNode.text : null);
        return;
      }
      case "method_definition": {
        const nameNode = node.childForFieldName("name");
        handleFunctionLike(node, nameNode ? nameNode.text : null);
        return;
      }
      case "arrow_function":
      case "function_expression": {
        handleFunctionLike(node, null);
        return;
      }
      case "call_expression":
        handleCall(node);
        return;
      case "variable_declarator":
        handleDeclarator(node);
        return;
      case "assignment_expression":
        handleAssignment(node);
        return;
      case "augmented_assignment_expression": {
        const left = node.childForFieldName("left");
        const right = node.childForFieldName("right");
        if (right) visit(right);
        if (left && left.type === "identifier") tracker.assign(left.text, right, true);
        return;
      }
      case "member_expression":
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

export const typescriptAdapter: LanguageAdapter = {
  id: "typescript",
  label: "TypeScript",
  // Plain `typescript` grammar (no JSX). .tsx/.jsx would need the separate tsx grammar.
  extensions: [".ts", ".mts", ".cts", ".js", ".mjs", ".cjs"],
  wasm: "tree-sitter-typescript.wasm",
  knowledge: typescriptKnowledge,
  extract: visitModule,
};

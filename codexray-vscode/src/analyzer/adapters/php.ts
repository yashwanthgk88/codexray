/**
 * PHP language adapter.
 *
 * PHP web apps are script-centric: each .php file's top-level code is itself a
 * web-reachable entry point, alongside its functions and methods. We model the
 * file's top-level as a synthetic `<main>` entry, then real functions/methods.
 *
 * Taint propagation (source→variable→sink, control collection, category
 * resolution) is delegated to the shared TaintTracker (analyzer/taint.ts); this
 * adapter supplies only the PHP grammar specifics via a TaintProfile.
 *
 * Node types below come from the installed tree-sitter-php grammar (verified via
 * scratch/probe-php.js): function_definition / method_declaration (fields
 * name|parameters|body), function_call_expression (field function->name),
 * member_call_expression / scoped_call_expression (field name), variable_name
 * (-> name, for superglobals), echo_statement, {include,require}[_once]_expression,
 * class_declaration.
 */
import Parser from "web-tree-sitter";
import { FunctionInfo } from "../model";
import { LanguageAdapter } from "./types";
import { phpKnowledge } from "../knowledge/php";
import { TaintTracker, TaintProfile, CtrlRef } from "../taint";

type Node = Parser.SyntaxNode;

const SINKS = phpKnowledge.sinks;
const SOURCES = phpKnowledge.sources;
const BLINDSPOTS = phpKnowledge.blindspots;
const SANITIZERS = phpKnowledge.sanitizers || {};

const lineOf = (node: Node): number => node.startPosition.row + 1;

/** The identifier text of a `variable_name` node ($_GET -> "_GET"). In tree-sitter-php
 *  the identifier is a child of type `name`, NOT a named field. */
function variableIdent(node: Node): string | null {
  const nm = node.namedChildren.find((c) => c.type === "name");
  if (nm) return nm.text;
  return node.text.startsWith("$") ? node.text.slice(1) : null;
}

const CALL_TYPES = new Set([
  "function_call_expression",
  "member_call_expression",
  "nullsafe_member_call_expression",
  "scoped_call_expression",
]);

/** PHP-specific grammar knowledge for the shared taint engine. */
const phpProfile: TaintProfile = {
  sigil: "$",
  sanitizers: SANITIZERS,
  varName(node: Node): string | null {
    return node.type === "variable_name" ? variableIdent(node) : null;
  },
  directSource(node: Node): string | null {
    if (node.type !== "variable_name") return null;
    const id = variableIdent(node);
    return id && SOURCES.has(id) ? `$${id}` : null;
  },
  callName(node: Node): string | null {
    if (!CALL_TYPES.has(node.type)) return null;
    const fn = node.childForFieldName(node.type === "function_call_expression" ? "function" : "name");
    return fn && fn.type === "name" ? fn.text : null;
  },
  castControl(node: Node): CtrlRef | null {
    return node.type === "cast_expression" ? { label: "(type) cast", cats: ["*"] } : null;
  },
};

const INCLUDE_NODES: Record<string, string> = {
  include_expression: "include",
  include_once_expression: "include_once",
  require_expression: "require",
  require_once_expression: "require_once",
};

/** Collect `$var` parameter names from a formal_parameters node. */
function paramNames(formal: Node): string[] {
  const out: string[] = [];
  for (const p of formal.namedChildren) {
    // simple_parameter / variadic_parameter / property_promotion_parameter all
    // wrap a variable_name whose `name` child is the identifier.
    const stack: Node[] = [p];
    while (stack.length) {
      const n = stack.pop()!;
      if (n.type === "variable_name") {
        const id = variableIdent(n);
        if (id) out.push(id);
        break;
      }
      for (const c of n.namedChildren) stack.push(c);
    }
  }
  return out;
}

function visitModule(root: Node, relpath: string): Map<string, FunctionInfo> {
  const functions = new Map<string, FunctionInfo>();
  const scope: string[] = [];
  const tracker = new TaintTracker(phpProfile);

  const qual = (name: string) => (scope.length ? `${scope.join(".")}.${name}` : name);

  // Synthetic top-level script = a web-reachable entry point.
  const main = new FunctionInfo("<main>", relpath, 1, root.endPosition.row + 1, "php");
  main.isEntry = true;
  main.entryKind = "http";
  main.entryMeta = { method: "ANY", path: relpath, decorator: "php script (top-level)" };
  functions.set("<main>", main);
  const funcStack: FunctionInfo[] = [main];

  const cur = () => funcStack[funcStack.length - 1];

  /** Record a sink; if `taintNode` carries untrusted input, record the chain. */
  function noteSink(name: string, ln: number, taintNode?: Node | null): void {
    const s = SINKS[name];
    if (s) {
      cur().sinks.push([name, s[0], s[1], ln]);
      tracker.recordSink(cur(), name, s[0], ln, taintNode);
    }
    const b = BLINDSPOTS[name];
    if (b) cur().blindspots.push([name, b, ln]);
  }

  function handleCallable(node: Node): void {
    const nameNode = node.childForFieldName("name");
    const name = nameNode ? nameNode.text : "<anon>";
    const q = qual(name);
    const fi = new FunctionInfo(q, relpath, lineOf(node), node.endPosition.row + 1, "php");
    const params = node.childForFieldName("parameters");
    if (params) fi.params = paramNames(params);
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

  function handleFunctionCall(node: Node): void {
    const fn = node.childForFieldName("function");
    const ln = lineOf(node);
    const args = node.childForFieldName("arguments");
    if (fn && fn.type === "name") {
      const short = fn.text;
      cur().calls.push([short, short, ln]);
      noteSink(short, ln, args);
    } else if (fn) {
      // $fn(...) — dynamic dispatch we cannot resolve.
      cur().blindspots.push(["variable_function", BLINDSPOTS["variable_function"], ln]);
    }
    if (args) visit(args);
    if (fn && fn.type !== "name") visit(fn);
  }

  function handleMemberCall(node: Node): void {
    const nameNode = node.childForFieldName("name");
    const ln = lineOf(node);
    const args = node.childForFieldName("arguments");
    if (nameNode && nameNode.type === "name") {
      const short = nameNode.text;
      cur().calls.push([short, short, ln]);
      noteSink(short, ln, args);
    }
    const obj = node.childForFieldName("object");
    if (obj) visit(obj);
    if (args) visit(args);
  }

  function handleScopedCall(node: Node): void {
    const nameNode = node.childForFieldName("name");
    const ln = lineOf(node);
    const args = node.childForFieldName("arguments");
    if (nameNode && nameNode.type === "name") {
      const short = nameNode.text;
      const scopeNode = node.childForFieldName("scope");
      const dotted = scopeNode ? `${scopeNode.text}::${short}` : short;
      cur().calls.push([short, dotted, ln]);
      noteSink(short, ln, args);
    }
    if (args) visit(args);
  }

  /** `$v = <expr>` / `$v .= <expr>` — propagate taint to `$v`. */
  function handleAssignment(node: Node, augmented: boolean): void {
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (right) visit(right);
    if (left && left.type === "variable_name") {
      tracker.assign(variableIdent(left), right, augmented);
    } else if (left) {
      visit(left); // e.g. $arr[$_GET['k']] = ... — left may hold a source
    }
  }

  function recordVariableSource(node: Node): void {
    const id = variableIdent(node);
    if (id && SOURCES.has(id)) {
      cur().sources.push([`$${id}`, lineOf(node)]);
    }
  }

  function visit(node: Node): void {
    switch (node.type) {
      case "function_definition":
        handleCallable(node);
        return;
      case "method_declaration":
        handleCallable(node);
        return;
      case "class_declaration":
      case "interface_declaration":
      case "trait_declaration":
      case "enum_declaration": {
        const nameNode = node.childForFieldName("name");
        scope.push(nameNode ? nameNode.text : "<class>");
        const body = node.childForFieldName("body");
        if (body) visit(body);
        scope.pop();
        return;
      }
      case "function_call_expression":
        handleFunctionCall(node);
        return;
      case "member_call_expression":
      case "nullsafe_member_call_expression":
        handleMemberCall(node);
        return;
      case "scoped_call_expression":
        handleScopedCall(node);
        return;
      case "assignment_expression":
        handleAssignment(node, false);
        return;
      case "augmented_assignment_expression":
        handleAssignment(node, true);
        return;
      case "echo_statement": {
        noteSink("echo", lineOf(node), node);
        for (const c of node.namedChildren) visit(c);
        return;
      }
      case "variable_name":
        recordVariableSource(node);
        return;
      default: {
        if (node.type in INCLUDE_NODES) {
          noteSink(INCLUDE_NODES[node.type], lineOf(node), node);
        }
        for (const c of node.namedChildren) visit(c);
        return;
      }
    }
  }

  visit(root);
  return functions;
}

export const phpAdapter: LanguageAdapter = {
  id: "php",
  label: "PHP",
  extensions: [".php", ".php3", ".php4", ".php5", ".phtml", ".inc"],
  wasm: "tree-sitter-php.wasm",
  knowledge: phpKnowledge,
  extract: visitModule,
};

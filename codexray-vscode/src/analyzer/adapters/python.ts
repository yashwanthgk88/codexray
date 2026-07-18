/**
 * Python language adapter — the original xray.py extraction, now behind the
 * LanguageAdapter contract. Tree walking is Python-grammar-specific; everything
 * it produces (FunctionInfo) feeds the shared core.
 */
import Parser from "web-tree-sitter";
import { FunctionInfo } from "../model";
import { LanguageAdapter } from "./types";
import { pythonKnowledge, ROUTE_DECORATORS, HTTP_VERBS } from "../knowledge/python";
import { TaintTracker, TaintProfile } from "../taint";

type Node = Parser.SyntaxNode;

const SINKS = pythonKnowledge.sinks;
const SOURCE_HINTS = pythonKnowledge.sources;
const BLINDSPOT_CALLS = pythonKnowledge.blindspots;
const SANITIZERS = pythonKnowledge.sanitizers || {};

/** Best-effort resolve a call target to a dotted string (os.system, cursor.execute). */
function dottedName(node: Node | null): string | null {
  if (!node) return null;
  if (node.type === "identifier") return node.text;
  if (node.type === "attribute") {
    const base = dottedName(node.childForFieldName("object"));
    const attr = node.childForFieldName("attribute");
    const attrText = attr ? attr.text : "";
    return base ? `${base}.${attrText}` : attrText;
  }
  return null;
}

const lineOf = (node: Node): number => node.startPosition.row + 1;

/** Python grammar specifics for the shared taint engine. */
const pythonProfile: TaintProfile = {
  sanitizers: SANITIZERS,
  varName(node: Node): string | null {
    return node.type === "identifier" ? node.text : null;
  },
  directSource(node: Node): string | null {
    // Attribute access to a request/env member: request.args, sys.argv, os.environ.
    if (node.type === "attribute") {
      const attr = node.childForFieldName("attribute");
      const obj = node.childForFieldName("object");
      if (attr && SOURCE_HINTS.has(attr.text)) {
        const objText = obj ? dottedName(obj) : null;
        return objText ? `${objText}.${attr.text}` : attr.text;
      }
      if (obj && obj.type === "identifier" && SOURCE_HINTS.has(obj.text)) return obj.text;
    }
    // input() builtin.
    if (node.type === "call") {
      const dn = dottedName(node.childForFieldName("function"));
      if (dn === "input") return "input()";
    }
    return null;
  },
  callName(node: Node): string | null {
    if (node.type !== "call") return null;
    const dn = dottedName(node.childForFieldName("function"));
    return dn ? (dn.split(".").pop() as string) : null;
  },
};

/** Value of a Python string literal node, minus quotes. */
function stringValue(node: Node): string | null {
  if (node.type !== "string") return null;
  for (const child of node.namedChildren) {
    if (child.type === "string_content") return child.text;
  }
  return node.text.replace(/^[rbuf]*['"]+|['"]+$/gi, "");
}

/** Extract simple positional parameter names (matches ast's node.args.args). */
function extractParams(paramsNode: Node): string[] {
  const out: string[] = [];
  for (const child of paramsNode.namedChildren) {
    if (child.type === "identifier") {
      out.push(child.text);
    } else if (
      child.type === "default_parameter" ||
      child.type === "typed_parameter" ||
      child.type === "typed_default_parameter"
    ) {
      const name = child.childForFieldName("name");
      if (name) out.push(name.text);
      else {
        const id = child.namedChildren.find((c) => c.type === "identifier");
        if (id) out.push(id.text);
      }
    }
  }
  return out;
}

/** Walk one parsed module, collecting functions and their facts. */
function visitModule(root: Node, relpath: string): Map<string, FunctionInfo> {
  const functions = new Map<string, FunctionInfo>();
  const scope: string[] = [];
  const funcStack: FunctionInfo[] = [];
  const tracker = new TaintTracker(pythonProfile);

  const qual = (name: string) =>
    scope.length ? `${scope.join(".")}.${name}` : name;

  function handleDecorator(dec: Node, fi: FunctionInfo): void {
    const expr = dec.namedChildren[0];
    if (!expr) return;
    const isCall = expr.type === "call";
    const target = isCall ? expr.childForFieldName("function") : expr;
    const dn = dottedName(target);
    if (!dn) return;
    const leafName = dn.split(".").pop() as string;
    if (!ROUTE_DECORATORS.has(leafName)) return;

    fi.isEntry = true;
    fi.entryKind = "http";
    let method = HTTP_VERBS.has(leafName) ? leafName.toUpperCase() : "ANY";
    let path: string | null = null;

    if (isCall) {
      const argList = expr.childForFieldName("arguments");
      if (argList) {
        for (const arg of argList.namedChildren) {
          if (arg.type === "string" && path === null) {
            path = stringValue(arg);
          } else if (arg.type === "keyword_argument") {
            const kwName = arg.childForFieldName("name");
            const kwVal = arg.childForFieldName("value");
            if (kwName && kwName.text === "methods" && kwVal &&
                (kwVal.type === "list" || kwVal.type === "tuple")) {
              const ms = kwVal.namedChildren
                .filter((e) => e.type === "string")
                .map((e) => stringValue(e))
                .filter((s): s is string => s !== null);
              if (ms.length) method = ms.join("/");
            }
          }
        }
      }
    }
    fi.entryMeta = { method, path: path || "?", decorator: dn };
  }

  function handleFunction(node: Node): void {
    const nameNode = node.childForFieldName("name");
    const name = nameNode ? nameNode.text : "<anon>";
    const q = qual(name);
    const fi = new FunctionInfo(q, relpath, lineOf(node), node.endPosition.row + 1, "python");
    const params = node.childForFieldName("parameters");
    if (params) fi.params = extractParams(params);

    const parent = node.parent;
    if (parent && parent.type === "decorated_definition") {
      for (const child of parent.namedChildren) {
        if (child.type === "decorator") handleDecorator(child, fi);
      }
    }

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

  /** `x = <expr>` / `x += <expr>` — propagate taint to `x`. */
  function handleAssignment(node: Node, augmented: boolean): void {
    const left = node.childForFieldName("left");
    const right = node.childForFieldName("right");
    if (right) visit(right);
    if (!funcStack.length) {
      if (left) visit(left);
      return;
    }
    if (left && left.type === "identifier") {
      tracker.assign(left.text, right, augmented);
    } else if (left) {
      visit(left); // e.g. d[request.args['k']] = ... — left may hold a source
    }
  }

  function recordCall(node: Node): void {
    if (!funcStack.length) return;
    const fi = funcStack[funcStack.length - 1];
    const fnNode = node.childForFieldName("function");
    const dn = dottedName(fnNode);
    if (!dn) return;
    const short = dn.split(".").pop() as string;
    const ln = lineOf(node);
    fi.calls.push([short, dn, ln]);
    const args = node.childForFieldName("arguments");
    if (dn in SINKS) {
      const [cat, why] = SINKS[dn];
      fi.sinks.push([dn, cat, why, ln]);
      tracker.recordSink(fi, dn, cat, ln, args);
    } else if (short in SINKS) {
      const [cat, why] = SINKS[short];
      fi.sinks.push([short, cat, why, ln]);
      tracker.recordSink(fi, short, cat, ln, args);
    }
    if (dn in BLINDSPOT_CALLS) {
      fi.blindspots.push([dn, BLINDSPOT_CALLS[dn], ln]);
    } else if (short in BLINDSPOT_CALLS) {
      fi.blindspots.push([short, BLINDSPOT_CALLS[short], ln]);
    }
  }

  function recordAttributeSource(node: Node): void {
    if (!funcStack.length) return;
    const fi = funcStack[funcStack.length - 1];
    const attrNode = node.childForFieldName("attribute");
    const attr = attrNode ? attrNode.text : "";
    const obj = node.childForFieldName("object");
    if (SOURCE_HINTS.has(attr)) {
      fi.sources.push([attr, lineOf(node)]);
    } else if (obj && obj.type === "identifier" && SOURCE_HINTS.has(obj.text)) {
      fi.sources.push([obj.text, lineOf(node)]);
    }
  }

  function recordNameSource(node: Node): void {
    if (!funcStack.length) return;
    if (SOURCE_HINTS.has(node.text)) {
      funcStack[funcStack.length - 1].sources.push([node.text, lineOf(node)]);
    }
  }

  function visit(node: Node): void {
    switch (node.type) {
      case "class_definition": {
        const nameNode = node.childForFieldName("name");
        scope.push(nameNode ? nameNode.text : "<class>");
        const body = node.childForFieldName("body");
        if (body) visit(body);
        scope.pop();
        return;
      }
      case "function_definition":
        handleFunction(node);
        return;
      case "decorated_definition": {
        const def = node.childForFieldName("definition");
        if (def) visit(def);
        return;
      }
      case "call": {
        recordCall(node);
        for (const child of node.namedChildren) visit(child);
        return;
      }
      case "assignment":
        handleAssignment(node, false);
        return;
      case "augmented_assignment":
        handleAssignment(node, true);
        return;
      case "attribute": {
        recordAttributeSource(node);
        const obj = node.childForFieldName("object");
        if (obj) visit(obj);
        return;
      }
      case "keyword_argument": {
        const val = node.childForFieldName("value");
        if (val) visit(val);
        return;
      }
      case "identifier":
        recordNameSource(node);
        return;
      default:
        for (const child of node.namedChildren) visit(child);
        return;
    }
  }

  visit(root);
  return functions;
}

/** Second pass: resolve `if __name__ == '__main__':` entry points across files. */
function walkForMain(root: Node, allFuncs: Map<string, FunctionInfo>): void {
  const byShort = new Map<string, string[]>();
  for (const [key, fi] of allFuncs) {
    if (fi.language !== "python") continue;
    const short = fi.qualname.split(".").pop() as string;
    (byShort.get(short) ?? byShort.set(short, []).get(short)!).push(key);
  }
  const stack: Node[] = [root];
  while (stack.length) {
    const node = stack.pop()!;
    if (node.type === "if_statement") {
      const cond = node.childForFieldName("condition");
      if (cond && cond.type === "comparison_operator") {
        const left = cond.namedChildren[0];
        const right = cond.namedChildren[1];
        const isMain =
          left && left.type === "identifier" && left.text === "__name__" &&
          right && right.type === "string" && stringValue(right) === "__main__";
        if (isMain) {
          const consequence = node.childForFieldName("consequence");
          if (consequence) {
            const callStack: Node[] = [consequence];
            while (callStack.length) {
              const n = callStack.pop()!;
              if (n.type === "call") {
                const dn = dottedName(n.childForFieldName("function"));
                if (dn) {
                  const short = dn.split(".").pop() as string;
                  for (const cand of byShort.get(short) ?? []) {
                    const fi = allFuncs.get(cand)!;
                    if (!fi.isEntry) {
                      fi.isEntry = true;
                      fi.entryKind = "cli";
                      fi.entryMeta = {
                        method: "CLI",
                        path: `__main__ -> ${short}()`,
                        decorator: "__main__ block",
                      };
                    }
                  }
                }
              }
              for (const c of n.namedChildren) callStack.push(c);
            }
          }
        }
      }
    }
    for (const c of node.namedChildren) stack.push(c);
  }
}

export const pythonAdapter: LanguageAdapter = {
  id: "python",
  label: "Python",
  extensions: [".py"],
  wasm: "tree-sitter-python.wasm",
  knowledge: pythonKnowledge,
  extract: visitModule,
  postPass(trees, allFuncs) {
    for (const tree of trees) walkForMain(tree.rootNode, allFuncs);
  },
};

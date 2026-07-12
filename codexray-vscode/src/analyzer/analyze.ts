/**
 * CodeXray analyzer engine — TypeScript port of xray.py.
 *
 * Emits ANATOMY + a COVERAGE LEDGER, never a vulnerability verdict:
 *   - every entry point in the source (HTTP routes + __main__/CLI)
 *   - every dangerous sink
 *   - which entry points can reach which sinks (with a witness path)
 *   - a disposition bucket for every function so nothing is silently skipped
 *   - explicitly MARKED blind spots where static analysis cannot see
 */
import Parser from "web-tree-sitter";
import { FunctionInfo, Model, SinkTuple } from "./model";
import {
  BLINDSPOT_CALLS,
  HTTP_VERBS,
  ROUTE_DECORATORS,
  SINKS,
  SOURCE_HINTS,
} from "./knowledge";

type Node = Parser.SyntaxNode;

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

/** Value of a Python string literal node, minus quotes. */
function stringValue(node: Node): string | null {
  if (node.type !== "string") return null;
  for (const child of node.namedChildren) {
    if (child.type === "string_content") return child.text;
  }
  // no content child (empty string) — strip surrounding quotes best-effort
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

/**
 * Walk one parsed module, collecting functions and their facts.
 * Mirrors ModuleVisitor in xray.py (scope stack + function stack).
 */
function visitModule(root: Node, relpath: string): Map<string, FunctionInfo> {
  const functions = new Map<string, FunctionInfo>();
  const scope: string[] = [];
  const funcStack: FunctionInfo[] = [];

  const qual = (name: string) =>
    scope.length ? `${scope.join(".")}.${name}` : name;

  function handleDecorator(dec: Node, fi: FunctionInfo): void {
    // dec is a `decorator` node; its named child is the decorator expression.
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
    const fi = new FunctionInfo(q, relpath, lineOf(node), node.endPosition.row + 1);
    const params = node.childForFieldName("parameters");
    if (params) fi.params = extractParams(params);

    // entry-point detection via decorators (siblings under decorated_definition)
    const parent = node.parent;
    if (parent && parent.type === "decorated_definition") {
      for (const child of parent.namedChildren) {
        if (child.type === "decorator") handleDecorator(child, fi);
      }
    }

    functions.set(q, fi);
    scope.push(name);
    funcStack.push(fi);
    const body = node.childForFieldName("body");
    if (body) visit(body);
    funcStack.pop();
    scope.pop();
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
    // sink?
    if (dn in SINKS) {
      const [cat, why] = SINKS[dn];
      fi.sinks.push([dn, cat, why, ln]);
    } else if (short in SINKS) {
      const [cat, why] = SINKS[short];
      fi.sinks.push([short, cat, why, ln]);
    }
    // blind spot?
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
        // decorators are handled inside handleFunction; only descend the definition
        const def = node.childForFieldName("definition");
        if (def) visit(def);
        return;
      }
      case "call": {
        recordCall(node);
        for (const child of node.namedChildren) visit(child);
        return;
      }
      case "attribute": {
        recordAttributeSource(node);
        const obj = node.childForFieldName("object");
        if (obj) visit(obj); // do NOT descend the attribute-name identifier
        return;
      }
      case "keyword_argument": {
        const val = node.childForFieldName("value");
        if (val) visit(val); // skip the keyword name identifier
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

export interface SourceFile {
  rel: string;
  src: string;
}

function walkForMain(root: Node, allFuncs: Map<string, FunctionInfo>): void {
  const byShort = new Map<string, string[]>();
  for (const [key, fi] of allFuncs) {
    const short = fi.qualname.split(".").pop() as string;
    (byShort.get(short) ?? byShort.set(short, []).get(short)!).push(key);
  }
  // find `if __name__ == '__main__':` blocks and the functions they invoke
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

function buildCallGraph(allFuncs: Map<string, FunctionInfo>): {
  edges: Map<string, Set<string>>;
  unresolved: Map<string, Array<[string, string, number]>>;
  ambiguous: Map<string, Array<[string, string[], number]>>;
} {
  const byShort = new Map<string, string[]>();
  for (const [key, fi] of allFuncs) {
    const short = fi.qualname.split(".").pop() as string;
    (byShort.get(short) ?? byShort.set(short, []).get(short)!).push(key);
  }

  const edges = new Map<string, Set<string>>();
  const unresolved = new Map<string, Array<[string, string, number]>>();
  const ambiguous = new Map<string, Array<[string, string[], number]>>();

  const externalOk = new Set<string>();
  for (const k of Object.keys(SINKS)) {
    externalOk.add(k);
    externalOk.add(k.split(".").pop() as string);
  }
  for (const s of SOURCE_HINTS) externalOk.add(s);
  for (const b of Object.keys(BLINDSPOT_CALLS)) externalOk.add(b);

  for (const [key, fi] of allFuncs) {
    for (const [short, dotted, lineno] of fi.calls) {
      const candidates = byShort.get(short) ?? [];
      if (candidates.length === 1) {
        (edges.get(key) ?? edges.set(key, new Set()).get(key)!).add(candidates[0]);
      } else if (candidates.length > 1) {
        const set = edges.get(key) ?? edges.set(key, new Set()).get(key)!;
        for (const c of candidates) set.add(c);
        (ambiguous.get(key) ?? ambiguous.set(key, []).get(key)!).push([short, candidates, lineno]);
      } else {
        if (!externalOk.has(short) && !externalOk.has(dotted)) {
          (unresolved.get(key) ?? unresolved.set(key, []).get(key)!).push([short, dotted, lineno]);
        }
      }
    }
  }
  return { edges, unresolved, ambiguous };
}

function reachability(
  allFuncs: Map<string, FunctionInfo>,
  edges: Map<string, Set<string>>
): {
  entries: string[];
  reachableFrom: Map<string, Set<string>>;
  entrySinks: Map<string, Array<[string, SinkTuple, string[]]>>;
  globallyReachable: Set<string>;
} {
  const entries: string[] = [];
  for (const [k, fi] of allFuncs) if (fi.isEntry) entries.push(k);

  const reachableFrom = new Map<string, Set<string>>();
  const entrySinks = new Map<string, Array<[string, SinkTuple, string[]]>>();

  for (const ekey of entries) {
    const seen = new Set<string>([ekey]);
    const parent = new Map<string, string | null>([[ekey, null]]);
    const stack = [ekey];
    while (stack.length) {
      const cur = stack.pop()!;
      for (const nxt of edges.get(cur) ?? []) {
        if (!seen.has(nxt)) {
          seen.add(nxt);
          parent.set(nxt, cur);
          stack.push(nxt);
        }
      }
    }
    reachableFrom.set(ekey, seen);
    const sinkList: Array<[string, SinkTuple, string[]]> = [];
    for (const fkey of seen) {
      const fi = allFuncs.get(fkey)!;
      if (fi.sinks.length) {
        const path: string[] = [];
        let node: string | null = fkey;
        while (node !== null && node !== undefined) {
          path.push(node);
          node = parent.get(node) ?? null;
        }
        path.reverse();
        for (const sink of fi.sinks) sinkList.push([fkey, sink, path]);
      }
    }
    entrySinks.set(ekey, sinkList);
  }

  const globallyReachable = new Set<string>();
  for (const s of reachableFrom.values()) for (const k of s) globallyReachable.add(k);
  return { entries, reachableFrom, entrySinks, globallyReachable };
}

function disposition(
  allFuncs: Map<string, FunctionInfo>,
  globallyReachable: Set<string>
): Record<string, string[]> {
  const buckets: Record<string, string[]> = {
    entry_point: [],
    reachable_with_sink: [],
    reachable_no_sink: [],
    not_reachable_from_entry: [],
  };
  for (const [key, fi] of allFuncs) {
    if (fi.isEntry) buckets.entry_point.push(key);
    else if (globallyReachable.has(key) && fi.sinks.length) buckets.reachable_with_sink.push(key);
    else if (globallyReachable.has(key)) buckets.reachable_no_sink.push(key);
    else buckets.not_reachable_from_entry.push(key);
  }
  return buckets;
}

/** Full pipeline: parse every file, build graph, reachability, ledger. */
export function buildModel(
  root: string,
  files: SourceFile[],
  parser: Parser
): Model {
  const allFuncs = new Map<string, FunctionInfo>();
  const fileSources = new Map<string, string[]>();
  const parseErrors: Array<[string, string]> = [];
  const scanned: string[] = [];
  const treeByRel = new Map<string, Parser.Tree>();

  for (const { rel, src } of files) {
    scanned.push(rel);
    let tree: Parser.Tree;
    try {
      tree = parser.parse(src);
    } catch (e) {
      parseErrors.push([rel, String(e)]);
      continue;
    }
    fileSources.set(rel, src.split("\n"));
    treeByRel.set(rel, tree);
    const funcs = visitModule(tree.rootNode, rel);
    for (const [q, fi] of funcs) {
      allFuncs.set(`${rel}::${q}`, fi);
    }
  }

  // second pass, after ALL files are known, to resolve __main__ entry points
  // (a __main__ block may invoke a function defined in another file).
  for (const tree of treeByRel.values()) {
    walkForMain(tree.rootNode, allFuncs);
  }

  const { edges, unresolved, ambiguous } = buildCallGraph(allFuncs);
  const { entries, reachableFrom, entrySinks, globallyReachable } =
    reachability(allFuncs, edges);
  const buckets = disposition(allFuncs, globallyReachable);

  for (const t of treeByRel.values()) t.delete();

  let totalBlind = 0, totalSinks = 0;
  for (const fi of allFuncs.values()) {
    totalBlind += fi.blindspots.length;
    totalSinks += fi.sinks.length;
  }
  let totalUnresolved = 0;
  for (const v of unresolved.values()) totalUnresolved += v.length;
  let totalAmbiguous = 0;
  for (const v of ambiguous.values()) totalAmbiguous += v.length;

  return {
    root,
    funcs: allFuncs,
    edges,
    fileSources,
    unresolved,
    ambiguous,
    entries,
    reachableFrom,
    entrySinks,
    buckets,
    files: scanned,
    parseErrors,
    stats: {
      files: scanned.length,
      functions: allFuncs.size,
      entry_points: entries.length,
      sinks: totalSinks,
      blindspots: totalBlind,
      unresolved_calls: totalUnresolved,
      ambiguous_calls: totalAmbiguous,
      parse_errors: parseErrors.length,
    },
  };
}

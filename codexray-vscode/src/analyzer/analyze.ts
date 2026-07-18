/**
 * CodeXray analyzer core — LANGUAGE-AGNOSTIC.
 *
 * Per-file extraction is delegated to a LanguageAdapter (see adapters/). This
 * file owns everything downstream: call graph, reachability, coverage ledger.
 *
 * Emits ANATOMY + a COVERAGE LEDGER, never a vulnerability verdict:
 *   - every entry point in the source (HTTP routes, scripts, __main__/CLI)
 *   - every dangerous sink
 *   - which entry points can reach which sinks (with a witness path)
 *   - a disposition bucket for every function so nothing is silently skipped
 *   - explicitly MARKED blind spots where static analysis cannot see
 */
import Parser from "web-tree-sitter";
import { FunctionInfo, Model, SinkTuple } from "./model";
import { LanguageAdapter, adapterForExt, externalNames } from "./adapters";
import * as path from "path";

export interface SourceFile {
  rel: string;
  src: string;
  /** adapter id chosen for this file (from its extension). */
  lang: string;
}

function buildCallGraph(
  allFuncs: Map<string, FunctionInfo>,
  externalOk: Set<string>
): {
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
        const p: string[] = [];
        let node: string | null = fkey;
        while (node !== null && node !== undefined) {
          p.push(node);
          node = parent.get(node) ?? null;
        }
        p.reverse();
        for (const sink of fi.sinks) sinkList.push([fkey, sink, p]);
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

/** Full pipeline: parse every file with its adapter, build graph, reachability, ledger. */
export function buildModel(
  root: string,
  files: SourceFile[],
  parsers: Map<string, Parser>
): Model {
  const allFuncs = new Map<string, FunctionInfo>();
  const fileSources = new Map<string, string[]>();
  const parseErrors: Array<[string, string]> = [];
  const scanned: string[] = [];
  const usedAdapters = new Map<string, LanguageAdapter>();
  const treesByAdapter = new Map<string, Parser.Tree[]>();
  const languages: Record<string, number> = {};

  for (const { rel, src, lang } of files) {
    scanned.push(rel);
    const ext = path.extname(rel);
    const adapter = adapterForExt(ext);
    const parser = parsers.get(lang);
    if (!adapter || !parser) {
      parseErrors.push([rel, `no adapter/parser for '${lang}'`]);
      continue;
    }
    usedAdapters.set(adapter.id, adapter);
    languages[adapter.id] = (languages[adapter.id] ?? 0) + 1;
    let tree: Parser.Tree;
    try {
      tree = parser.parse(src);
    } catch (e) {
      parseErrors.push([rel, String(e)]);
      continue;
    }
    fileSources.set(rel, src.split("\n"));
    (treesByAdapter.get(adapter.id) ?? treesByAdapter.set(adapter.id, []).get(adapter.id)!).push(tree);
    const funcs = adapter.extract(tree.rootNode, rel);
    for (const [q, fi] of funcs) {
      allFuncs.set(`${rel}::${q}`, fi);
    }
  }

  // Cross-file post-passes (e.g. Python __main__ resolution).
  for (const [id, adapter] of usedAdapters) {
    if (adapter.postPass) adapter.postPass(treesByAdapter.get(id) ?? [], allFuncs);
  }

  const externalOk = externalNames(usedAdapters.values());
  const { edges, unresolved, ambiguous } = buildCallGraph(allFuncs, externalOk);
  const { entries, reachableFrom, entrySinks, globallyReachable } =
    reachability(allFuncs, edges);
  const buckets = disposition(allFuncs, globallyReachable);

  for (const trees of treesByAdapter.values()) for (const t of trees) t.delete();

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
    languages,
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

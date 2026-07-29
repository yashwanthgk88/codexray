/** Serialize the analysis Model into the JSON payload the webview report renders. */
import { Model, FunctionInfo } from "./model";
import { hashCode } from "../review/store";

const leaf = (key: string): string => (key.includes("::") ? key.split("::").pop()! : key);

/** Display metadata + review ordering per sink category. Ordering reflects blast
 *  radius of the sink class, NOT a verdict — the analyst still decides. */
const CATEGORY_META: Record<string, { label: string; order: number }> = {
  command_exec: { label: "OS command execution", order: 1 },
  code_exec: { label: "Code execution", order: 2 },
  deserialization: { label: "Unsafe deserialization", order: 3 },
  template_injection: { label: "Template injection", order: 4 },
  sql: { label: "SQL query", order: 5 },
  file_inclusion: { label: "File inclusion", order: 6 },
  ssrf: { label: "Outbound request (SSRF)", order: 7 },
  variable_injection: { label: "Variable injection", order: 8 },
  ldap: { label: "LDAP query", order: 9 },
  file_io: { label: "File access", order: 10 },
  xss: { label: "Output to response (XSS)", order: 11 },
  header_injection: { label: "Response header", order: 12 },
  response_write: { label: "Response write", order: 13 },
};
const catOrder = (c: string): number => CATEGORY_META[c]?.order ?? 99;
const catLabel = (c: string): string => CATEGORY_META[c]?.label ?? c;

const snippet = (lines: string[], ln: number): string =>
  ln >= 1 && ln <= lines.length ? lines[ln - 1].trim() : "";

/** Residual-risk level given a taint finding's controls:
 *  none = no control seen; weak = control present but none defends this category;
 *  guarded = a category-relevant control is present; na = not a taint chain. */
function defenseLevel(t: { controls: Array<{ relevant: boolean }> } | undefined): string {
  if (!t) return "na";
  if (t.controls.some((c) => c.relevant)) return "guarded";
  if (t.controls.length) return "weak";
  return "none";
}

/**
 * Build the ranked flow list — the heart of the taint visualization. One flow =
 * an entry point that reaches a sink, annotated with the taint chain when a
 * source demonstrably reaches that sink inside its function.
 */
function buildFlows(model: Model): any[] {
  const flows: any[] = [];
  let id = 0;
  for (const ekey of model.entries) {
    const entry = model.funcs.get(ekey)!;
    for (const [sinkKey, sink, pathArr] of model.entrySinks.get(ekey) ?? []) {
      const sinkFn = model.funcs.get(sinkKey)!;
      const sinkLines = model.fileSources.get(sinkFn.file) ?? [];
      const [sinkName, category, why, sinkLine] = sink;

      // Is there an intra-function taint chain landing on THIS sink line?
      const t = sinkFn.taint.find((x) => x.sink === sinkName && x.sinkLine === sinkLine);
      const srcLines = t ? model.fileSources.get(sinkFn.file) ?? [] : [];

      const pathNodes = pathArr.map((k) => {
        const f = model.funcs.get(k)!;
        return { key: k, name: f.qualname, file: f.file, line: f.lineno };
      });

      flows.push({
        id: id++,
        entryKey: ekey,
        entryName: entry.qualname,
        entryFile: entry.file,
        entryKind: entry.entryKind,
        entryMeta: entry.entryMeta,
        category,
        categoryLabel: catLabel(category),
        sinkKey,
        sink: sinkName,
        sinkWhy: why,
        sinkFile: sinkFn.file,
        sinkFunc: sinkFn.qualname,
        sinkLine,
        sinkCode: snippet(sinkLines, sinkLine),
        tainted: !!t,
        origin: t?.origin ?? null,
        originLine: t?.originLine ?? null,
        originCode: t ? snippet(srcLines, t.originLine) : null,
        via: t?.via ?? [],
        controls: t?.controls ?? [],
        defense: defenseLevel(t),
        crossFunction: pathNodes.length > 1,
        path: pathNodes,
      });
    }
  }
  // Rank: tainted before reachable; within tainted, UNDEFENDED first (that's the
  // real residual risk), then by sink-class blast radius, then by file.
  const defRank: Record<string, number> = { none: 0, weak: 1, guarded: 2, na: 3 };
  flows.sort((a, b) => {
    if (a.tainted !== b.tainted) return a.tainted ? -1 : 1;
    if (defRank[a.defense] !== defRank[b.defense]) return defRank[a.defense] - defRank[b.defense];
    if (catOrder(a.category) !== catOrder(b.category)) return catOrder(a.category) - catOrder(b.category);
    return a.entryFile.localeCompare(b.entryFile);
  });
  return flows;
}

/** Complete catalog: every sink and source in the code, reachable or not,
 *  tainted or not — the full attack-surface inventory for the analyst. */
function buildInventory(model: Model): { sinks: any[]; sources: any[] } {
  const reachable = new Set<string>();
  for (const b of ["entry_point", "reachable_with_sink", "reachable_no_sink"]) {
    for (const k of model.buckets[b] ?? []) reachable.add(k);
  }
  const sinks: any[] = [];
  const sources: any[] = [];
  for (const [key, fi] of model.funcs) {
    const isReach = reachable.has(key);
    for (const [name, cat, why, ln] of fi.sinks) {
      const t = fi.taint.find((x) => x.sink === name && x.sinkLine === ln);
      sinks.push({
        name, category: cat, categoryLabel: catLabel(cat), why,
        func: fi.qualname, file: fi.file, line: ln,
        reachable: isReach, tainted: !!t,
        defense: t ? defenseLevel(t) : "na",
        controls: t ? t.controls : [],
      });
    }
    for (const [name, ln] of fi.sources) {
      sources.push({ name, func: fi.qualname, file: fi.file, line: ln, reachable: isReach });
    }
  }
  sinks.sort((a, b) =>
    catOrder(a.category) - catOrder(b.category) || a.file.localeCompare(b.file) || a.line - b.line);
  sources.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  return { sinks, sources };
}

function funcToJson(model: Model, key: string, fi: FunctionInfo): any {
  const srcLines = model.fileSources.get(fi.file) ?? [];
  const body: Array<{ n: number; t: string }> = [];
  const lastLine = Math.min(fi.endlineno, srcLines.length);
  for (let ln = fi.lineno; ln <= lastLine; ln++) {
    body.push({ n: ln, t: ln - 1 < srcLines.length ? srcLines[ln - 1] : "" });
  }

  const events: Record<number, any[]> = {};
  const add = (ln: number, ev: any) => {
    (events[ln] ?? (events[ln] = [])).push(ev);
  };
  for (const [dotted, cat, why, ln] of fi.sinks) add(ln, { kind: "sink", label: dotted, cat, why });
  for (const [name, ln] of fi.sources) add(ln, { kind: "source", label: name });
  for (const [dotted, reason, ln] of fi.blindspots) add(ln, { kind: "blind", label: dotted, why: reason });

  const calleeKeys = model.edges.get(key) ?? new Set<string>();
  const calleeByShort: Record<string, string> = {};
  for (const ck of calleeKeys) calleeByShort[leaf(ck)] = ck;
  const children: any[] = [];
  for (const [short, , lineno] of fi.calls) {
    if (short in calleeByShort) {
      children.push({ line: lineno, target: calleeByShort[short], name: short, resolved: true });
    }
  }

  return {
    key,
    name: fi.qualname,
    file: fi.file,
    lang: fi.language,
    line: fi.lineno,
    endline: fi.endlineno,
    is_entry: fi.isEntry,
    entry_kind: fi.entryKind,
    entry_meta: fi.entryMeta,
    params: fi.params,
    body,
    events,
    children,
    nsinks: fi.sinks.length,
    nblind: fi.blindspots.length,
    codeHash: hashCode(body.map((b) => b.t).join("\n")),
  };
}

export function buildPayload(model: Model): any {
  const funcJson: Record<string, any> = {};
  for (const [key, fi] of model.funcs) funcJson[key] = funcToJson(model, key, fi);

  const entries: any[] = [];
  for (const ekey of model.entries) {
    const fi = model.funcs.get(ekey)!;
    const sinkCats = new Set<string>();
    for (const s of model.entrySinks.get(ekey) ?? []) sinkCats.add(s[1][1]);
    const sources = new Set<string>();
    for (const s of fi.sources) sources.add(s[0]);
    entries.push({
      key: ekey,
      name: fi.qualname,
      kind: fi.entryKind,
      meta: fi.entryMeta,
      reach: (model.reachableFrom.get(ekey) ?? new Set()).size,
      sink_cats: [...sinkCats].sort(),
      sources: [...sources].sort(),
    });
  }

  const ledger: Record<string, any[]> = {};
  for (const [bucket, keys] of Object.entries(model.buckets)) {
    ledger[bucket] = [];
    for (const key of [...keys].sort()) {
      const fi = model.funcs.get(key)!;
      const cats = new Set<string>();
      for (const s of fi.sinks) cats.add(s[1]);
      ledger[bucket].push({
        key, name: fi.qualname, file: fi.file, line: fi.lineno,
        endline: fi.endlineno, cats: [...cats].sort(), nblind: fi.blindspots.length,
      });
    }
  }

  const blindRows: any[] = [];
  for (const [key, fi] of model.funcs) {
    for (const [dotted, reason, lineno] of fi.blindspots) {
      blindRows.push({ func: fi.qualname, file: fi.file, line: lineno, call: dotted, reason, key });
    }
  }

  const flows = buildFlows(model);
  const taintedFlows = flows.filter((f) => f.tainted).length;
  const undefended = flows.filter((f) => f.tainted && f.defense === "none").length;

  return {
    root: model.root,
    stats: { ...model.stats, tainted_flows: taintedFlows, undefended, flows: flows.length },
    languages: model.languages,
    funcs: funcJson,
    entries,
    ledger,
    blind_rows: blindRows,
    flows,
    inventory: buildInventory(model),
  };
}

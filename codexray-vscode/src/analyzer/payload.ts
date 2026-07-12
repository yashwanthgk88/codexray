/** Serialize the analysis Model into the JSON payload the webview report renders. */
import { Model } from "./model";

const leaf = (key: string): string => (key.includes("::") ? key.split("::").pop()! : key);

export function buildPayload(model: Model): any {
  const funcs = model.funcs;
  const edges = model.edges;
  const fileSources = model.fileSources;

  const funcJson: Record<string, any> = {};
  for (const [key, fi] of funcs) {
    const srcLines = fileSources.get(fi.file) ?? [];
    const body: Array<{ n: number; t: string }> = [];
    const lastLine = Math.min(fi.endlineno, srcLines.length);
    for (let ln = fi.lineno; ln <= lastLine; ln++) {
      body.push({ n: ln, t: ln - 1 < srcLines.length ? srcLines[ln - 1] : "" });
    }

    const events: Record<number, any[]> = {};
    const add = (ln: number, ev: any) => {
      (events[ln] ?? (events[ln] = [])).push(ev);
    };
    for (const [dotted, cat, why, ln] of fi.sinks) {
      add(ln, { kind: "sink", label: dotted, cat, why });
    }
    for (const [name, ln] of fi.sources) {
      add(ln, { kind: "source", label: name });
    }
    for (const [dotted, reason, ln] of fi.blindspots) {
      add(ln, { kind: "blind", label: dotted, why: reason });
    }

    const calleeKeys = edges.get(key) ?? new Set<string>();
    const calleeByShort: Record<string, string> = {};
    for (const ck of calleeKeys) calleeByShort[leaf(ck)] = ck;
    const children: any[] = [];
    for (const [short, , lineno] of fi.calls) {
      if (short in calleeByShort) {
        children.push({ line: lineno, target: calleeByShort[short], name: short, resolved: true });
      }
    }

    funcJson[key] = {
      key,
      name: fi.qualname,
      file: fi.file,
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
    };
  }

  const entries: any[] = [];
  for (const ekey of model.entries) {
    const fi = funcs.get(ekey)!;
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
      const fi = funcs.get(key)!;
      const cats = new Set<string>();
      for (const s of fi.sinks) cats.add(s[1]);
      ledger[bucket].push({
        key,
        name: fi.qualname,
        file: fi.file,
        line: fi.lineno,
        endline: fi.endlineno,
        cats: [...cats].sort(),
        nblind: fi.blindspots.length,
      });
    }
  }

  const blindRows: any[] = [];
  for (const [key, fi] of funcs) {
    for (const [dotted, reason, lineno] of fi.blindspots) {
      blindRows.push({ func: fi.qualname, file: fi.file, line: lineno, call: dotted, reason, key });
    }
  }

  return {
    root: model.root,
    stats: model.stats,
    funcs: funcJson,
    entries,
    ledger,
    blind_rows: blindRows,
  };
}

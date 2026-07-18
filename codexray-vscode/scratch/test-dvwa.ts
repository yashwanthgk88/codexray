// Headless end-to-end: run the analyzer core on a real folder (no vscode).
import * as fs from "fs";
import * as path from "path";
import { getParsers } from "../src/analyzer/parser";
import { buildModel, SourceFile } from "../src/analyzer/analyze";
import { adapterForExt } from "../src/analyzer/adapters";

const IGNORE = new Set([".git", "__pycache__", "node_modules", ".venv", "venv", "env"]);

function collect(root: string): SourceFile[] {
  const out: SourceFile[] = [];
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!IGNORE.has(e.name)) stack.push(full); }
      else if (e.isFile()) {
        const a = adapterForExt(path.extname(e.name));
        if (!a) continue;
        try { out.push({ rel: path.relative(root, full), src: fs.readFileSync(full, "utf-8"), lang: a.id }); } catch {}
      }
    }
  }
  return out;
}

(async () => {
  const root = process.argv[2];
  const files = collect(root);
  const parsers = await getParsers(path.join(__dirname, "..", "dist"), files.map((f) => f.lang));
  const model = buildModel(root, files, parsers);
  console.log("stats:", JSON.stringify(model.stats));
  console.log("languages:", JSON.stringify(model.languages));

  // Show the top entry points that reach sinks, with a witness path + sink.
  const withSinks: Array<{ entry: string; nsinks: number; cats: Set<string> }> = [];
  for (const ekey of model.entries) {
    const sinks = model.entrySinks.get(ekey) ?? [];
    if (!sinks.length) continue;
    const cats = new Set<string>();
    for (const [, sink] of sinks) cats.add(sink[1]);
    withSinks.push({ entry: ekey, nsinks: sinks.length, cats });
  }
  withSinks.sort((a, b) => b.nsinks - a.nsinks);
  console.log(`\nentries reaching >=1 sink: ${withSinks.length}`);
  for (const w of withSinks.slice(0, 8)) {
    console.log(`  ${w.entry}  [${[...w.cats].join(",")}]  (${w.nsinks} sink hits)`);
  }

  // Show one full flow in detail.
  const sample = withSinks.find((w) => w.cats.has("sql") || w.cats.has("command_exec")) ?? withSinks[0];
  if (sample) {
    console.log(`\n=== sample flow from ${sample.entry} ===`);
    for (const [fkey, sink, pathArr] of (model.entrySinks.get(sample.entry) ?? []).slice(0, 6)) {
      const fi = model.funcs.get(fkey)!;
      console.log(`  SINK ${sink[0]} (${sink[1]}: ${sink[2]}) at ${fi.file}:${sink[3]}`);
      console.log(`    path: ${pathArr.map((k) => k.split("::").pop()).join(" -> ")}`);
      const src = model.funcs.get(sample.entry)!;
      if (src.sources.length) console.log(`    entry sources: ${src.sources.map((s) => s[0]).join(", ")}`);
    }
  }
})();

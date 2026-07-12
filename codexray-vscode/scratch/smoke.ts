import * as fs from "fs";
import * as path from "path";
import { getParser } from "../src/analyzer/parser";
import { buildModel, SourceFile } from "../src/analyzer/analyze";
import { buildPayload } from "../src/analyzer/payload";

function collect(root: string): SourceFile[] {
  const out: SourceFile[] = [];
  for (const name of fs.readdirSync(root)) {
    const full = path.join(root, name);
    if (fs.statSync(full).isFile() && name.endsWith(".py")) {
      out.push({ rel: path.relative(root, full), src: fs.readFileSync(full, "utf-8") });
    }
  }
  return out;
}

(async () => {
  const root = process.argv[2] || path.join(__dirname, "..", "..", "sample_app");
  const wasmDir = path.join(__dirname, "..", "dist");
  const parser = await getParser(wasmDir);
  const model = buildModel(root, collect(root), parser);
  console.log("=== STATS ===");
  console.log(JSON.stringify(model.stats, null, 2));
  console.log("\n=== ENTRY POINTS ===");
  for (const ek of model.entries) {
    const fi = model.funcs.get(ek)!;
    const cats = new Set<string>();
    for (const s of model.entrySinks.get(ek) || []) cats.add(s[1][1]);
    console.log(`  [${fi.entryMeta.method}] ${fi.entryMeta.path}  -> reach ${model.reachableFrom.get(ek)!.size}, sinks: ${[...cats].join(", ") || "none"}`);
  }
  console.log("\n=== BLIND SPOTS ===");
  for (const [, fi] of model.funcs) {
    for (const [call, reason, ln] of fi.blindspots) {
      console.log(`  ${fi.file}:${ln}  ${call}  (${reason})`);
    }
  }
  console.log("\n=== LEDGER BUCKETS ===");
  for (const [b, keys] of Object.entries(model.buckets)) {
    console.log(`  ${b}: ${keys.length}`);
  }
  const payload = buildPayload(model);
  console.log("\npayload ok — funcs:", Object.keys(payload.funcs).length, "entries:", payload.entries.length);
})().catch((e) => { console.error(e); process.exit(1); });

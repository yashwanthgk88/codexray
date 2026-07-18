/**
 * Verify the Java / C# / TypeScript adapters against known-vulnerable fixtures.
 * Asserts on entry points, tainted flows, and defense grades (none/weak/guarded).
 * Run: npx ts-node scratch/verify-langs.ts
 */
import * as fs from "fs";
import * as path from "path";
import { getParsers } from "../src/analyzer/parser";
import { buildModel } from "../src/analyzer/analyze";
import { buildPayload } from "../src/analyzer/payload";
import { adapterForExt } from "../src/analyzer/adapters";

function collect(root: string): any[] {
  const out: any[] = [];
  for (const name of fs.readdirSync(root)) {
    const full = path.join(root, name);
    if (fs.statSync(full).isFile()) {
      const a = adapterForExt(path.extname(name));
      if (a) out.push({ rel: name, src: fs.readFileSync(full, "utf-8"), lang: a.id });
    }
  }
  return out;
}

let pass = 0, fail = 0;
function check(name: string, cond: boolean, detail = ""): void {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; console.log(`  ✗ ${name} ${detail}`); }
}

async function run(dir: string, label: string, expect: (p: any) => void): Promise<void> {
  const root = path.join(__dirname, "fixtures", dir);
  const files = collect(root);
  const parsers = await getParsers(path.join(__dirname, "..", "dist"), files.map((f) => f.lang));
  const payload = buildPayload(buildModel(root, files, parsers));
  console.log(`\n=== ${label} ===`);
  console.log(`  stats: ${JSON.stringify(payload.stats)}`);
  expect(payload);
}

const flowsBy = (p: any, cat: string, def?: string) =>
  p.flows.filter((f: any) => f.category === cat && f.tainted && (def === undefined || f.defense === def));

(async () => {
  await run("java", "Java", (p) => {
    check("entry points found (>=4)", p.stats.entry_points >= 4, `got ${p.stats.entry_points}`);
    check("tainted flows found", p.stats.tainted_flows >= 3, `got ${p.stats.tainted_flows}`);
    check("undefended command_exec", flowsBy(p, "command_exec", "none").length >= 1);
    check("undefended sql", flowsBy(p, "sql", "none").length >= 1);
    check("guarded command_exec (parseInt)", flowsBy(p, "command_exec", "guarded").length >= 1);
    check("weak sql (htmlEscape wrong defense)", flowsBy(p, "sql", "weak").length >= 1);
  });

  await run("csharp", "C#", (p) => {
    check("entry points found (>=3)", p.stats.entry_points >= 3, `got ${p.stats.entry_points}`);
    check("tainted flows found", p.stats.tainted_flows >= 2, `got ${p.stats.tainted_flows}`);
    check("undefended command_exec", flowsBy(p, "command_exec", "none").length >= 1);
    check("undefended sql (SqlCommand ctor)", flowsBy(p, "sql", "none").length >= 1);
    check("guarded command_exec (int.Parse)", flowsBy(p, "command_exec", "guarded").length >= 1);
  });

  await run("ts", "TypeScript", (p) => {
    check("route entry points found (>=4)", p.stats.entry_points >= 4, `got ${p.stats.entry_points}`);
    check("tainted flows found", p.stats.tainted_flows >= 3, `got ${p.stats.tainted_flows}`);
    check("undefended command_exec", flowsBy(p, "command_exec", "none").length >= 1);
    check("DESTRUCTURING taint -> sql", flowsBy(p, "sql", "none").length >= 1);
    check("guarded command_exec (Number)", flowsBy(p, "command_exec", "guarded").length >= 1);
    check("innerHTML xss", flowsBy(p, "xss").length >= 1);
  });

  console.log(`\n${"=".repeat(40)}\nRESULT: ${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();

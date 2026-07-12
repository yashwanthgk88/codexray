import * as fs from "fs";
import * as path from "path";
import { getParser } from "../src/analyzer/parser";
import { buildModel } from "../src/analyzer/analyze";
(async () => {
  const root = path.join(__dirname, "..", "..", "sample_app");
  const parser = await getParser(path.join(__dirname, "..", "dist"));
  const files = fs.readdirSync(root).filter(f=>f.endsWith(".py")).map(f=>({rel:f,src:fs.readFileSync(path.join(root,f),"utf-8")}));
  const m = buildModel(root, files, parser);
  const c = {};
  for (const v of m.unresolved.values()) for (const [short] of v) c[short]=(c[short]||0)+1;
  console.log("TS unresolved:", c);
})();

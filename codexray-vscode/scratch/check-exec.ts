import * as fs from "fs";
import * as path from "path";
import { getParsers } from "../src/analyzer/parser";
import { buildModel } from "../src/analyzer/analyze";
(async () => {
  const root = "/Users/yashwanthgk/Downloads/DVWA-master";
  const parsers = await getParsers(path.join(__dirname, "..", "dist"), ["php"]);
  for (const rel of ["vulnerabilities/exec/source/low.php", "vulnerabilities/sqli/source/low.php", "vulnerabilities/fi/source/low.php"]) {
    const src = fs.readFileSync(path.join(root, rel), "utf-8");
    const model = buildModel(root, [{ rel, src, lang: "php" }], parsers);
    console.log(`\n### ${rel}`);
    for (const [, fi] of model.funcs) {
      if (fi.taint.length) {
        for (const t of fi.taint)
          console.log(`  TAINT: ${t.origin}@${t.originLine} --[${t.via.join(",")||"direct"}]--> ${t.sink}()@${t.sinkLine}  (${t.category})`);
      }
    }
  }
})();

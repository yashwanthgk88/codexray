import * as fs from "fs"; import * as path from "path";
import { getParsers } from "../src/analyzer/parser";
import { buildModel } from "../src/analyzer/analyze";
(async () => {
  const root = "/Users/yashwanthgk/Downloads/DVWA-master";
  const parsers = await getParsers(path.join(__dirname, "..", "dist"), ["php"]);
  const files = [
    "vulnerabilities/exec/source/low.php","vulnerabilities/exec/source/high.php",
    "vulnerabilities/sqli/source/low.php","vulnerabilities/sqli/source/high.php",
    "vulnerabilities/xss_r/source/low.php","vulnerabilities/xss_r/source/high.php",
  ];
  for (const rel of files) {
    let src; try { src = fs.readFileSync(path.join(root, rel), "utf-8"); } catch { continue; }
    const model = buildModel(root, [{ rel, src, lang: "php" }], parsers);
    console.log("\n### " + rel);
    for (const [, fi] of model.funcs)
      for (const t of fi.taint) {
        const ctl = t.controls.length ? t.controls.map((c:any)=>`${c.label}${c.relevant?"✓":"✗"}`).join(", ") : "NONE";
        console.log(`  ${t.origin} -> ${t.sink}()@${t.sinkLine} [${t.category}]  controls: ${ctl}`);
      }
  }
})();

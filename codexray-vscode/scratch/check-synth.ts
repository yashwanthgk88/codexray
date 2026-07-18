import * as path from "path";
import { getParsers } from "../src/analyzer/parser";
import { buildModel } from "../src/analyzer/analyze";
const SRC = `<?php
$t = $_GET['ip'];
$safe = escapeshellarg($t);
system('ping ' . $safe);
system('ping ' . htmlspecialchars($t));
$q = mysqli_real_escape_string($conn, $_GET['q']);
mysqli_query($c, "SELECT " . $q);
echo htmlspecialchars($_GET['x']);
$id = intval($_GET['id']);
system("id " . $id);
`;
(async () => {
  const parsers = await getParsers(path.join(__dirname, "..", "dist"), ["php"]);
  const model = buildModel("/x", [{ rel: "synth.php", src: SRC, lang: "php" }], parsers);
  for (const [, fi] of model.funcs)
    for (const t of fi.taint) {
      const ctl = t.controls.length ? t.controls.map((c:any)=>`${c.label}${c.relevant?" ✓relevant":" ✗not-relevant"}`).join(", ") : "NONE";
      console.log(`${t.origin} -> ${t.sink}()@${t.sinkLine} [${t.category}]\n   controls: ${ctl}`);
    }
})();

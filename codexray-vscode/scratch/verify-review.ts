/**
 * Headless tests for the review instrument logic (store + export).
 * Run: npx ts-node scratch/verify-review.ts
 */
import {
  hashCode, emptyReview, setDisposition, mergeReviews, annotatePayload, isReviewed,
} from "../src/review/store";
import { buildMarkdown, buildHtml, buildSarif } from "../src/review/export";

let pass = 0, fail = 0;
const check = (name: string, cond: boolean, detail = "") =>
  cond ? (pass++, console.log(`  ✓ ${name}`)) : (fail++, console.log(`  ✗ ${name} ${detail}`));

const T0 = "2026-01-01T00:00:00.000Z";
const T1 = "2026-01-02T00:00:00.000Z";
const T2 = "2026-01-03T00:00:00.000Z";

// Fake analysis payload with two functions and one tainted/undefended flow.
function fakePayload(): any {
  return {
    root: "/repo",
    languages: { python: 2 },
    stats: { files: 2, entry_points: 1, sinks: 2, tainted_flows: 1, undefended: 1, blindspots: 1 },
    funcs: {
      "a.py::run": { name: "run", file: "a.py", line: 3, nblind: 0, codeHash: hashCode("os.system(x)") },
      "a.py::helper": { name: "helper", file: "a.py", line: 20, nblind: 1, codeHash: hashCode("getattr(o,n)") },
    },
    ledger: {
      entry_point: [{ key: "a.py::run" }],
      reachable_with_sink: [{ key: "a.py::run", name: "run", file: "a.py", line: 3 }],
      reachable_no_sink: [], not_reachable_from_entry: [],
    },
    flows: [{
      id: 0, sinkKey: "a.py::run", entryKey: "a.py::run", entryName: "run",
      category: "command_exec", categoryLabel: "OS command execution",
      sink: "os.system", sinkFile: "a.py", sinkLine: 3, sinkCode: "os.system(x)",
      tainted: true, defense: "none", origin: "request.args", originLine: 2, via: ["x"],
      path: [{ name: "run" }],
    }],
    blind_rows: [{ func: "helper", file: "a.py", line: 20, call: "getattr", reason: "dynamic dispatch", key: "a.py::helper" }],
  };
}

console.log("=== store: hashing + disposition ===");
check("hash deterministic", hashCode("abc") === hashCode("abc"));
check("hash differs on change", hashCode("abc") !== hashCode("abd"));
check("isReviewed", isReviewed("finding") && !isReviewed("unreviewed"));

let rev = emptyReview({ name: "Engagement X", reviewer: "alice", createdAt: T0 }, T0);
setDisposition(rev, "a.py::run", { status: "finding", note: "cmd injection", reviewer: "alice", codeHash: hashCode("os.system(x)"), now: T1 });
check("disposition stored", rev.functions["a.py::run"]?.status === "finding");
check("engagement updatedAt bumped", rev.engagement.updatedAt === T1);

// Clearing to unreviewed removes the record.
const rev2 = emptyReview({ name: "e", reviewer: "a" }, T0);
setDisposition(rev2, "k", { status: "safe", reviewer: "a", codeHash: "h", now: T1 });
setDisposition(rev2, "k", { status: "unreviewed", reviewer: "a", codeHash: "h", now: T2 });
check("clearing disposition removes record", !rev2.functions["k"]);

console.log("\n=== annotate + completeness + staleness ===");
const pl = fakePayload();
annotatePayload(pl, rev);
check("func review overlaid", pl.funcs["a.py::run"].review.status === "finding");
check("completeness computed", pl.review.completeness.reviewed === 1 && pl.review.completeness.total === 2);
check("percent 50", pl.review.completeness.percent === 50);
check("unreviewed func defaulted", pl.funcs["a.py::helper"].review.status === "unreviewed");

// Staleness: change the function body hash, re-annotate.
const pl2 = fakePayload();
pl2.funcs["a.py::run"].codeHash = hashCode("os.system(x) # edited");
annotatePayload(pl2, rev);
check("stale detected on code change", pl2.funcs["a.py::run"].review.stale === true);
check("stale counted", pl2.review.completeness.stale === 1);

console.log("\n=== merge (multi-reviewer) ===");
const base = emptyReview({ name: "e", reviewer: "alice" }, T0);
setDisposition(base, "k1", { status: "safe", reviewer: "alice", codeHash: "h", now: T1 });
setDisposition(base, "k2", { status: "reviewing", reviewer: "alice", codeHash: "h", now: T1 });
const incoming = emptyReview({ name: "e", reviewer: "bob" }, T0);
setDisposition(incoming, "k2", { status: "finding", reviewer: "bob", codeHash: "h", now: T2 }); // newer wins
setDisposition(incoming, "k3", { status: "safe", reviewer: "bob", codeHash: "h", now: T1 });
const merged = mergeReviews(base, incoming);
check("merge keeps base-only", merged.functions["k1"]?.reviewer === "alice");
check("merge newer wins", merged.functions["k2"]?.status === "finding" && merged.functions["k2"]?.reviewer === "bob");
check("merge adds incoming-only", merged.functions["k3"]?.reviewer === "bob");

console.log("\n=== export: markdown / html / sarif ===");
const apl = fakePayload();
annotatePayload(apl, rev);
const md = buildMarkdown(apl, rev);
check("md has engagement", md.includes("Engagement X"));
check("md has confirmed finding", /Confirmed findings \(1\)/.test(md));
check("md lists blind spot", md.includes("getattr"));
check("md has coverage %", md.includes("50%"));
const html = buildHtml(apl, rev);
check("html self-contained", html.startsWith("<!doctype html>") && html.includes("</html>"));
check("html rendered heading", html.includes("<h1>") && html.includes("Security Review"));
const sarif = buildSarif(apl, rev);
check("sarif version", sarif.version === "2.1.0");
check("sarif has finding result", sarif.runs[0].results.some((r: any) => r.ruleId === "command_exec" && r.level === "error"));
check("sarif has blind-spot note", sarif.runs[0].results.some((r: any) => r.ruleId === "blind_spot" && r.level === "note"));

console.log(`\n${"=".repeat(40)}\nRESULT: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

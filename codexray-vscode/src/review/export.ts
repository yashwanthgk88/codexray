/**
 * Review export (Phase 2) — turns an annotated payload + review into the
 * auditable deliverable. Three formats:
 *   - Markdown  : for git / PRs (review-as-code)
 *   - HTML      : self-contained client-facing report
 *   - SARIF     : findings for downstream tooling
 *
 * The deliverable states the three things scanners don't: what was reviewed,
 * what was explicitly NOT (blind spots + un-reviewed remainder), and by whom.
 * Pure functions — no IO, unit-tested in scratch/verify-review.ts.
 */
import { ReviewFile, Disposition } from "./store";

const STATUS_LABEL: Record<Disposition, string> = {
  unreviewed: "Unreviewed",
  reviewing: "In progress",
  safe: "Safe",
  finding: "Finding",
  needs_info: "Needs info",
  false_positive: "False positive",
};

interface FuncView {
  key: string;
  name: string;
  file: string;
  line: number;
  review: { status: Disposition; note: string; reviewer: string; reviewedAt: string; stale: boolean };
  cats?: string[];
  nblind?: number;
}

function funcsWith(payload: any, pred: (f: FuncView) => boolean): FuncView[] {
  const out: FuncView[] = [];
  for (const key of Object.keys(payload.funcs || {})) {
    const f = payload.funcs[key];
    const v: FuncView = {
      key, name: f.name, file: f.file, line: f.line,
      review: f.review || { status: "unreviewed", note: "", reviewer: "", reviewedAt: "", stale: false },
      nblind: f.nblind,
    };
    if (pred(v)) out.push(v);
  }
  return out;
}

const flowsForSinkFunc = (payload: any, key: string): any[] =>
  (payload.flows || []).filter((fl: any) => fl.sinkKey === key);

/** All ledger functions that contain a sink but are still unreviewed. */
function coverageGaps(payload: any): FuncView[] {
  const withSink = new Set<string>((payload.ledger?.reachable_with_sink || []).map((r: any) => r.key));
  return funcsWith(payload, (f) => withSink.has(f.key) && f.review.status === "unreviewed");
}

function undefendedUnreviewed(payload: any): any[] {
  return (payload.flows || []).filter((fl: any) => {
    if (!fl.tainted || fl.defense !== "none") return false;
    const fr = payload.funcs?.[fl.sinkKey]?.review;
    return !fr || fr.status === "unreviewed";
  });
}

// ---------------------------------------------------------------- Markdown ----

export function buildMarkdown(payload: any, review: ReviewFile): string {
  const c = payload.review?.completeness || { total: 0, reviewed: 0, percent: 0, byStatus: {}, stale: 0 };
  const s = payload.stats || {};
  const L: string[] = [];
  const p = (line = "") => L.push(line);

  p(`# Security Review — ${review.engagement.name}`);
  p();
  p(`- **Reviewer:** ${review.engagement.reviewer}`);
  p(`- **Created:** ${review.engagement.createdAt}`);
  p(`- **Updated:** ${review.engagement.updatedAt}`);
  p(`- **Target:** \`${payload.root || ""}\``);
  p(`- **Languages:** ${Object.entries(payload.languages || {}).map(([k, n]) => `${k} (${n})`).join(", ") || "—"}`);
  p();
  p(`## Review coverage`);
  p();
  p(`**${c.reviewed} / ${c.total} functions reviewed (${c.percent}%).**` + (c.stale ? `  ⚠️ ${c.stale} disposition(s) stale — code changed since sign-off.` : ""));
  p();
  p(`| Disposition | Count |`);
  p(`|---|---|`);
  for (const st of Object.keys(c.byStatus) as Disposition[]) {
    if (c.byStatus[st]) p(`| ${STATUS_LABEL[st]} | ${c.byStatus[st]} |`);
  }
  p();
  p(`Analysis surface: ${s.files || 0} files · ${s.entry_points || 0} entry points · ${s.sinks || 0} sinks · ${s.tainted_flows || 0} tainted flows (${s.undefended || 0} undefended) · ${s.blindspots || 0} blind spots.`);
  p();

  // Confirmed findings
  const findings = funcsWith(payload, (f) => f.review.status === "finding");
  p(`## Confirmed findings (${findings.length})`);
  p();
  if (!findings.length) p(`_None recorded._`);
  for (const f of findings) {
    p(`### ${f.name}  \`${f.file}:${f.line}\`${f.review.stale ? "  ⚠️ STALE" : ""}`);
    if (f.review.note) p(`> ${f.review.note.replace(/\n/g, "\n> ")}`);
    p(`_Dispositioned by ${f.review.reviewer || "?"} at ${f.review.reviewedAt || "?"}._`);
    const flows = flowsForSinkFunc(payload, f.key);
    for (const fl of flows) {
      p();
      p(`- **${fl.categoryLabel}** — \`${fl.sink}()\` at \`${fl.sinkFile}:${fl.sinkLine}\` (defense: ${fl.defense})`);
      if (fl.tainted && fl.origin) p(`  - taint: \`${fl.origin}\` (line ${fl.originLine})${fl.via?.length ? ` via ${fl.via.join(", ")}` : ""} → sink`);
      if (fl.path?.length > 1) p(`  - path: ${fl.path.map((n: any) => n.name).join(" → ")}`);
      if (fl.sinkCode) p(`  - \`${fl.sinkCode}\``);
    }
    p();
  }

  // Flagged but not yet dispositioned
  const flagged = undefendedUnreviewed(payload);
  p(`## Undefended flows not yet reviewed (${flagged.length})`);
  p();
  if (!flagged.length) p(`_None — every undefended flow has a disposition._`);
  for (const fl of flagged.slice(0, 200)) {
    p(`- **${fl.categoryLabel}** \`${fl.sink}()\` — \`${fl.sinkFile}:${fl.sinkLine}\` (entry: ${fl.entryName})`);
  }
  p();

  // Explicit blind spots — the honesty section
  p(`## Blind spots — what static analysis could not see (${(payload.blind_rows || []).length})`);
  p();
  if (!(payload.blind_rows || []).length) p(`_None recorded._`);
  for (const b of (payload.blind_rows || []).slice(0, 300)) {
    p(`- \`${b.call}\` in \`${b.func}\` (\`${b.file}:${b.line}\`) — ${b.reason}`);
  }
  p();

  // Coverage gaps
  const gaps = coverageGaps(payload);
  p(`## Coverage gaps — sink-bearing functions still unreviewed (${gaps.length})`);
  p();
  if (!gaps.length) p(`_None — every function containing a sink has been reviewed._`);
  for (const g of gaps.slice(0, 300)) p(`- \`${g.name}\` — \`${g.file}:${g.line}\``);
  p();
  p(`---`);
  p(`_Generated by CodeXray. Findings are the reviewer's recorded judgment; this is an audit record, not an automated verdict._`);
  return L.join("\n");
}

// -------------------------------------------------------------------- HTML ----

const escH = (s: any): string =>
  String(s == null ? "" : s).replace(/[&<>"]/g, (m) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" } as any)[m]);

export function buildHtml(payload: any, review: ReviewFile): string {
  const md = buildMarkdown(payload, review);
  // Minimal, dependency-free markdown → HTML (headings, bold, code, lists, quotes, tables).
  const lines = md.split("\n");
  const body: string[] = [];
  let inList = false, inTable = false;
  const closeList = () => { if (inList) { body.push("</ul>"); inList = false; } };
  const closeTable = () => { if (inTable) { body.push("</table>"); inTable = false; } };
  const inline = (t: string) =>
    escH(t)
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/_([^_]+)_/g, "<em>$1</em>");
  for (const raw of lines) {
    const line = raw;
    if (/^\|/.test(line)) {
      if (/^\|[-\s|]+\|?$/.test(line)) continue; // separator row
      const cells = line.split("|").slice(1, -1).map((x) => x.trim());
      if (!inTable) { closeList(); body.push('<table class="t">'); inTable = true; }
      body.push("<tr>" + cells.map((x) => `<td>${inline(x)}</td>`).join("") + "</tr>");
      continue;
    }
    closeTable();
    if (/^### /.test(line)) { closeList(); body.push(`<h3>${inline(line.slice(4))}</h3>`); }
    else if (/^## /.test(line)) { closeList(); body.push(`<h2>${inline(line.slice(3))}</h2>`); }
    else if (/^# /.test(line)) { closeList(); body.push(`<h1>${inline(line.slice(2))}</h1>`); }
    else if (/^> /.test(line)) { closeList(); body.push(`<blockquote>${inline(line.slice(2))}</blockquote>`); }
    else if (/^- /.test(line)) { if (!inList) { body.push("<ul>"); inList = true; } body.push(`<li>${inline(line.slice(2))}</li>`); }
    else if (/^---/.test(line)) { closeList(); body.push("<hr>"); }
    else if (line.trim() === "") { closeList(); }
    else { closeList(); body.push(`<p>${inline(line)}</p>`); }
  }
  closeList(); closeTable();
  return `<!doctype html><html><head><meta charset="utf-8"><title>Security Review — ${escH(review.engagement.name)}</title>
<style>
body{font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;max-width:920px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}
h1{font-size:1.7rem;border-bottom:2px solid #eee;padding-bottom:.3rem}
h2{font-size:1.25rem;margin-top:2rem;border-bottom:1px solid #eee;padding-bottom:.2rem}
h3{font-size:1.05rem;margin-top:1.4rem}
code{background:#f4f4f4;padding:.1em .3em;border-radius:3px;font:12px SFMono-Regular,Consolas,monospace}
blockquote{border-left:3px solid #cbd5e1;margin:.4rem 0;padding:.2rem .8rem;color:#334155;background:#f8fafc}
table.t{border-collapse:collapse;margin:.5rem 0}table.t td{border:1px solid #e2e8f0;padding:.25rem .6rem}
ul{margin:.3rem 0}hr{border:none;border-top:1px solid #eee;margin:2rem 0}
@media(prefers-color-scheme:dark){body{background:#1e1e1e;color:#d4d4d4}code{background:#2d2d2d}blockquote{background:#252525;color:#cbd5e1}table.t td{border-color:#3a3a3a}}
</style></head><body>${body.join("\n")}</body></html>`;
}

// ------------------------------------------------------------------- SARIF ----

export function buildSarif(payload: any, review: ReviewFile): any {
  const results: any[] = [];
  const rules = new Map<string, any>();

  const addRule = (id: string, name: string) => {
    if (!rules.has(id)) rules.set(id, { id, name, shortDescription: { text: name } });
  };

  // Confirmed findings → error-level results.
  for (const key of Object.keys(payload.funcs || {})) {
    const f = payload.funcs[key];
    if (f.review?.status !== "finding") continue;
    for (const fl of flowsForSinkFunc(payload, key)) {
      addRule(fl.category, fl.categoryLabel || fl.category);
      results.push({
        ruleId: fl.category,
        level: "error",
        message: { text: `${fl.categoryLabel}: ${fl.sink}() — reviewer-confirmed finding${f.review.note ? `. ${f.review.note}` : ""}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: fl.sinkFile },
            region: { startLine: fl.sinkLine || 1 },
          },
        }],
        properties: { defense: fl.defense, reviewer: f.review.reviewer, taintOrigin: fl.origin || null },
      });
    }
  }

  // Blind spots → note-level results (honest coverage record).
  for (const b of payload.blind_rows || []) {
    addRule("blind_spot", "Static-analysis blind spot");
    results.push({
      ruleId: "blind_spot",
      level: "note",
      message: { text: `Blind spot: ${b.call} — ${b.reason}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: b.file }, region: { startLine: b.line || 1 } } }],
    });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "CodeXray",
          informationUri: "https://github.com/yashwanthgk88/codexray",
          rules: [...rules.values()],
        },
      },
      properties: {
        engagement: review.engagement.name,
        reviewer: review.engagement.reviewer,
        coverage: payload.review?.completeness || null,
      },
      results,
    }],
  };
}

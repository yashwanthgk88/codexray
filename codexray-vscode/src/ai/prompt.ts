/**
 * Builds the security-analysis prompt for a single taint/reachability flow.
 * Provider-neutral: returns a {system, user} pair any chat model can consume.
 */

export interface FlowForPrompt {
  categoryLabel: string;
  category: string;
  sink: string;
  sinkWhy: string;
  sinkFile: string;
  sinkFunc: string;
  sinkLine: number;
  tainted: boolean;
  origin: string | null;
  originLine: number | null;
  via: string[];
  controls: Array<{ label: string; relevant: boolean }>;
  defense: string; // none | weak | guarded | na
  language: string;
  code: string; // the sink function's source
}

export const SYSTEM_PROMPT =
  "You are a senior application-security engineer helping a junior analyst do a MANUAL code review. " +
  "You are given ONE data-flow that a static tool surfaced: an entry point that reaches a dangerous sink, " +
  "sometimes with a taint chain from an untrusted source. Your job is to give a concise, concrete, honest " +
  "assessment of THIS specific code — never a generic lecture. You do not have the whole codebase, so state " +
  "your assumptions and tell the analyst exactly what to check. Do not overclaim: if exploitability depends " +
  "on something you cannot see (sanitization in a caller, framework escaping), say so. Prefer precision over drama.";

export function buildUserPrompt(f: FlowForPrompt): string {
  const lines: string[] = [];
  lines.push(`Language: ${f.language}`);
  lines.push(`Sink category: ${f.categoryLabel} (${f.category}) — ${f.sinkWhy}`);
  lines.push(`Sink call: ${f.sink}() at ${f.sinkFile}:${f.sinkLine}, inside function \`${f.sinkFunc}\`.`);
  if (f.tainted && f.origin) {
    lines.push(
      `Taint chain (found by the tool): untrusted source ${f.origin} at line ${f.originLine}` +
        (f.via.length ? ` flows via ${f.via.join(", ")}` : "") +
        ` into the sink. Treat this as "input may reach the sink" — verify it is not sanitized in between.`
    );
  } else {
    lines.push(
      `No source→sink taint chain was proven — the sink is only known to be REACHABLE from an entry point. ` +
        `Assess whether attacker-controlled input can plausibly influence this sink.`
    );
  }
  if (f.tainted) {
    if (f.controls && f.controls.length) {
      const list = f.controls
        .map((c) => `${c.label} (${c.relevant ? "defends this sink type" : "does NOT defend this sink type"})`)
        .join("; ");
      lines.push(
        `Existing controls found on the path: ${list}. ` +
          `Evaluate whether the relevant control(s) actually cover the whole tainted value, are applied on every path, and can't be bypassed — a control being present is not proof of safety.`
      );
    } else {
      lines.push(`No sanitizer/validator/escaper was found between the source and the sink.`);
    }
  }
  lines.push("");
  lines.push("Function source:");
  lines.push("```" + f.language);
  lines.push(f.code);
  lines.push("```");
  lines.push("");
  lines.push("Give your assessment as short Markdown with these sections, and nothing else:");
  lines.push("- **Verdict** — one line: is this likely exploitable, possibly, or likely safe, and why (name the deciding factor).");
  lines.push("- **How it could be exploited** — a concrete example input/payload for THIS code, or state why it can't be.");
  lines.push("- **What to check** — the exact things the analyst must confirm in the surrounding code (callers, sanitizers, config).");
  lines.push("- **Fix** — the minimal, idiomatic remediation for this language/sink, with a one-line code sketch.");
  lines.push("Keep it tight. This is advisory input to a human reviewer, not a verdict of record.");
  return lines.join("\n");
}

/**
 * Language-adapter contract. Each supported language provides one adapter that
 * turns a parsed tree-sitter tree into the shared FunctionInfo model. Everything
 * downstream (call graph, reachability, coverage ledger, report) is language-agnostic.
 */
import Parser from "web-tree-sitter";
import { FunctionInfo } from "../model";

/** A defensive control — a sanitizer / escaper / validator / cast. */
export interface Sanitizer {
  /** human label, e.g. "escapeshellarg()". */
  label: string;
  /** sink categories this control defends; ["*"] = generic (e.g. an int cast). */
  cats: string[];
}

/** The facts a language surfaces — sinks, taint sources, blind-spot calls, controls. */
export interface Knowledge {
  /** dotted or short call name -> [category, why it matters]. Facts, not severities. */
  sinks: Record<string, [string, string]>;
  /** identifiers that indicate untrusted input reaching the code (taint sources). */
  sources: Set<string>;
  /** call patterns static analysis cannot resolve -> reason to MARK (not hide). */
  blindspots: Record<string, string>;
  /** defensive controls: function/method name -> what it defends. */
  sanitizers?: Record<string, Sanitizer>;
}

export interface LanguageAdapter {
  /** stable id, e.g. 'python' | 'php' | 'java' | 'csharp' | 'kotlin' | 'swift'. */
  id: string;
  /** human label for the report. */
  label: string;
  /** file extensions this adapter claims (lowercase, with dot). */
  extensions: string[];
  /** tree-sitter grammar wasm filename in dist/ (copied by esbuild). */
  wasm: string;
  /** this language's sink/source/blind-spot facts. */
  knowledge: Knowledge;
  /** Extract functions (with calls/sinks/sources/entries) from one parsed file. */
  extract(root: Parser.SyntaxNode, relpath: string): Map<string, FunctionInfo>;
  /**
   * Optional cross-file post-pass, run after every file is extracted — e.g.
   * Python's `if __name__ == '__main__'` entry-point resolution which may point
   * at a function defined in another file.
   */
  postPass?(trees: Parser.Tree[], allFuncs: Map<string, FunctionInfo>): void;
}

/** Union of all sink/source/blind-spot names across the adapters actually used —
 *  lets the call-graph builder treat known externals as "resolved elsewhere". */
export function externalNames(adapters: Iterable<LanguageAdapter>): Set<string> {
  const ok = new Set<string>();
  for (const a of adapters) {
    for (const k of Object.keys(a.knowledge.sinks)) {
      ok.add(k);
      ok.add(k.split(".").pop() as string);
    }
    for (const s of a.knowledge.sources) ok.add(s);
    for (const b of Object.keys(a.knowledge.blindspots)) ok.add(b);
  }
  return ok;
}

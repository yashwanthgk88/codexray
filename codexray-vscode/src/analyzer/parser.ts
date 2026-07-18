import * as path from "path";
import Parser from "web-tree-sitter";
import { adapterById } from "./adapters";

let _initPromise: Promise<void> | null = null;
const _parsers = new Map<string, Parser>();

/** Initialise the tree-sitter runtime once (idempotent). */
function ensureInit(wasmDir: string): Promise<void> {
  if (!_initPromise) {
    _initPromise = Parser.init({
      locateFile: () => path.join(wasmDir, "tree-sitter.wasm"),
    });
  }
  return _initPromise;
}

/**
 * Return a parser per requested language id, lazily loading each grammar's wasm
 * from `wasmDir` (esbuild copies every grammar into dist/). Only the grammars
 * actually needed for the scanned files are loaded.
 */
export async function getParsers(
  wasmDir: string,
  langIds: Iterable<string>
): Promise<Map<string, Parser>> {
  await ensureInit(wasmDir);
  const result = new Map<string, Parser>();
  for (const id of new Set(langIds)) {
    if (!_parsers.has(id)) {
      const adapter = adapterById(id);
      if (!adapter) continue;
      const Lang = await Parser.Language.load(path.join(wasmDir, adapter.wasm));
      const p = new Parser();
      p.setLanguage(Lang);
      _parsers.set(id, p);
    }
    const parser = _parsers.get(id);
    if (parser) result.set(id, parser);
  }
  return result;
}

export type SyntaxNode = Parser.SyntaxNode;

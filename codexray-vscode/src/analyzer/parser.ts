import * as path from "path";
import Parser from "web-tree-sitter";

let _parser: Parser | null = null;
let _initPromise: Promise<Parser> | null = null;

/**
 * Initialise a singleton tree-sitter parser configured for Python.
 * `wasmDir` is the directory holding tree-sitter.wasm + tree-sitter-python.wasm
 * (esbuild copies both into dist/ at build time — see esbuild.js).
 */
export function getParser(wasmDir: string): Promise<Parser> {
  if (_parser) {
    return Promise.resolve(_parser);
  }
  if (_initPromise) {
    return _initPromise;
  }
  _initPromise = (async () => {
    await Parser.init({
      locateFile: () => path.join(wasmDir, "tree-sitter.wasm"),
    });
    const Python = await Parser.Language.load(
      path.join(wasmDir, "tree-sitter-python.wasm")
    );
    const parser = new Parser();
    parser.setLanguage(Python);
    _parser = parser;
    return parser;
  })();
  return _initPromise;
}

export type SyntaxNode = Parser.SyntaxNode;

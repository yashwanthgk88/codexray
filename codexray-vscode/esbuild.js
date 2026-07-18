const esbuild = require("esbuild");
const fs = require("fs");
const path = require("path");

const production = process.argv.includes("--production");
const watch = process.argv.includes("--watch");

const DIST = path.join(__dirname, "dist");

/**
 * web-tree-sitter loads WebAssembly at runtime. When we bundle with esbuild the
 * package's own file-resolution breaks, so we copy the two .wasm files into dist/
 * and load them from there with an explicit absolute path (see analyzer/parser.ts).
 */
function copyWasm() {
  fs.mkdirSync(DIST, { recursive: true });
  // Runtime + one grammar per supported language adapter (see src/analyzer/adapters).
  const targets = [
    ["web-tree-sitter/tree-sitter.wasm", "tree-sitter.wasm"],
    ["tree-sitter-wasms/out/tree-sitter-python.wasm", "tree-sitter-python.wasm"],
    ["tree-sitter-wasms/out/tree-sitter-php.wasm", "tree-sitter-php.wasm"],
    ["tree-sitter-wasms/out/tree-sitter-java.wasm", "tree-sitter-java.wasm"],
    ["tree-sitter-wasms/out/tree-sitter-c_sharp.wasm", "tree-sitter-c_sharp.wasm"],
    ["tree-sitter-wasms/out/tree-sitter-typescript.wasm", "tree-sitter-typescript.wasm"],
  ];
  for (const [from, to] of targets) {
    const src = require.resolve(from);
    fs.copyFileSync(src, path.join(DIST, to));
    console.log("copied", to);
  }
}

async function main() {
  copyWasm();
  const ctx = await esbuild.context({
    entryPoints: ["src/extension.ts"],
    bundle: true,
    format: "cjs",
    platform: "node",
    target: "node18",
    outfile: "dist/extension.js",
    external: ["vscode"],
    sourcemap: !production,
    minify: production,
    logLevel: "info",
  });
  if (watch) {
    await ctx.watch();
  } else {
    await ctx.rebuild();
    await ctx.dispose();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});

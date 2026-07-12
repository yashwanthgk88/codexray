# CodeXray — VS Code extension

A source-code **X-ray** for manual security review of Python, right inside VS Code.
**Not a scanner** — it emits zero vulnerability verdicts. It surfaces *anatomy*
(entry points, flows, sinks, tainted inputs, blind spots) as facts, marks where
static analysis cannot see, and enforces a coverage ledger so no flow is silently
skipped. **The analyst decides.**

This is a native TypeScript port of the CodeXray engine — it parses Python with
[tree-sitter](https://tree-sitter.github.io/) in-process, so **no Python install
is required**.

## Usage

1. Open a folder or workspace containing Python source.
2. Run **CodeXray: X-ray Workspace** from the Command Palette (`Cmd/Ctrl+Shift+P`),
   or right-click any folder in the Explorer → **CodeXray: X-ray This Folder**.
3. An interactive report opens in a panel:
   - **Sidebar** lists every entry point (HTTP routes + `__main__`/CLI).
   - Click an entry point to see its handler's real source, with **sinks** (red),
     **tainted inputs** (amber) and **blind spots** (yellow) highlighted inline.
   - Every resolved call has a **dig →** button — expand the callee's source
     beneath the call site and keep digging. Recursion/cycles are detected.
   - **Coverage ledger** — disposition every function (safe / finding / n-a).
   - **Blind spots** — the calls (`getattr`, `eval`, dynamic import…) the X-ray
     cannot follow, listed explicitly rather than silently skipped.

## What it detects

- **Entry points:** Flask/FastAPI/Django route decorators + `if __name__ == "__main__"` blocks.
- **Sinks:** command exec, code exec, SQL, deserialization, file I/O, SSRF,
  template injection, XSS-ish, response writes.
- **Taint sources:** `request.*`, `sys.argv`, `os.environ`, `input()`, etc.
- **Blind spots:** dynamic dispatch / import / `eval` / `exec`.

## Honest limits (same as the PoC)

- Python source only.
- Call graph resolves by name (intraprocedural, over-approximate); ambiguity and
  misses are tracked and shown, not hidden.
- Highlighting is **presence-based** (source & sink co-occur in a reachable path),
  **not dataflow-proven**. Confirming the input actually reaches the sink argument
  is the analyst's job — by design.

## Development

```bash
npm install
npm run compile        # bundle with esbuild + copy the two .wasm files into dist/
# then press F5 in VS Code to launch the Extension Development Host
npm run vsce:package   # produce codexray-<version>.vsix
```

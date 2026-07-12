# CodeXray — session log (2026-07-12)

A record of the work done turning the CodeXray PoC into a VS Code extension.

## Starting point

The project (developed in the web Claude version) contained:
- `xray.py` — the AST-based analyzer engine (Python `ast`).
- `report_interactive.py` — interactive drill-down HTML report generator.
- `codexray_interactive.html` — a generated report artifact.
- `README.md`.

The README referenced `report.py` and `sample_app/` which were **missing** from
the downloaded folder.

## What we built

Turned CodeXray into a **native VS Code extension** — a full **TypeScript port**
of `xray.py` (chosen over wrapping Python), packaged as an installable `.vsix`.

New project: [`codexray-vscode/`](codexray-vscode/)

| File | Role |
|---|---|
| `src/analyzer/analyze.ts` | Port of `xray.py` — entry points, sinks, taint sources, blind spots, call graph, reachability, ledger |
| `src/analyzer/knowledge.ts` | SINKS / SOURCE_HINTS / BLINDSPOT_CALLS / ROUTE_DECORATORS (verbatim) |
| `src/analyzer/model.ts` | `FunctionInfo` + `Model` types |
| `src/analyzer/parser.ts` | tree-sitter Python parser (WASM), singleton init |
| `src/analyzer/payload.ts` | Port of `build_payload` → JSON the report consumes |
| `src/extension.ts` | Commands, file collection, webview, output channel |
| `media/report.html` | The interactive report, reused verbatim (with `__PAYLOAD__` placeholder) |
| `esbuild.js` | Bundles + copies the two `.wasm` files into `dist/` |

### Key technical decisions
- **Parser:** `web-tree-sitter` (0.22.6) + prebuilt `tree-sitter-python.wasm` from
  the `tree-sitter-wasms` package. No Python dependency at runtime, no native build.
- **WASM loading:** esbuild copies `tree-sitter.wasm` + `tree-sitter-python.wasm`
  into `dist/`; `parser.ts` loads them with an explicit `locateFile` path
  (`context.extensionPath/dist`).
- **Report:** shipped as a static `media/report.html`; the extension reads it,
  replaces `__PAYLOAD__` with `JSON.stringify(payload)` (with `<` → `<` to
  avoid `</script>` breakage), and sets it as the webview HTML.
- **Faithful-port nuances:** decorator calls are NOT treated as in-body calls
  (cleaner than the Python original); attribute-name / keyword-name identifiers
  are excluded from taint-source detection to avoid double counting.

### Verification
- `tsc --noEmit` clean.
- **Parity with the Python engine** on `sample_app`: files, functions, entry
  points (5), sinks (5), blindspots (1), ambiguous, parse_errors all match.
  Only `unresolved_calls` differed (6 vs 11) — traced exactly to the 5
  `@app.route` decorator calls the port intentionally ignores.
- **End-to-end** run of `analyzeWorkspace` (stubbed `vscode`): real WASM load,
  full analysis, webview HTML rendered, placeholder replaced.

Also **recreated the missing `sample_app/app.py`** — a deliberately messy Flask
target (command-exec, SQLi, path traversal, SSTI, pickle, `getattr` blind spot).

## GitHub

Pushed to **https://github.com/yashwanthgk88/codexray** (public, `main`).
`.gitignore` excludes `node_modules/`, `dist/`, `*.vsix`, `__pycache__`.

## The install issue (and fix)

**Symptom:** installed the extension, "nothing happened" — no panel, no error.

**Diagnosis (from VS Code logs):** the extension was correctly installed and
registered (`codexray.codexray` in `~/.vscode/extensions/extensions.json`) but had
**never activated** — classic case of installing into an already-running window
that was never fully reloaded. (Editor: real VS Code, running translocated from
Downloads; extensions dir `~/.vscode/extensions`.)

**Fix — v0.1.1:**
- Explicit `onCommand:` activation events; engine floor lowered to `^1.75.0`
  (and `@types/vscode` pinned to `1.75.1` so vsce packages).
- Command handlers wrapped so any failure shows a notification **and** logs to a
  new **"CodeXray" output channel** — no more silent failures.
- Per-step logging (scan → parser init → analyze → render).
- Hand-installed v0.1.1 into `~/.vscode/extensions/codexray.codexray-0.1.1`,
  updated the registry, removed 0.1.0. Copy also in `~/Downloads/`.

**Action required by user:** fully quit + reopen VS Code (Cmd+Q, or Developer:
Reload Window), open a folder with Python, then run **CodeXray: X-ray Workspace**.
If it still fails, check View → Output → "CodeXray".

## Build / dev commands (in `codexray-vscode/`)
```bash
npm install
npm run compile        # esbuild bundle + copy wasm into dist/
npm run vsce:package   # produce codexray-<version>.vsix
# F5 in VS Code launches the Extension Development Host
```

## Possible next steps
- CI (GitHub Actions) to build the `.vsix` and attach to releases.
- Publish to the VS Code Marketplace (`vsce publish`).
- Editor integration: click a function in the report to jump to source.
- Extend the engine: more frameworks / sinks, or real dataflow.

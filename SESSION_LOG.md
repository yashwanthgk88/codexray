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

## v0.2.0 — multi-language architecture + PHP + taint visualization (2026-07-13)

Goal: support more languages (starting PHP, for DVWA) and a taint-flow view a
junior analyst can follow.

**Language-adapter architecture.** Split the engine into a language-agnostic core
and per-language adapters:
- `analyzer/analyze.ts` — now core only: call graph, reachability, coverage ledger.
  Dispatches each file to its adapter, unions the knowledge bases.
- `analyzer/adapters/types.ts` — `LanguageAdapter` + `Knowledge` contract.
- `analyzer/adapters/{python,php}.ts` — per-language tree walkers. Python is the
  original xray.py logic moved behind the contract (with its `__main__` post-pass).
- `analyzer/knowledge/{python,php}.ts` — per-language sinks/sources/blind spots.
- `analyzer/adapters/index.ts` — registry (extension → adapter); one place to add
  a language.
- `analyzer/parser.ts` — multi-grammar registry, lazy-loads only the grammars the
  scanned files need. All grammars already ship in `tree-sitter-wasms`.

**PHP adapter.** Models each `.php` file's top-level as a synthetic `<main>`
web-reachable entry, plus real functions/methods. Node types verified empirically
via `scratch/probe-php.js`. Gotcha fixed: `variable_name`'s identifier is a child
of type `name`, NOT a field (`variableIdent()` helper).

**Intra-function taint** (PHP): tracks `$var = <source>` assignments and flags a
sink when a tainted var / superglobal reaches its arguments → records
`origin → via[] → sink` chains (`FunctionInfo.taint`).

**Visualization overhaul** (`media/report.html`, rewritten): VS Code-theme-aware
two-pane webview. Left = ranked flow list (tainted first, then by category),
filter by category / search / tainted-only. Right = a source→sink "ladder" with
code at each step + the sink function's code with source/sink lines highlighted.
Click any location → opens the file at that line (new `onDidReceiveMessage`
handler in `extension.ts`).

**Verified on DVWA:** 170 files (169 PHP + 1 py), 352 sinks, **453 flows, 70
proven taint chains**. Signature vulns land correctly, e.g. exec/high.php:
`$_REQUEST['ip']` → `$target` → `shell_exec()`.

Packaged + hand-installed **codexray-0.2.0.vsix**; registry points at
`codexray.codexray-0.2.0`, 0.1.x removed. Requires a VS Code reload to activate.

## v0.3.0 — AI-agnostic flow insights (2026-07-13)

Added an **"Explain with AI"** button on every flow. It sends the source→sink
chain + the sink function's code to a configured model and renders the model's
security assessment (verdict / how it could be exploited / what to check / fix).

**Provider-agnostic by design** — raw HTTP, no bundled SDK. Four first-class
providers in `src/ai/provider.ts` (v0.3.2), each with the correct URL + auth
(verified via scratch/test-providers.ts):
- `anthropic` → `POST {base}/v1/messages`, `x-api-key` (Claude; default `claude-opus-4-8`)
- `openai` → `POST {base}/chat/completions`, `Bearer` (OpenAI, OpenRouter, LM Studio, vLLM)
- `azure` → `POST {base}/openai/deployments/{model}/chat/completions?api-version=..`, `api-key`
- `ollama` → `POST {base}/chat/completions`, no key (local, default :11434)

Config via VS Code settings (`codexray.ai.provider|model|baseUrl|maxTokens`); API
key in SecretStorage via the **CodeXray: Set AI API Key** command (falls back to
`ANTHROPIC_API_KEY` / `OPENAI_API_KEY`). Prompt lives in `src/ai/prompt.ts`
(framed as advisory input to a human reviewer — the analyst still decides). The
webview posts `explain`, the extension host makes the call (not the webview, so
no CSP/network issue), and posts the insight back; rendered with a small safe
Markdown converter. Packaged + installed **codexray-0.3.0.vsix**.

## v0.4.0 — existing-controls / defense evaluation (2026-07-13)

CodeXray now recognises **existing defenses** and evaluates residual risk, not
just "there is a sink". A `sanitizers` map was added to the Knowledge contract
(`adapters/types.ts`) and populated for PHP (`knowledge/php.ts`): escapers
(`escapeshellarg`, `htmlspecialchars`, `mysqli_real_escape_string`, …), path
guards (`basename`, `realpath`), and generic validators/casts (`intval`,
`filter_var`, `is_numeric`, `(int)` cast, …), each tagged with the sink
categories it actually defends (`["*"]` = generic).

The PHP taint engine now carries controls: `$safe = escapeshellarg($t)`
propagates the control onto `$safe`; at the sink, controls from the carrier
variable + the sink expression are recorded on the `TaintFinding`, each marked
**relevant** iff it defends that sink's category. Crucially this is *smart* —
`htmlspecialchars()` on a shell-command sink is flagged **✗ not-relevant**, while
`escapeshellarg()` is **✓ relevant** (verified in scratch/check-synth.ts).

Payload derives a **defense level** per flow — `none` / `weak` (control present
but wrong category) / `guarded` (relevant control) — and ranks **undefended
flows first**. Report UI shows a defense badge, an "Existing controls" line with
✓/✗ chips, defense-aware "What to do" guidance, an **Undefended only** filter,
and an **undefended** stat. The AI prompt includes the controls so the model
evaluates whether they truly cover the value. On DVWA: 70 tainted → 46
undefended, 4 weak, 20 guarded. Packaged + installed **codexray-0.4.0.vsix**.

## v0.5.0 — complete Inventory view (2026-07-17)

Added an **Inventory** tab: the full attack surface, listing EVERY entry point,
sink, and source found — reachable or not, tainted or not — as browsable,
filterable tables (clickable to source). Complements the risk-ranked Taint Flows
tab. `buildInventory()` in payload.ts derives per-sink `reachable` (from the
coverage buckets) and `tainted`/`controls` (from taint findings); a live text
filter narrows all three tables. Key win: sinks NOT reachable from a recognized
entry point (8 on DVWA) never appear as flows but DO appear here — nothing hidden.
On DVWA: 169 entries, 352 sinks (344 reachable / 8 unreached / 67 tainted), 333
sources. Packaged + installed **codexray-0.5.0.vsix**.

## Possible next steps
- Java, C# (ASP.NET), Kotlin/Swift (mobile) adapters — grammars already bundled;
  each is one adapter + one knowledge file (incl. its own sanitizers), no core changes.
- Precise control scoping (does the sanitizer wrap THIS value vs a sibling);
  detect prepared statements (bind_param) as a strong SQL control.
- Stream AI insights token-by-token; "explain all undefended flows" batch.
- Cross-function taint (propagate through call args/returns, not just intra-function).
- Python taint (the taint pass is currently PHP-only).
- CI (GitHub Actions) to build the `.vsix`; publish to Marketplace.

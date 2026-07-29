# CodeXray — VS Code extension

A source-code **X-ray** for manual security review of **Python, PHP, Java, C#/.NET
and TypeScript**, right inside VS Code. **Not a scanner** — it emits zero
vulnerability verdicts. It surfaces *anatomy* (entry points, flows, sinks, tainted
inputs, blind spots) as facts, marks where static analysis cannot see, and enforces
a coverage ledger so no flow is silently skipped. **The analyst decides.**

It parses every language with [tree-sitter](https://tree-sitter.github.io/)
in-process (WebAssembly grammars), so **no language toolchain is required** — no
Python, PHP, JDK, .NET SDK or Node install needed to analyse those sources.

## Usage

1. Open a folder or workspace containing source in a supported language.
2. Run **CodeXray: X-ray Workspace** from the Command Palette (`Cmd/Ctrl+Shift+P`),
   or right-click any folder in the Explorer → **CodeXray: X-ray This Folder**.
3. An interactive report opens in a panel:
   - **Sidebar** lists every entry point (HTTP routes + `__main__`/CLI/`Main`).
   - Click an entry point to see its handler's real source, with **sinks** (red),
     **tainted inputs** (amber) and **blind spots** (yellow) highlighted inline.
   - Every resolved call has a **dig →** button — expand the callee's source
     beneath the call site and keep digging. Recursion/cycles are detected.
   - **Coverage ledger** — disposition every function (safe / finding / n-a).
   - **Blind spots** — the calls (`eval`, reflection, dynamic import…) the X-ray
     cannot follow, listed explicitly rather than silently skipped.

## The review instrument

CodeXray is not just a viewer — it **records the review**. State lives in
`.codexray/review.json`, committed to your repo, so reviews are diffable, PR-able,
and travel with the code (review-as-code).

- **Disposition every function** — `unreviewed → in progress → safe / finding /
  needs-info / false-positive`, with a reviewer note. Set it from the Coverage
  Ledger or the flow detail pane, or by keyboard (`s` safe, `f` finding, `i`
  needs-info, `p` false-positive; `j`/`k` to move; `e` to export).
- **Completeness meter** — the header shows `reviewed / total` and a progress bar,
  so "did we look at everything?" has a real answer.
- **Staleness (re-review)** — each disposition stores a hash of the function body.
  When the code changes, that disposition is flagged **⚠ stale** and the export
  lists it — a one-shot scan becomes an ongoing review relationship with the code.
- **Auditable export** — **CodeXray: Export Review Report** writes
  `review-report.md` (git/PR), `.html` (self-contained, client-facing) and
  `.sarif.json` (tooling) into `.codexray/`. The deliverable states the three
  things scanners don't: what was reviewed, **what was explicitly not** (blind
  spots + un-reviewed sink-bearing functions), and by whom.
- **Multi-reviewer** — **CodeXray: Merge Another Reviewer's Review** merges a
  second `review.json`; the more recent disposition per function wins, attribution
  preserved. Set your name via `codexray.review.reviewer` (defaults to OS user).

## Supported languages

| Language | Extensions | Entry points | Taint chains |
|---|---|---|---|
| Python | `.py` | Flask/FastAPI decorators, `__main__` | **yes** — `request.*`, `sys.argv`, `input()` |
| PHP | `.php` `.phtml` `.inc` … | every script top-level, functions/methods | **yes** — source→var→sink |
| Java | `.java` | `@GetMapping`/`@Path`/…, `main` | **yes** — `@RequestParam`, `request.getParameter` |
| C# / .NET | `.cs` | `[HttpGet]`/`[Route]`/…, `Main` | **yes** — `Request.Query`, `[FromQuery]` |
| TypeScript / JS | `.ts` `.mts` `.js` `.mjs` … | Express/Koa routes (`app.get(…)`) | **yes** — `req.query`, incl. destructuring |

All five languages build full source→variable→sink taint chains with defense
grading through the shared engine.

## What it detects

- **Entry points:** framework routes per language + program `main`/`__main__`.
- **Sinks:** command exec, code exec / reflection, SQL, deserialization, file I/O,
  SSRF, template injection, XSS / response writes, header injection.
- **Taint sources:** request objects/params, environment, CLI args — per language.
- **Defense grading** (taint-chain languages): `none` (undefended — real residual
  risk), `weak` (a control is present but defends the *wrong* sink category),
  `guarded` (a category-relevant control is present — still verify it covers the
  whole value), `n/a`.
- **Blind spots:** dynamic dispatch / reflection / dynamic import / `eval`.

## Architecture

A **language-agnostic core** (call graph, reachability, coverage ledger) plus one
`LanguageAdapter` per language (`src/analyzer/adapters/`). Taint propagation is a
single shared engine (`src/analyzer/taint.ts`) parameterised by a small
per-language `TaintProfile`, so every language inherits the same
source→variable→sink propagation, control collection and category resolution.
Adding a language = knowledge file + adapter + one registry line + one esbuild
wasm-copy line. See `src/analyzer/adapters/types.ts` for the contract.

## Honest limits

- **Taint is intra-function.** A tainted value passed into another function is
  tracked for *reachability* but not carried as taint across the call boundary.
- **Python route/query params are not auto-seeded.** Python taint enters through
  `request.*` / `sys.argv` / `input()` access; a FastAPI handler that takes a
  bare `q: str` query param (no `request.` access) is seen as reachable, not
  tainted. Flask/Django `request.args.get(...)` is fully tracked.
- **Call graph resolves by short name** (over-approximate); ambiguity and misses
  are counted (`ambiguous_calls`, `unresolved_calls`) and shown, not hidden.
- **Controls are over-approximate** — a `guarded` grade means a relevant control
  was *seen in the expression*, not proven to cover the tainted value. Verify it.
- Highlighting is **presence-based**, **not dataflow-proven**. Confirming the
  input actually reaches the sink argument is the analyst's job — by design.
- `.tsx`/`.jsx` are not parsed (the plain `typescript` grammar has no JSX);
  a `tsx` adapter would add the separate grammar.

## Development

```bash
npm install
npm run compile        # bundle with esbuild + copy the language .wasm files into dist/
# then press F5 in VS Code to launch the Extension Development Host
npm run vsce:package   # produce codexray-<version>.vsix
```

Verify the analyzers against fixtures (no VS Code needed):

```bash
npx ts-node scratch/verify-langs.ts      # Java / C# / TypeScript taint assertions
npx ts-node scratch/check-payload.ts     # PHP/Python against a real app (edit the root path)
```

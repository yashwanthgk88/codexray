# CodeXray PoC

A source-code X-ray for manual security review. **Not a scanner** - emits zero
vulnerability verdicts. It exposes anatomy (entry points, flows, sinks, controls,
real source) as facts, marks where static analysis cannot see, and enforces a
coverage ledger so no flow is silently skipped. The analyst decides.

## Two report views

**Interactive drill-down explorer** (the main deliverable):
```bash
python3 report_interactive.py <repo> report.html
```
- Sidebar lists every entry point (HTTP + non-HTTP/CLI).
- Click an entry point -> see its handler's real source, with sinks (red),
  tainted inputs (amber) and blind spots (yellow) highlighted inline.
- Every function call has a **dig ->** button: click it to expand that callee's
  real source directly beneath the call site, and keep digging deeper.
- "Expand every reachable path" renders the full call tree at once.
- Recursion / cycles are detected and marked, never infinitely expanded.
- Jump to the **coverage ledger** (disposition every function) or **blind spots**.

**Flat tabular report** (quick overview / printable):
```bash
python3 report.py <repo> report.html
```

Example target (bundled deliberately-messy app):
```bash
python3 report_interactive.py sample_app report.html
```

## PoC scope / honest limits
- Python source only; entry points: Flask/FastAPI/Django decorators + `__main__`.
- Call graph resolves by name (intraprocedural, over-approximate); ambiguity and
  misses are tracked and shown, not hidden.
- Highlighting is presence-based (source & sink co-occur in a reachable path),
  NOT dataflow-proven. Confirming the input actually reaches the sink argument is
  the analyst's job - by design.
- No config/IaC/server analysis (scope = "100% of what the source can tell us").

## Files
- `xray.py` - analyzer engine (ast -> entry points, sinks, call graph, reachability, ledger, source capture)
- `report_interactive.py` - interactive drill-down explorer (recommended)
- `report.py` - flat tabular report
- `sample_app/app.py` - deliberately messy demo target

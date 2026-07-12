#!/usr/bin/env python3
"""
CodeXray - a source-code X-ray for manual security review.

PHILOSOPHY (read this before judging the output):
  This is NOT a scanner. It emits ZERO vulnerability verdicts.
  It emits ANATOMY + a COVERAGE LEDGER:
    - every entry point that exists in the source
    - every dangerous sink that exists in the source
    - which entry points can reach which sinks (with a witness path)
    - a disposition bucket for every function so nothing is silently skipped
    - explicitly MARKED blind spots where static analysis cannot see
  The human analyst decides what is and isn't a vulnerability.

PoC scope: Python source, targeting Flask / FastAPI / Django / CLI entry points.
Uses only the standard library (ast) so it runs anywhere with no install.
"""

import ast
import os
import sys
import json
from collections import defaultdict


# ---------------------------------------------------------------------------
# Knowledge base: what counts as an entry point / sink / blind spot.
# These are FACTS to surface, not judgments. Kept small & explicit for the PoC.
# ---------------------------------------------------------------------------

# Decorators that mark HTTP route entry points, by framework.
ROUTE_DECORATORS = {
    "route", "get", "post", "put", "delete", "patch",  # flask / fastapi
    "api_route", "websocket",
}

# Full dotted sink names -> (category, why it matters). Facts, not severities.
SINKS = {
    "os.system":            ("command_exec", "runs a shell command"),
    "os.popen":             ("command_exec", "runs a shell command"),
    "subprocess.call":      ("command_exec", "spawns a process"),
    "subprocess.run":       ("command_exec", "spawns a process"),
    "subprocess.Popen":     ("command_exec", "spawns a process"),
    "subprocess.check_output": ("command_exec", "spawns a process"),
    "eval":                 ("code_exec", "evaluates a string as code"),
    "exec":                 ("code_exec", "executes a string as code"),
    "pickle.load":          ("deserialization", "deserializes untrusted data"),
    "pickle.loads":         ("deserialization", "deserializes untrusted data"),
    "yaml.load":            ("deserialization", "deserializes untrusted data"),
    "cursor.execute":       ("sql", "executes a SQL statement"),
    "execute":              ("sql", "executes a SQL statement (db cursor)"),
    "executemany":          ("sql", "executes SQL statements"),
    "open":                 ("file_io", "opens a file path"),
    "send_file":            ("file_io", "returns a file to the client"),
    "render_template_string": ("template_injection", "renders a template from a string"),
    "Markup":               ("xss", "marks a string as safe HTML"),
    "make_response":        ("response_write", "writes an HTTP response"),
    "requests.get":         ("ssrf", "makes an outbound HTTP request"),
    "requests.post":        ("ssrf", "makes an outbound HTTP request"),
    "urllib.request.urlopen": ("ssrf", "makes an outbound HTTP request"),
}

# Names that indicate untrusted input reaching the code (taint sources).
SOURCE_HINTS = {
    "request",       # flask/django request object
    "args",          # request.args
    "form",          # request.form
    "json",          # request.json / get_json
    "get_json",
    "values",
    "cookies",
    "headers",
    "params",
    "query_params",
    "input",         # builtin input()
    "argv",          # sys.argv
    "environ",       # os.environ
}

# Call patterns we cannot statically resolve -> blind spots to MARK, not hide.
BLINDSPOT_CALLS = {
    "getattr":  "dynamic attribute / method dispatch",
    "setattr":  "dynamic attribute assignment",
    "__import__": "dynamic import",
    "importlib.import_module": "dynamic import",
    "globals":  "runtime symbol table access",
    "locals":   "runtime symbol table access",
    "eval":     "runtime code construction",
    "exec":     "runtime code construction",
}


def dotted_name(node):
    """Best-effort resolve a call target to a dotted string (os.system, cursor.execute)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        if base:
            return f"{base}.{node.attr}"
        return node.attr
    return None


class FunctionInfo:
    __slots__ = ("qualname", "file", "lineno", "endlineno", "calls",
                 "sinks", "sources", "blindspots", "is_entry", "entry_kind",
                 "entry_meta", "params")

    def __init__(self, qualname, file, lineno, endlineno):
        self.qualname = qualname
        self.file = file
        self.lineno = lineno
        self.endlineno = endlineno
        self.calls = []          # list of (callee_short, callee_dotted, lineno)
        self.sinks = []          # list of (dotted, category, why, lineno)
        self.sources = []        # list of (name, lineno)
        self.blindspots = []     # list of (dotted, reason, lineno)
        self.is_entry = False
        self.entry_kind = None   # 'http' | 'cli' | 'task' | 'main'
        self.entry_meta = {}     # {method, path, decorator}
        self.params = []


class ModuleVisitor(ast.NodeVisitor):
    """Walk one module, collecting functions and their facts."""

    def __init__(self, filepath, relpath):
        self.filepath = filepath
        self.relpath = relpath
        self.functions = {}       # qualname -> FunctionInfo
        self._scope = []          # qualname stack
        self._func_stack = []     # FunctionInfo stack

    def _qual(self, name):
        return ".".join(self._scope + [name]) if self._scope else name

    def visit_ClassDef(self, node):
        self._scope.append(node.name)
        self.generic_visit(node)
        self._scope.pop()

    def _handle_function(self, node):
        qual = self._qual(node.name)
        end = getattr(node, "end_lineno", node.lineno)
        fi = FunctionInfo(qual, self.relpath, node.lineno, end)
        fi.params = [a.arg for a in node.args.args]

        # entry-point detection via decorators
        for dec in node.decorator_list:
            target = dec
            if isinstance(dec, ast.Call):
                target = dec.func
            dn = dotted_name(target)
            if not dn:
                continue
            leaf = dn.split(".")[-1]
            if leaf in ROUTE_DECORATORS:
                fi.is_entry = True
                fi.entry_kind = "http"
                method = leaf.upper() if leaf in {"get", "post", "put", "delete", "patch"} else "ANY"
                path = None
                if isinstance(dec, ast.Call) and dec.args:
                    first = dec.args[0]
                    if isinstance(first, ast.Constant):
                        path = first.value
                    # flask: methods=[...] kwarg
                    for kw in dec.keywords:
                        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                            ms = [e.value for e in kw.value.elts if isinstance(e, ast.Constant)]
                            if ms:
                                method = "/".join(ms)
                fi.entry_meta = {"method": method, "path": path or "?", "decorator": dn}

        self.functions[qual] = fi
        self._scope.append(node.name)
        self._func_stack.append(fi)
        self.generic_visit(node)
        self._func_stack.pop()
        self._scope.pop()

    visit_FunctionDef = _handle_function
    visit_AsyncFunctionDef = _handle_function

    def visit_Call(self, node):
        if self._func_stack:
            fi = self._func_stack[-1]
            dn = dotted_name(node.func)
            if dn:
                short = dn.split(".")[-1]
                fi.calls.append((short, dn, node.lineno))
                # sink?
                if dn in SINKS:
                    cat, why = SINKS[dn]
                    fi.sinks.append((dn, cat, why, node.lineno))
                elif short in SINKS:
                    cat, why = SINKS[short]
                    fi.sinks.append((short, cat, why, node.lineno))
                # blind spot?
                if dn in BLINDSPOT_CALLS:
                    fi.blindspots.append((dn, BLINDSPOT_CALLS[dn], node.lineno))
                elif short in BLINDSPOT_CALLS:
                    fi.blindspots.append((short, BLINDSPOT_CALLS[short], node.lineno))
        self.generic_visit(node)

    def visit_Attribute(self, node):
        # detect taint sources like request.args, sys.argv
        if self._func_stack:
            fi = self._func_stack[-1]
            if node.attr in SOURCE_HINTS or (isinstance(node.value, ast.Name) and node.value.id in SOURCE_HINTS):
                nm = node.attr if node.attr in SOURCE_HINTS else node.value.id
                fi.sources.append((nm, node.lineno))
        self.generic_visit(node)

    def visit_Name(self, node):
        if self._func_stack and node.id in SOURCE_HINTS:
            self._func_stack[-1].sources.append((node.id, node.lineno))
        self.generic_visit(node)


def analyze_repo(root):
    """Parse every .py file, build the global function table + call graph."""
    all_funcs = {}          # qualname -> FunctionInfo
    files_scanned = []
    parse_errors = []
    file_sources = {}       # relpath -> list of source lines
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       {".git", "__pycache__", "node_modules", ".venv", "venv", "env"}]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            files_scanned.append(rel)
            try:
                src = open(full, encoding="utf-8").read()
                tree = ast.parse(src, filename=rel)
            except (SyntaxError, UnicodeDecodeError) as e:
                parse_errors.append((rel, str(e)))
                continue
            file_sources[rel] = src.split("\n")
            v = ModuleVisitor(full, rel)
            v.visit(tree)
            for q, fi in v.functions.items():
                # namespace collisions across files: prefix with file stem
                key = f"{rel}::{q}"
                fi.qualname = q
                all_funcs[key] = fi
    return all_funcs, files_scanned, parse_errors, file_sources


def detect_main_entrypoints(root, all_funcs):
    """Find functions invoked from `if __name__ == '__main__':` blocks and mark
    them as CLI/script entry points. Testers routinely forget these exist."""
    by_short = defaultdict(list)
    for key, fi in all_funcs.items():
        by_short[fi.qualname.split(".")[-1]].append(key)

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in
                       {".git", "__pycache__", "node_modules", ".venv", "venv", "env"}]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root)
            try:
                tree = ast.parse(open(full, encoding="utf-8").read(), filename=rel)
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.If):
                    test = node.test
                    is_main = (isinstance(test, ast.Compare)
                               and isinstance(test.left, ast.Name)
                               and test.left.id == "__name__")
                    if not is_main:
                        continue
                    for call in ast.walk(node):
                        if isinstance(call, ast.Call):
                            dn = dotted_name(call.func)
                            if not dn:
                                continue
                            short = dn.split(".")[-1]
                            for cand in by_short.get(short, []):
                                fi = all_funcs[cand]
                                if not fi.is_entry:
                                    fi.is_entry = True
                                    fi.entry_kind = "cli"
                                    fi.entry_meta = {"method": "CLI", "path": f"__main__ -> {short}()",
                                                     "decorator": "__main__ block"}


def build_call_graph(all_funcs):
    """
    Resolve each call to a known function by short name (best-effort, intraprocedural
    name match). Ambiguity and misses are TRACKED, not hidden - that's the point.
    """
    # index functions by their short (leaf) name
    by_short = defaultdict(list)
    for key, fi in all_funcs.items():
        short = fi.qualname.split(".")[-1]
        by_short[short].append(key)

    edges = defaultdict(set)       # caller_key -> set(callee_key)
    unresolved = defaultdict(list) # caller_key -> list of (call_short, lineno) we couldn't map
    ambiguous = defaultdict(list)  # caller_key -> list of (call_short, [candidates], lineno)

    known_short = set(by_short.keys())
    # calls to library/builtin things we don't need to resolve (reduce noise)
    external_ok = set(SINKS.keys()) | {s.split(".")[-1] for s in SINKS} | set(SOURCE_HINTS) | set(BLINDSPOT_CALLS)

    for key, fi in all_funcs.items():
        for short, dotted, lineno in fi.calls:
            candidates = by_short.get(short, [])
            if len(candidates) == 1:
                edges[key].add(candidates[0])
            elif len(candidates) > 1:
                # keep all candidates as edges (over-approximate) but flag ambiguity
                for c in candidates:
                    edges[key].add(c)
                ambiguous[key].append((short, candidates, lineno))
            else:
                # not one of our functions. Only flag as unresolved if it's not
                # obviously a library/builtin/known sink/source.
                if short not in external_ok and dotted not in external_ok:
                    unresolved[key].append((short, dotted, lineno))
    return edges, unresolved, ambiguous, by_short


def reachability(all_funcs, edges):
    """From each entry point, BFS the call graph; record reachable functions
    and any sinks encountered, with a witness path."""
    entries = [k for k, fi in all_funcs.items() if fi.is_entry]
    reachable_from = {}          # entry_key -> set(reachable func keys)
    entry_sinks = defaultdict(list)  # entry_key -> list of (sink_func_key, sink_tuple, path)

    for ekey in entries:
        seen = {ekey}
        parent = {ekey: None}
        stack = [ekey]
        while stack:
            cur = stack.pop()
            for nxt in edges.get(cur, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    parent[nxt] = cur
                    stack.append(nxt)
        reachable_from[ekey] = seen
        # collect sinks in any reachable function
        for fkey in seen:
            fi = all_funcs[fkey]
            if fi.sinks:
                # reconstruct witness path
                path = []
                node = fkey
                while node is not None:
                    path.append(node)
                    node = parent[node]
                path.reverse()
                for sink in fi.sinks:
                    entry_sinks[ekey].append((fkey, sink, path))

    # which functions are reachable from ANY entry point
    globally_reachable = set()
    for s in reachable_from.values():
        globally_reachable |= s
    return entries, reachable_from, entry_sinks, globally_reachable


def disposition(all_funcs, globally_reachable):
    """Assign every function exactly one ledger bucket. Nothing is silently skipped."""
    buckets = {
        "entry_point": [],
        "reachable_with_sink": [],
        "reachable_no_sink": [],
        "not_reachable_from_entry": [],
    }
    for key, fi in all_funcs.items():
        if fi.is_entry:
            buckets["entry_point"].append(key)
        elif key in globally_reachable and fi.sinks:
            buckets["reachable_with_sink"].append(key)
        elif key in globally_reachable:
            buckets["reachable_no_sink"].append(key)
        else:
            buckets["not_reachable_from_entry"].append(key)
    return buckets


def build_model(root):
    all_funcs, files, parse_errors, file_sources = analyze_repo(root)
    detect_main_entrypoints(root, all_funcs)
    edges, unresolved, ambiguous, by_short = build_call_graph(all_funcs)
    entries, reachable_from, entry_sinks, globally_reachable = reachability(all_funcs, edges)
    buckets = disposition(all_funcs, globally_reachable)

    total_blindspots = sum(len(fi.blindspots) for fi in all_funcs.values())
    total_unresolved = sum(len(v) for v in unresolved.values())
    total_ambiguous = sum(len(v) for v in ambiguous.values())

    return {
        "root": os.path.abspath(root),
        "funcs": all_funcs,
        "edges": edges,
        "file_sources": file_sources,
        "unresolved": unresolved,
        "ambiguous": ambiguous,
        "entries": entries,
        "reachable_from": reachable_from,
        "entry_sinks": entry_sinks,
        "buckets": buckets,
        "files": files,
        "parse_errors": parse_errors,
        "stats": {
            "files": len(files),
            "functions": len(all_funcs),
            "entry_points": len(entries),
            "sinks": sum(len(fi.sinks) for fi in all_funcs.values()),
            "blindspots": total_blindspots,
            "unresolved_calls": total_unresolved,
            "ambiguous_calls": total_ambiguous,
            "parse_errors": len(parse_errors),
        },
    }


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "."
    model = build_model(root)
    print(json.dumps(model["stats"], indent=2))

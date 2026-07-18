/**
 * Shared, grammar-parameterised taint engine.
 *
 * Every language adapter walks its own tree-sitter tree (grammar-specific), but
 * the taint MECHANICS — per-function environment, source→variable→sink
 * propagation, control (sanitizer) collection, category resolution and
 * TaintFinding construction — are identical across languages and live here.
 *
 * An adapter supplies a small `TaintProfile` describing how to recognise the
 * handful of node shapes that matter (variable references, direct sources,
 * calls, casts), then drives the tracker from inside its walk:
 *
 *     const tracker = new TaintTracker(profile);
 *     tracker.enter();                              // function scope
 *     tracker.seedParam("id");                      // a request-bound parameter
 *     ...on assignment:  tracker.assign(name, rhsNode, augmented);
 *     ...on a sink call: tracker.recordSink(fi, name, cat, why, line, argsNode);
 *     tracker.exit();
 *
 * This is the same algorithm the PHP adapter shipped with (verified against
 * DVWA); it was lifted here verbatim so the three new adapters inherit it
 * instead of each re-implementing — and mis-implementing — taint.
 */
import Parser from "web-tree-sitter";
import { FunctionInfo, Control } from "./model";

type Node = Parser.SyntaxNode;

/** A raw control reference carried through propagation (category resolved later). */
export interface CtrlRef {
  label: string;
  cats: string[]; // sink categories this control defends; ["*"] = generic
}

/** An untrusted value discovered in an expression subtree. */
export interface TaintValue {
  origin: string; // e.g. "$_REQUEST", "req.query", "getParameter()"
  line: number;
  via: string[]; // carrier variables the value flowed through
  controls: CtrlRef[]; // controls already applied on the way here
}

/** Everything grammar-specific the tracker needs, supplied by each adapter. */
export interface TaintProfile {
  /** Identifier of a variable-reference node, else null (e.g. `$id` -> "id"). */
  varName(node: Node): string | null;
  /**
   * If this node is a DIRECT untrusted source, its display label — else null.
   * Superglobal (`$_GET`), request member (`req.query`) or request accessor
   * call (`request.getParameter(...)`) all resolve here.
   */
  directSource(node: Node): string | null;
  /** Called-function short name if `node` is a call, else null (for controls). */
  callName(node: Node): string | null;
  /** Sanitizer table: call name -> {label, categories defended}. */
  sanitizers: Record<string, { label: string; cats: string[] }>;
  /** Optional: a control contributed by the node itself, e.g. a `(int)` cast. */
  castControl?(node: Node): CtrlRef | null;
  /** Optional display prefix for carrier variables in `via` (PHP: "$"). */
  sigil?: string;
}

const dedupe = (cs: CtrlRef[]): CtrlRef[] => {
  const seen = new Set<string>();
  return cs.filter((c) => (seen.has(c.label) ? false : (seen.add(c.label), true)));
};

export class TaintTracker {
  private stack: Array<Map<string, TaintValue>> = [new Map()];

  constructor(private readonly p: TaintProfile) {}

  enter(): void {
    this.stack.push(new Map());
  }
  exit(): void {
    this.stack.pop();
  }
  private cur(): Map<string, TaintValue> {
    return this.stack[this.stack.length - 1];
  }

  /** Seed a parameter as tainted (request-bound param, framework input). */
  seedParam(name: string, origin: string, line: number): void {
    this.cur().set(name, { origin, line, via: [], controls: [] });
  }

  /** Mark a variable tainted directly (e.g. a destructured source binding). */
  seedVar(name: string, value: TaintValue): void {
    this.cur().set(name, value);
  }

  has(name: string): boolean {
    return this.cur().has(name);
  }

  /**
   * First untrusted value in a subtree. A direct source wins immediately; a
   * tainted variable is remembered as a fallback (carrying its via + controls)
   * so a direct source found deeper still takes precedence.
   */
  scan(node: Node): TaintValue | null {
    const stack: Node[] = [node];
    let fallback: TaintValue | null = null;
    while (stack.length) {
      const n = stack.pop()!;
      const direct = this.p.directSource(n);
      if (direct) return { origin: direct, line: n.startPosition.row + 1, via: [], controls: [] };
      const vn = this.p.varName(n);
      if (vn && this.cur().has(vn)) {
        const o = this.cur().get(vn)!;
        const label = (this.p.sigil ?? "") + vn;
        fallback = fallback ?? { origin: o.origin, line: o.line, via: [label], controls: o.controls };
      }
      for (const c of n.namedChildren) stack.push(c);
    }
    return fallback;
  }

  /** Sanitizer/cast controls found anywhere in a subtree (over-approximate). */
  collectControls(node: Node): CtrlRef[] {
    const out: CtrlRef[] = [];
    const seen = new Set<string>();
    const add = (c: CtrlRef) => {
      if (!seen.has(c.label)) {
        seen.add(c.label);
        out.push(c);
      }
    };
    const stack: Node[] = [node];
    while (stack.length) {
      const n = stack.pop()!;
      if (this.p.castControl) {
        const cc = this.p.castControl(n);
        if (cc) add(cc);
      }
      const cn = this.p.callName(n);
      if (cn && this.p.sanitizers[cn]) {
        add({ label: this.p.sanitizers[cn].label, cats: this.p.sanitizers[cn].cats });
      }
      for (const c of n.namedChildren) stack.push(c);
    }
    return out;
  }

  /**
   * `target = <right>` / augmented `target op= <right>`. Propagate taint (and
   * any controls it passed through) to `target`. Reassignment clears; an
   * augmented assignment keeps the prior taint (the tainted content remains).
   */
  assign(targetName: string | null, right: Node | null, augmented: boolean): void {
    const t = right ? this.scan(right) : null;
    if (!targetName) return;
    if (t) {
      const prior = augmented && this.cur().has(targetName) ? this.cur().get(targetName)!.controls : [];
      const controls = dedupe([...t.controls, ...(right ? this.collectControls(right) : []), ...prior]);
      this.cur().set(targetName, { origin: t.origin, line: t.line, via: t.via, controls });
    } else if (!augmented) {
      this.cur().delete(targetName);
    }
  }

  /**
   * Record a taint finding on `fi` if `argNode`'s subtree carries untrusted
   * input into the sink. Controls are resolved against THIS sink's category:
   * a control is `relevant` only if it defends this category (or is generic).
   */
  recordSink(
    fi: FunctionInfo,
    sink: string,
    category: string,
    line: number,
    argNode: Node | null | undefined
  ): void {
    if (!argNode) return;
    const t = this.scan(argNode);
    if (!t) return;
    const raw = dedupe([...t.controls, ...this.collectControls(argNode)]);
    const controls: Control[] = raw.map((c) => ({
      label: c.label,
      relevant: c.cats.includes(category) || c.cats.includes("*"),
    }));
    fi.taint.push({
      origin: t.origin,
      originLine: t.line,
      sink,
      sinkLine: line,
      category,
      via: t.via,
      controls,
    });
  }
}

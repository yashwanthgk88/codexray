/**
 * Review state — the spine that turns CodeXray from a viewer into an
 * instrument. A review is persisted at `.codexray/review.json` in the workspace
 * so it lives in version control: reviews become diffable and travel with code.
 *
 * This module is split into PURE logic (schema, hashing, disposition, merge,
 * staleness, payload annotation) and thin IO (load/save). The pure functions are
 * unit-tested headlessly (scratch/verify-review.ts).
 */

export type Disposition =
  | "unreviewed"
  | "reviewing"
  | "safe"
  | "finding"
  | "needs_info"
  | "false_positive";

export const DISPOSITIONS: Disposition[] = [
  "unreviewed", "reviewing", "safe", "finding", "needs_info", "false_positive",
];

/** A status counts as "reviewed" for completeness once it leaves unreviewed. */
export const isReviewed = (s: Disposition): boolean => s !== "unreviewed";

export interface FunctionReview {
  status: Disposition;
  note?: string;
  reviewer?: string;
  reviewedAt?: string; // ISO-8601
  codeHash: string; // hash of the function body at the time this was set
}

export interface Engagement {
  name: string;
  reviewer: string;
  createdAt: string;
  updatedAt: string;
}

export interface ReviewFile {
  version: 1;
  engagement: Engagement;
  /** key = `${file}::${qualname}` (the payload's function key). */
  functions: Record<string, FunctionReview>;
}

/** Deterministic 32-bit FNV-1a hash → base36. No crypto dep; stable across runs. */
export function hashCode(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(36);
}

export function emptyReview(engagement: Partial<Engagement>, now: string): ReviewFile {
  return {
    version: 1,
    engagement: {
      name: engagement.name || "Untitled review",
      reviewer: engagement.reviewer || "unknown",
      createdAt: engagement.createdAt || now,
      updatedAt: now,
    },
    functions: {},
  };
}

/** Set/replace one function's disposition. Mutates and returns the review. */
export function setDisposition(
  review: ReviewFile,
  key: string,
  d: { status: Disposition; note?: string; reviewer: string; codeHash: string; now: string }
): ReviewFile {
  if (d.status === "unreviewed" && !d.note) {
    delete review.functions[key]; // clearing a disposition removes the record
  } else {
    review.functions[key] = {
      status: d.status,
      note: d.note || undefined,
      reviewer: d.reviewer,
      reviewedAt: d.now,
      codeHash: d.codeHash,
    };
  }
  review.engagement.updatedAt = d.now;
  return review;
}

/**
 * Merge `incoming` into `base` (multi-reviewer). Per function, the more recent
 * `reviewedAt` wins; ties keep `base`. Non-destructive: returns a new object.
 */
export function mergeReviews(base: ReviewFile, incoming: ReviewFile): ReviewFile {
  const out: ReviewFile = {
    version: 1,
    engagement: { ...base.engagement },
    functions: { ...base.functions },
  };
  for (const [key, inc] of Object.entries(incoming.functions)) {
    const cur = out.functions[key];
    if (!cur || (inc.reviewedAt || "") > (cur.reviewedAt || "")) {
      out.functions[key] = inc;
    }
  }
  if ((incoming.engagement.updatedAt || "") > (out.engagement.updatedAt || "")) {
    out.engagement.updatedAt = incoming.engagement.updatedAt;
  }
  return out;
}

export interface Completeness {
  total: number;
  reviewed: number;
  percent: number;
  byStatus: Record<Disposition, number>;
  stale: number;
}

/**
 * Overlay review state onto the analysis payload IN PLACE:
 *  - each `funcs[key].review` gets { status, note, stale, reviewer, reviewedAt }
 *  - `payload.review` gets engagement + completeness (incl. stale count)
 * Staleness (Phase 3): a disposition whose stored codeHash no longer matches the
 * function's current body is flagged `stale` — it needs re-review.
 */
export function annotatePayload(payload: any, review: ReviewFile): Completeness {
  const byStatus = {
    unreviewed: 0, reviewing: 0, safe: 0, finding: 0, needs_info: 0, false_positive: 0,
  } as Record<Disposition, number>;
  let reviewed = 0;
  let stale = 0;
  const funcs = payload.funcs || {};
  const keys = Object.keys(funcs);

  for (const key of keys) {
    const fr = review.functions[key];
    const currentHash: string = funcs[key].codeHash || "";
    if (fr) {
      const isStale = !!currentHash && !!fr.codeHash && currentHash !== fr.codeHash;
      funcs[key].review = {
        status: fr.status,
        note: fr.note || "",
        reviewer: fr.reviewer || "",
        reviewedAt: fr.reviewedAt || "",
        stale: isStale,
      };
      byStatus[fr.status] = (byStatus[fr.status] || 0) + 1;
      if (isReviewed(fr.status)) reviewed++;
      if (isStale) stale++;
    } else {
      funcs[key].review = { status: "unreviewed", note: "", reviewer: "", reviewedAt: "", stale: false };
      byStatus.unreviewed++;
    }
  }

  const total = keys.length;
  const completeness: Completeness = {
    total,
    reviewed,
    percent: total ? Math.round((reviewed / total) * 100) : 0,
    byStatus,
    stale,
  };
  payload.review = { engagement: review.engagement, completeness };
  return completeness;
}

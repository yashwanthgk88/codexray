/**
 * Review persistence IO — reads/writes `.codexray/review.json` at the workspace
 * root. Kept separate from store.ts (pure logic) so the logic stays testable
 * without a filesystem.
 */
import * as fs from "fs";
import * as path from "path";
import { ReviewFile } from "./store";

export const REVIEW_DIR = ".codexray";
export const REVIEW_FILE = "review.json";

export function reviewPath(root: string): string {
  return path.join(root, REVIEW_DIR, REVIEW_FILE);
}

/** Load the review for a workspace root, or null if none / unreadable / wrong version. */
export function loadReview(root: string): ReviewFile | null {
  try {
    const raw = fs.readFileSync(reviewPath(root), "utf-8");
    const parsed = JSON.parse(raw);
    if (!parsed || parsed.version !== 1 || typeof parsed.functions !== "object") return null;
    if (!parsed.engagement) return null;
    return parsed as ReviewFile;
  } catch {
    return null;
  }
}

/** Read a review from an arbitrary path (for multi-reviewer merge). */
export function loadReviewFrom(file: string): ReviewFile | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (!parsed || parsed.version !== 1 || typeof parsed.functions !== "object") return null;
    return parsed as ReviewFile;
  } catch {
    return null;
  }
}

/** Persist the review, creating `.codexray/` if needed. */
export function saveReview(root: string, review: ReviewFile): void {
  const dir = path.join(root, REVIEW_DIR);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(reviewPath(root), JSON.stringify(review, null, 2) + "\n", "utf-8");
}

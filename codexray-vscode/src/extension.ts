import * as vscode from "vscode";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { getParsers } from "./analyzer/parser";
import { buildModel, SourceFile } from "./analyzer/analyze";
import { buildPayload } from "./analyzer/payload";
import { adapterForExt } from "./analyzer/adapters";
import { getAiConfig, getApiKey, callProvider, secretKeyId, envKeyName, keyRequired } from "./ai/provider";
import { SYSTEM_PROMPT, buildUserPrompt } from "./ai/prompt";
import {
  emptyReview, setDisposition, mergeReviews, annotatePayload, ReviewFile, Disposition,
} from "./review/store";
import { loadReview, loadReviewFrom, saveReview } from "./review/io";
import { buildMarkdown, buildHtml, buildSarif } from "./review/export";

/** Reviewer identity: setting → OS user → "unknown". */
function reviewerName(): string {
  const cfg = vscode.workspace.getConfiguration("codexray.review").get<string>("reviewer");
  if (cfg && cfg.trim()) return cfg.trim();
  try { return os.userInfo().username || "unknown"; } catch { return "unknown"; }
}

const nowIso = (): string => new Date().toISOString();

/** Write the review deliverable (md/html/sarif) into `<root>/.codexray/`. Returns the .md path. */
function writeReviewReport(root: string, payload: any, review: ReviewFile): string {
  const dir = path.join(root, ".codexray");
  fs.mkdirSync(dir, { recursive: true });
  const base = "review-report";
  fs.writeFileSync(path.join(dir, `${base}.md`), buildMarkdown(payload, review), "utf-8");
  fs.writeFileSync(path.join(dir, `${base}.html`), buildHtml(payload, review), "utf-8");
  fs.writeFileSync(path.join(dir, `${base}.sarif.json`), JSON.stringify(buildSarif(payload, review), null, 2), "utf-8");
  return path.join(dir, `${base}.md`);
}

/** Set by the most-recent panel so the palette export/merge commands can act. */
let activeReview: { root: string; payload: any; getReview: () => ReviewFile; refresh: () => void } | null = null;

const IGNORE_DIRS = new Set([
  ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
  // Dependency + build-output trees for the supported languages — these hold
  // vendored / generated code that would consume the file budget (see MAX_FILES).
  "vendor",           // PHP (Composer)
  "target",           // Java (Maven/Gradle)
  "bin", "obj",       // C# / .NET
  "dist", "build", "out", // JS/TS + general build output
]);
const MAX_FILES = 4000;

let out: vscode.OutputChannel;
function log(msg: string): void {
  out.appendLine(`[${new Date().toISOString()}] ${msg}`);
}

/** Run a command body with a single guaranteed-visible failure path. */
async function guard(fn: () => Promise<void>): Promise<void> {
  try {
    await fn();
  } catch (err) {
    const msg = err instanceof Error ? err.stack || err.message : String(err);
    log("UNCAUGHT: " + msg);
    out.show(true);
    void vscode.window.showErrorMessage(
      `CodeXray failed: ${err instanceof Error ? err.message : String(err)} (see the CodeXray output channel)`
    );
  }
}

/** Empty tree provider — its only job is to host the Activity Bar welcome view
 *  (the "X-ray Workspace" button lives in viewsWelcome in package.json). */
class CodeXrayViewProvider implements vscode.TreeDataProvider<never> {
  getTreeItem(): vscode.TreeItem {
    return new vscode.TreeItem("");
  }
  getChildren(): never[] {
    return [];
  }
}

export function activate(context: vscode.ExtensionContext): void {
  out = vscode.window.createOutputChannel("CodeXray");
  context.subscriptions.push(out);
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("codexray.panel", new CodeXrayViewProvider())
  );
  log("CodeXray activated. extensionPath=" + context.extensionPath);

  context.subscriptions.push(
    vscode.commands.registerCommand("codexray.analyzeWorkspace", () =>
      guard(async () => {
        log("command: analyzeWorkspace");
        const folders = vscode.workspace.workspaceFolders;
        if (!folders || folders.length === 0) {
          void vscode.window.showErrorMessage(
            "CodeXray: open a folder or workspace first (File → Open Folder…)."
          );
          return;
        }
        let target = folders[0].uri;
        if (folders.length > 1) {
          const pick = await vscode.window.showWorkspaceFolderPick({
            placeHolder: "Which folder should CodeXray X-ray?",
          });
          if (!pick) return;
          target = pick.uri;
        }
        await analyzeAndShow(context, target);
      })
    ),
    vscode.commands.registerCommand("codexray.analyzeFolder", (uri?: vscode.Uri) =>
      guard(async () => {
        log("command: analyzeFolder uri=" + (uri ? uri.fsPath : "none"));
        let target = uri;
        if (!target) {
          const folders = vscode.workspace.workspaceFolders;
          target = folders && folders.length ? folders[0].uri : undefined;
        }
        if (!target) {
          void vscode.window.showErrorMessage("CodeXray: no folder selected.");
          return;
        }
        await analyzeAndShow(context, target);
      })
    ),
    vscode.commands.registerCommand("codexray.setAiKey", () =>
      guard(async () => {
        const cfg = getAiConfig();
        const key = await vscode.window.showInputBox({
          title: `CodeXray: ${cfg.provider} API key`,
          prompt: `Stored securely in VS Code SecretStorage. Leave blank to clear. (Also read from $${envKeyName(cfg.provider)} if unset.)`,
          password: true,
          ignoreFocusOut: true,
        });
        if (key === undefined) return; // cancelled
        if (key.trim() === "") {
          await context.secrets.delete(secretKeyId(cfg.provider));
          void vscode.window.showInformationMessage(`CodeXray: cleared ${cfg.provider} API key.`);
        } else {
          await context.secrets.store(secretKeyId(cfg.provider), key.trim());
          void vscode.window.showInformationMessage(`CodeXray: saved ${cfg.provider} API key.`);
        }
      })
    ),
    // Phase 2: export the review deliverable from the active X-ray panel.
    vscode.commands.registerCommand("codexray.exportReview", () =>
      guard(async () => {
        if (!activeReview) {
          void vscode.window.showWarningMessage("CodeXray: open an X-ray panel first, then export its review.");
          return;
        }
        const mdPath = writeReviewReport(activeReview.root, activeReview.payload, activeReview.getReview());
        const openIt = "Open Markdown";
        const pick = await vscode.window.showInformationMessage(
          "CodeXray: exported review report to .codexray/.", openIt
        );
        if (pick === openIt) {
          const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
          await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One });
        }
      })
    ),
    // Phase 4: merge another reviewer's review.json into this workspace's review.
    vscode.commands.registerCommand("codexray.mergeReview", () =>
      guard(async () => {
        const folders = vscode.workspace.workspaceFolders;
        if (!folders || !folders.length) {
          void vscode.window.showErrorMessage("CodeXray: open a folder first.");
          return;
        }
        let root = folders[0].uri.fsPath;
        if (activeReview) root = activeReview.root;
        const picked = await vscode.window.showOpenDialog({
          title: "CodeXray: merge a review.json from another reviewer",
          canSelectMany: false,
          filters: { "Review JSON": ["json"] },
        });
        if (!picked || !picked.length) return;
        const incoming = loadReviewFrom(picked[0].fsPath);
        if (!incoming) {
          void vscode.window.showErrorMessage("CodeXray: that file is not a valid CodeXray review.json.");
          return;
        }
        const current =
          loadReview(root) ||
          emptyReview({ name: `${path.basename(root)} review`, reviewer: reviewerName(), createdAt: nowIso() }, nowIso());
        const before = Object.keys(current.functions).length;
        const merged = mergeReviews(current, incoming);
        saveReview(root, merged);
        const after = Object.keys(merged.functions).length;
        if (activeReview && activeReview.root === root) {
          // Live-refresh the open panel with the merged review on disk.
          const fresh = loadReview(root);
          if (fresh) { Object.assign(activeReview.getReview(), fresh); activeReview.refresh(); }
        }
        void vscode.window.showInformationMessage(
          `CodeXray: merged review (${before} → ${after} dispositioned functions). Re-run X-ray if the panel isn't open.`
        );
      })
    )
  );
}

export function deactivate(): void {
  /* nothing to clean up */
}

/** Recursively collect every source file a language adapter claims, tagged with
 *  the adapter id chosen from its extension. */
function collectSourceFiles(root: string): SourceFile[] {
  const out: SourceFile[] = [];
  const stack: string[] = [root];
  while (stack.length) {
    if (out.length >= MAX_FILES) break;
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) stack.push(full);
      } else if (entry.isFile()) {
        const adapter = adapterForExt(path.extname(entry.name));
        if (!adapter) continue;
        let src: string;
        try {
          src = fs.readFileSync(full, "utf-8");
        } catch {
          continue;
        }
        out.push({ rel: path.relative(root, full), src, lang: adapter.id });
        if (out.length >= MAX_FILES) break;
      }
    }
  }
  return out;
}

async function analyzeAndShow(
  context: vscode.ExtensionContext,
  rootUri: vscode.Uri
): Promise<void> {
  const root = rootUri.fsPath;
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: "CodeXray: X-raying source…",
      cancellable: false,
    },
    async (progress) => {
      progress.report({ message: "collecting source files" });
      log("scanning " + root);
      const files = collectSourceFiles(root);
      const langCounts: Record<string, number> = {};
      for (const f of files) langCounts[f.lang] = (langCounts[f.lang] ?? 0) + 1;
      log(`found ${files.length} source file(s): ${JSON.stringify(langCounts)}`);
      if (files.length === 0) {
        vscode.window.showWarningMessage(
          `CodeXray: no supported source files found under ${path.basename(root)} (Python, PHP, Java, C#, TypeScript).`
        );
        return;
      }
      if (files.length >= MAX_FILES) {
        vscode.window.showWarningMessage(
          `CodeXray: capped at ${MAX_FILES} files — some source was not analyzed.`
        );
      }

      progress.report({ message: "initialising parsers" });
      const wasmDir = path.join(context.extensionPath, "dist");
      log("initialising tree-sitter from " + wasmDir);
      const parsers = await getParsers(wasmDir, files.map((f) => f.lang));
      log(`parsers ready for: ${[...parsers.keys()].join(", ")}; analyzing`);
      progress.report({ message: `analyzing ${files.length} file(s)` });
      const model = buildModel(root, files, parsers);
      const payload = buildPayload(model);
      log(`analysis done: ${JSON.stringify(model.stats)}`);

      // Review instrument: load persisted review (or start one) and overlay it.
      let review: ReviewFile =
        loadReview(root) ||
        emptyReview({ name: `${path.basename(root)} review`, reviewer: reviewerName(), createdAt: nowIso() }, nowIso());
      annotatePayload(payload, review);
      log(`review: ${payload.review.completeness.reviewed}/${payload.review.completeness.total} reviewed, ${payload.review.completeness.stale} stale`);

      const panel = vscode.window.createWebviewPanel(
        "codexray",
        `CodeXray · ${path.basename(root)}`,
        vscode.ViewColumn.Active,
        { enableScripts: true, retainContextWhenHidden: true }
      );
      const templatePath = path.join(context.extensionPath, "media", "report.html");
      const template = fs.readFileSync(templatePath, "utf-8");
      const payloadJson = JSON.stringify(payload).replace(/</g, "\\u003c");
      // NB: use a replacer FUNCTION, not a string — the payload is full of PHP `$`
      // (e.g. `$'`, `$1`) which String.replace would interpret as $-patterns and
      // corrupt the JSON into invalid JS (blank webview).
      panel.webview.html = template.replace("__PAYLOAD__", () => payloadJson);

      // Webview messages: {type:'open',...} jumps to source; {type:'explain',...}
      // runs the configured AI over one flow and posts the insight back.
      panel.webview.onDidReceiveMessage(
        async (msg) => {
          if (!msg) return;
          if (msg.type === "open" && typeof msg.file === "string") {
            try {
              const fileUri = vscode.Uri.file(path.join(root, msg.file));
              const doc = await vscode.workspace.openTextDocument(fileUri);
              const editor = await vscode.window.showTextDocument(doc, {
                viewColumn: vscode.ViewColumn.One,
                preserveFocus: false,
              });
              const line = Math.max(0, (Number(msg.line) || 1) - 1);
              const pos = new vscode.Position(line, 0);
              editor.selection = new vscode.Selection(pos, pos);
              editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
            } catch (e) {
              log("open failed: " + String(e));
              void vscode.window.showWarningMessage(`CodeXray: could not open ${msg.file}:${msg.line}`);
            }
            return;
          }
          if (msg.type === "setKey") {
            await vscode.commands.executeCommand("codexray.setAiKey");
            return;
          }
          if (msg.type === "mergeRequest") {
            await vscode.commands.executeCommand("codexray.mergeReview");
            return;
          }
          if (msg.type === "disposition" && typeof msg.key === "string") {
            // Phase 1: reviewer sets a disposition on a function. Persist + re-overlay.
            const codeHash = payload.funcs[msg.key]?.codeHash || "";
            review = setDisposition(review, msg.key, {
              status: msg.status as Disposition,
              note: typeof msg.note === "string" ? msg.note : undefined,
              reviewer: reviewerName(),
              codeHash,
              now: nowIso(),
            });
            try {
              saveReview(root, review);
            } catch (e) {
              log("saveReview failed: " + String(e));
              void vscode.window.showErrorMessage(`CodeXray: could not save review (${String(e)})`);
            }
            annotatePayload(payload, review); // recompute completeness + clear staleness
            void panel.webview.postMessage({
              type: "reviewUpdated",
              key: msg.key,
              review: payload.funcs[msg.key].review,
              completeness: payload.review.completeness,
              engagement: payload.review.engagement,
            });
            return;
          }
          if (msg.type === "export") {
            try {
              const mdPath = writeReviewReport(root, payload, review);
              log(`exported review report to ${path.dirname(mdPath)}`);
              const openIt = "Open Markdown";
              const pick = await vscode.window.showInformationMessage(
                "CodeXray: exported review report to .codexray/ (review-report.md, .html, .sarif.json).",
                openIt
              );
              if (pick === openIt) {
                const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(mdPath));
                await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.One });
              }
            } catch (e) {
              log("export failed: " + String(e));
              void vscode.window.showErrorMessage(`CodeXray: export failed (${String(e)})`);
            }
            return;
          }
          if (msg.type === "explain" && msg.flow) {
            const id = msg.id;
            try {
              const cfg = getAiConfig();
              const apiKey = await getApiKey(context, cfg.provider);
              if (!apiKey && keyRequired(cfg.provider)) {
                void panel.webview.postMessage({
                  type: "insightError",
                  id,
                  error: `No ${cfg.provider} API key. Run "CodeXray: Set AI API Key" (or set $${envKeyName(cfg.provider)}).`,
                  needsKey: true,
                });
                return;
              }
              log(`explain flow ${id} via ${cfg.provider}/${cfg.model}`);
              const text = await callProvider(cfg, apiKey || "", SYSTEM_PROMPT, buildUserPrompt(msg.flow));
              void panel.webview.postMessage({ type: "insight", id, markdown: text, model: cfg.model });
            } catch (e) {
              const em = e instanceof Error ? e.message : String(e);
              log("explain failed: " + em);
              void panel.webview.postMessage({ type: "insightError", id, error: em });
            }
            return;
          }
        },
        undefined,
        context.subscriptions
      );

      // Expose this panel's review to the palette commands (export / merge).
      activeReview = {
        root,
        payload,
        getReview: () => review,
        refresh: () => {
          annotatePayload(payload, review);
          void panel.webview.postMessage({
            type: "reviewReloaded",
            funcs: payload.funcs,
            completeness: payload.review.completeness,
            engagement: payload.review.engagement,
          });
        },
      };
      panel.onDidDispose(() => { if (activeReview && activeReview.root === root) activeReview = null; },
        undefined, context.subscriptions);
      panel.onDidChangeViewState((e) => {
        if (e.webviewPanel.active) {
          activeReview = { root, payload, getReview: () => review, refresh: () => {
            annotatePayload(payload, review);
            void panel.webview.postMessage({ type: "reviewReloaded", funcs: payload.funcs,
              completeness: payload.review.completeness, engagement: payload.review.engagement });
          } };
        }
      }, undefined, context.subscriptions);

      log("webview rendered");
    }
  );
}

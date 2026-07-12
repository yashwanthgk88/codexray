import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { getParser } from "./analyzer/parser";
import { buildModel, SourceFile } from "./analyzer/analyze";
import { buildPayload } from "./analyzer/payload";

const IGNORE_DIRS = new Set([
  ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
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
    )
  );
}

export function deactivate(): void {
  /* nothing to clean up */
}

/** Recursively collect .py files under `root`, mirroring xray.py's os.walk skip set. */
function collectPythonFiles(root: string): SourceFile[] {
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
      } else if (entry.isFile() && entry.name.endsWith(".py")) {
        let src: string;
        try {
          src = fs.readFileSync(full, "utf-8");
        } catch {
          continue;
        }
        out.push({ rel: path.relative(root, full), src });
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
      progress.report({ message: "collecting Python files" });
      log("scanning " + root);
      const files = collectPythonFiles(root);
      log(`found ${files.length} .py file(s)`);
      if (files.length === 0) {
        vscode.window.showWarningMessage(
          `CodeXray: no .py files found under ${path.basename(root)}.`
        );
        return;
      }
      if (files.length >= MAX_FILES) {
        vscode.window.showWarningMessage(
          `CodeXray: capped at ${MAX_FILES} files — some source was not analyzed.`
        );
      }

      progress.report({ message: "initialising parser" });
      const wasmDir = path.join(context.extensionPath, "dist");
      log("initialising tree-sitter from " + wasmDir);
      const parser = await getParser(wasmDir);
      log("parser ready; analyzing");
      progress.report({ message: `analyzing ${files.length} file(s)` });
      const model = buildModel(root, files, parser);
      const payload = buildPayload(model);
      log(`analysis done: ${JSON.stringify(model.stats)}`);

      const panel = vscode.window.createWebviewPanel(
        "codexray",
        `CodeXray · ${path.basename(root)}`,
        vscode.ViewColumn.Active,
        { enableScripts: true, retainContextWhenHidden: true }
      );
      const templatePath = path.join(context.extensionPath, "media", "report.html");
      const template = fs.readFileSync(templatePath, "utf-8");
      panel.webview.html = template.replace(
        "__PAYLOAD__",
        JSON.stringify(payload).replace(/</g, "\\u003c")
      );
      log("webview rendered");
    }
  );
}

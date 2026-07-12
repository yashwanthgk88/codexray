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

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand("codexray.analyzeWorkspace", async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showErrorMessage("CodeXray: open a folder or workspace first.");
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
    }),
    vscode.commands.registerCommand(
      "codexray.analyzeFolder",
      async (uri?: vscode.Uri) => {
        let target = uri;
        if (!target) {
          const folders = vscode.workspace.workspaceFolders;
          target = folders && folders.length ? folders[0].uri : undefined;
        }
        if (!target) {
          vscode.window.showErrorMessage("CodeXray: no folder selected.");
          return;
        }
        await analyzeAndShow(context, target);
      }
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
      const files = collectPythonFiles(root);
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
      let payload: any;
      try {
        const parser = await getParser(wasmDir);
        progress.report({ message: `analyzing ${files.length} file(s)` });
        const model = buildModel(root, files, parser);
        payload = buildPayload(model);
      } catch (err) {
        vscode.window.showErrorMessage(
          `CodeXray failed: ${err instanceof Error ? err.message : String(err)}`
        );
        return;
      }

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
    }
  );
}

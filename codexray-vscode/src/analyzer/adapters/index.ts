/** Adapter registry: the single place that lists every supported language. */
import { LanguageAdapter } from "./types";
import { pythonAdapter } from "./python";
import { phpAdapter } from "./php";
import { javaAdapter } from "./java";
import { csharpAdapter } from "./csharp";
import { typescriptAdapter } from "./typescript";

export { LanguageAdapter } from "./types";
export { externalNames } from "./types";

export const ADAPTERS: LanguageAdapter[] = [
  pythonAdapter, phpAdapter, javaAdapter, csharpAdapter, typescriptAdapter,
];

const BY_ID = new Map<string, LanguageAdapter>();
const BY_EXT = new Map<string, LanguageAdapter>();
for (const a of ADAPTERS) {
  BY_ID.set(a.id, a);
  for (const ext of a.extensions) BY_EXT.set(ext.toLowerCase(), a);
}

export const adapterById = (id: string): LanguageAdapter | undefined => BY_ID.get(id);
export const adapterForExt = (ext: string): LanguageAdapter | undefined =>
  BY_EXT.get(ext.toLowerCase());

/** All file extensions any adapter claims (for the file collector). */
export const SUPPORTED_EXTENSIONS: string[] = [...BY_EXT.keys()];

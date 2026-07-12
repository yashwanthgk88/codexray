/** Data model shared across the analyzer, ported from xray.py's FunctionInfo + model dict. */

export type EntryKind = "http" | "cli" | "task" | "main" | null;

export interface EntryMeta {
  method?: string;
  path?: string;
  decorator?: string;
}

/** [callee_short, callee_dotted, lineno] */
export type CallTuple = [string, string, number];
/** [dotted, category, why, lineno] */
export type SinkTuple = [string, string, string, number];
/** [name, lineno] */
export type SourceTuple = [string, number];
/** [dotted, reason, lineno] */
export type BlindTuple = [string, string, number];

export class FunctionInfo {
  qualname: string;
  file: string;
  lineno: number;
  endlineno: number;
  calls: CallTuple[] = [];
  sinks: SinkTuple[] = [];
  sources: SourceTuple[] = [];
  blindspots: BlindTuple[] = [];
  isEntry = false;
  entryKind: EntryKind = null;
  entryMeta: EntryMeta = {};
  params: string[] = [];

  constructor(qualname: string, file: string, lineno: number, endlineno: number) {
    this.qualname = qualname;
    this.file = file;
    this.lineno = lineno;
    this.endlineno = endlineno;
  }
}

export interface Model {
  root: string;
  funcs: Map<string, FunctionInfo>;
  edges: Map<string, Set<string>>;
  fileSources: Map<string, string[]>;
  unresolved: Map<string, Array<[string, string, number]>>;
  ambiguous: Map<string, Array<[string, string[], number]>>;
  entries: string[];
  reachableFrom: Map<string, Set<string>>;
  entrySinks: Map<string, Array<[string, SinkTuple, string[]]>>;
  buckets: Record<string, string[]>;
  files: string[];
  parseErrors: Array<[string, string]>;
  stats: Record<string, number>;
}

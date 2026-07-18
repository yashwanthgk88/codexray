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

/** A defensive control the tainted value passed through on its way to the sink. */
export interface Control {
  label: string;    // e.g. "escapeshellarg()"
  relevant: boolean; // does it defend THIS sink's category?
}

/** A confirmed intra-function taint chain: untrusted source → variable(s) → sink. */
export interface TaintFinding {
  origin: string;      // e.g. "$_REQUEST"
  originLine: number;
  sink: string;        // e.g. "shell_exec"
  sinkLine: number;
  category: string;    // e.g. "command_exec"
  via: string[];       // carrier variables, e.g. ["$target"]
  controls: Control[]; // defenses seen between source and sink
}

export class FunctionInfo {
  qualname: string;
  file: string;
  lineno: number;
  endlineno: number;
  language: string;
  calls: CallTuple[] = [];
  sinks: SinkTuple[] = [];
  sources: SourceTuple[] = [];
  blindspots: BlindTuple[] = [];
  taint: TaintFinding[] = [];
  isEntry = false;
  entryKind: EntryKind = null;
  entryMeta: EntryMeta = {};
  params: string[] = [];

  constructor(
    qualname: string,
    file: string,
    lineno: number,
    endlineno: number,
    language = "python"
  ) {
    this.qualname = qualname;
    this.file = file;
    this.lineno = lineno;
    this.endlineno = endlineno;
    this.language = language;
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
  /** per-language file counts, e.g. { php: 169, python: 1 }. */
  languages: Record<string, number>;
  stats: Record<string, number>;
}

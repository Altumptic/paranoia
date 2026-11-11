// Function memory: matching two binaries and the local knowledge base.
// Desktop only; both run in the engine process (see crates/paranoia-core/src/memory).

import { getBackend, type Session } from "./client";

export type MatchKind = "name" | "exact" | "shape" | "anchors" | "call_graph" | "fuzzy" | "order";

export interface FunctionMatch {
  a: number;
  b: number;
  a_name: string;
  b_name: string;
  a_named: boolean;
  b_named: boolean;
  /** 1 for identical code. */
  score: number;
  kind: MatchKind;
  changed: boolean;
}

export interface Unmatched {
  address: number;
  name: string;
  instructions: number;
}

export interface DiffReport {
  matches: FunctionMatch[];
  only_a: Unmatched[];
  only_b: Unmatched[];
  similarity: number;
}

export interface KnownFunction {
  name: string;
  comment?: string;
  var_names?: Record<string, string>;
  var_types?: Record<string, string>;
  comments?: [number, string][];
  calls?: string[];
  source: string;
  source_sha256: string;
  // The fingerprint travels back to the engine unchanged when applying.
  print: unknown;
}

export interface Recall {
  address: number;
  current: string;
  score: number;
  exact: boolean;
  known: KnownFunction;
}

export interface SourceInfo {
  file: string;
  sha256: string;
  functions: number;
  time: number;
}

export interface KnowledgeStats {
  functions: number;
  sources: SourceInfo[];
}

const memoryOp = <T>(method: string, session: Session | null, args: unknown = null) =>
  getBackend().raw({ op: "memory", method, handle: session?.handle, args }) as Promise<T>;

export const memory = {
  stats: () => memoryOp<KnowledgeStats>("stats", null),
  learn: (s: Session, symbols: boolean) => memoryOp<{ added: number; updated: number }>("learn", s, { symbols }),
  recall: (s: Session, minScore?: number) => memoryOp<Recall[]>("recall", s, minScore == null ? null : { min_score: minScore }),
  forget: (sha256: string) => memoryOp<number>("forget", null, { sha256 }),
  /** Applies chosen recalls to the open file: one undo step. */
  apply: (s: Session, items: Recall[]) => s.backend.call<{ renamed: number; comments: number; variables: number }>(s.handle, "applyKnown", { items }),
  diff: (a: Session, b: Session, names = true) => getBackend().raw({ op: "diff", handle: a.handle, args: { other: b.handle, names } }) as Promise<DiffReport>,
  /** Renames several addresses as one undo step. */
  renameMany: (s: Session, items: { va: number; text: string }[]) => s.backend.call<number>(s.handle, "renameMany", { items }),
};

export const kindLabel: Record<MatchKind, string> = {
  name: "name",
  exact: "identical bytes",
  shape: "same instructions",
  anchors: "same imports/strings",
  call_graph: "call graph",
  fuzzy: "similar code",
  order: "identical copy, by position",
};

/**
 * sonobat — Datalog engine type definitions
 *
 * AST types, runtime types, configuration, and error types
 * for the Datalog inference engine.
 */

// ============================================================
// Token types
// ============================================================

export type TokenKind =
  | 'IDENT'
  | 'VARIABLE'
  | 'STRING'
  | 'NUMBER'
  | 'LPAREN'
  | 'RPAREN'
  | 'COMMA'
  | 'DOT'
  | 'COLON_DASH'
  | 'NOT'
  | 'NEQ'
  | 'EQ'
  | 'LT'
  | 'GT'
  | 'LTE'
  | 'GTE'
  | 'QUERY'
  | 'UNDERSCORE'
  | 'EOF';

export interface Token {
  kind: TokenKind;
  value: string;
  line: number;
  col: number;
}

// ============================================================
// AST types
// ============================================================

export type Term =
  | { kind: 'variable'; name: string }
  | { kind: 'constant'; value: string | number };

export interface Atom {
  predicate: string;
  args: Term[];
}

export type BodyLiteral =
  | { kind: 'positive'; atom: Atom }
  | { kind: 'negated'; atom: Atom }
  | { kind: 'comparison'; op: ComparisonOp; left: Term; right: Term };

export type ComparisonOp = '=' | '!=' | '<' | '>' | '<=' | '>=';

export interface Rule {
  head: Atom;
  body: BodyLiteral[];
}

export interface Query {
  atom: Atom;
}

export interface Program {
  rules: Rule[];
  queries: Query[];
}

// ============================================================
// Runtime types
// ============================================================

export type Tuple = ReadonlyArray<string | number>;

export interface EvalConfig {
  /** Maximum fixed-point iterations (default: 1000) */
  maxIterations: number;
  /** Maximum total derived tuples (default: 100_000) */
  maxTuples: number;
  /** Maximum rules allowed (default: 200) */
  maxRules: number;
  /** Timeout in milliseconds (default: 5000) */
  timeoutMs: number;
}

export const DEFAULT_EVAL_CONFIG: EvalConfig = {
  maxIterations: 1000,
  maxTuples: 100_000,
  maxRules: 200,
  timeoutMs: 5000,
};

export interface QueryAnswer {
  query: Atom;
  tuples: Tuple[];
  columns: string[];
}

export interface EvalStats {
  iterations: number;
  totalDerived: number;
  elapsedMs: number;
}

export interface EvalResult {
  answers: QueryAnswer[];
  stats: EvalStats;
}

// ============================================================
// Fact types (for fact-extractor)
// ============================================================

export interface Fact {
  predicate: string;
  values: ReadonlyArray<string | number>;
}

// ============================================================
// Rule storage types
// ============================================================

export interface DatalogRule {
  id: string;
  name: string;
  description?: string;
  ruleText: string;
  generatedBy: 'human' | 'ai' | 'preset';
  isPreset: boolean;
  createdAt: string;
  updatedAt: string;
}

export interface CreateDatalogRuleInput {
  name: string;
  description?: string;
  ruleText: string;
  generatedBy: 'human' | 'ai' | 'preset';
  isPreset?: boolean;
}

// ============================================================
// Error types
// ============================================================

export class DatalogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DatalogError';
  }
}

export class DatalogSyntaxError extends DatalogError {
  readonly line: number;
  readonly col: number;

  constructor(message: string, line: number, col: number) {
    super(`Syntax error at ${line}:${col}: ${message}`);
    this.name = 'DatalogSyntaxError';
    this.line = line;
    this.col = col;
  }
}

export class DatalogSafetyError extends DatalogError {
  constructor(message: string) {
    super(message);
    this.name = 'DatalogSafetyError';
  }
}

export class DatalogResourceError extends DatalogError {
  constructor(message: string) {
    super(message);
    this.name = 'DatalogResourceError';
  }
}

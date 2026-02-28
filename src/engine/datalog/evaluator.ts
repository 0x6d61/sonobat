/**
 * sonobat — Datalog naive bottom-up evaluator
 *
 * Takes a parsed Program AST and base facts, then:
 * 1. Initializes a fact database from base facts and inline facts (empty-body rules)
 * 2. Repeatedly applies rules until a fixed point (no new facts derived)
 * 3. Evaluates queries against the final fact set
 *
 * Uses a naive semi-naive-style evaluation with Map-based fact storage.
 * Supports positive literals, negated literals, and comparison operators.
 */

import {
  DatalogResourceError,
  DEFAULT_EVAL_CONFIG,
} from './types.js';
import type {
  Program,
  Rule,
  Atom,
  BodyLiteral,
  Term,
  ComparisonOp,
  Fact,
  Tuple,
  EvalConfig,
  EvalResult,
  EvalStats,
  QueryAnswer,
} from './types.js';

// ============================================================
// Binding type — maps variable names to concrete values
// ============================================================

type Binding = Map<string, string | number>;

// ============================================================
// FactDB — stores facts indexed by predicate name
// ============================================================

class FactDB {
  private readonly store: Map<string, Tuple[]> = new Map();
  private readonly seen: Map<string, Set<string>> = new Map();
  private totalCount = 0;

  /** Get all tuples for a predicate. */
  get(predicate: string): ReadonlyArray<Tuple> {
    return this.store.get(predicate) ?? [];
  }

  /** Total number of stored tuples across all predicates. */
  get size(): number {
    return this.totalCount;
  }

  /**
   * Add a tuple for a predicate. Returns true if it was new.
   * Uses a serialized key for deduplication.
   */
  add(predicate: string, tuple: Tuple): boolean {
    const key = serializeTuple(tuple);

    let seenSet = this.seen.get(predicate);
    if (!seenSet) {
      seenSet = new Set();
      this.seen.set(predicate, seenSet);
    }

    if (seenSet.has(key)) {
      return false;
    }

    seenSet.add(key);

    let tuples = this.store.get(predicate);
    if (!tuples) {
      tuples = [];
      this.store.set(predicate, tuples);
    }
    tuples.push(tuple);
    this.totalCount++;
    return true;
  }
}

/** Serialize a tuple into a unique string key for deduplication. */
function serializeTuple(tuple: Tuple): string {
  return tuple
    .map((v) => (typeof v === 'number' ? `n:${v}` : `s:${v}`))
    .join('\0');
}

// ============================================================
// Core evaluation
// ============================================================

/**
 * Evaluate a Datalog program with base facts.
 *
 * @param program - Parsed Datalog program (rules + queries)
 * @param baseFacts - Base facts from the database
 * @param config - Optional resource limits
 * @returns Evaluation result with query answers and statistics
 * @throws DatalogResourceError when resource limits are exceeded
 */
export function evaluate(
  program: Program,
  baseFacts: Fact[],
  config?: Partial<EvalConfig>,
): EvalResult {
  const cfg: EvalConfig = { ...DEFAULT_EVAL_CONFIG, ...config };
  const startTime = performance.now();

  // Separate facts (empty-body rules) from real rules
  const inlineFacts: Rule[] = [];
  const realRules: Rule[] = [];
  for (const rule of program.rules) {
    if (rule.body.length === 0) {
      inlineFacts.push(rule);
    } else {
      realRules.push(rule);
    }
  }

  // Check maxRules limit
  if (realRules.length > cfg.maxRules) {
    throw new DatalogResourceError(
      `Number of rules (${realRules.length}) exceeds maxRules limit (${cfg.maxRules})`,
    );
  }

  // Initialize fact database
  const db = new FactDB();

  // Load base facts
  for (const fact of baseFacts) {
    db.add(fact.predicate, fact.values);
  }

  // Load inline facts (rules with empty body)
  for (const rule of inlineFacts) {
    const tuple = rule.head.args.map((arg) => {
      if (arg.kind === 'constant') {
        return arg.value;
      }
      // Variables in facts without body are not meaningful,
      // but we allow them as-is (parser already validates safety)
      return arg.name;
    });
    db.add(rule.head.predicate, tuple);
  }

  // Fixed-point evaluation
  const stats: EvalStats = { iterations: 0, totalDerived: 0, elapsedMs: 0 };

  if (realRules.length > 0) {
    let changed = true;
    while (changed) {
      // Check timeout
      const elapsed = performance.now() - startTime;
      if (elapsed > cfg.timeoutMs) {
        throw new DatalogResourceError(
          `Evaluation timeout: exceeded ${cfg.timeoutMs}ms`,
        );
      }

      // Check iteration limit
      if (stats.iterations >= cfg.maxIterations) {
        throw new DatalogResourceError(
          `Iteration limit exceeded: ${cfg.maxIterations}`,
        );
      }

      changed = false;
      stats.iterations++;

      for (const rule of realRules) {
        const derivedTuples = evaluateRule(rule, db);
        for (const tuple of derivedTuples) {
          // Check tuple limit
          if (db.size >= cfg.maxTuples) {
            throw new DatalogResourceError(
              `Tuple limit exceeded: ${cfg.maxTuples}`,
            );
          }
          const isNew = db.add(rule.head.predicate, tuple);
          if (isNew) {
            changed = true;
            stats.totalDerived++;
          }
        }
      }
    }
  }

  stats.elapsedMs = performance.now() - startTime;

  // Evaluate queries
  const answers: QueryAnswer[] = program.queries.map((q) =>
    evaluateQuery(q.atom, db),
  );

  return { answers, stats };
}

// ============================================================
// Rule evaluation — derive new tuples from a single rule
// ============================================================

/**
 * Evaluate a single rule against the fact database.
 * Returns all new tuples derivable by the rule's head.
 */
function evaluateRule(rule: Rule, db: FactDB): Tuple[] {
  const bindings = evaluateBody(rule.body, 0, new Map(), db);
  const result: Tuple[] = [];
  const seen = new Set<string>();

  for (const binding of bindings) {
    const tuple = instantiateHead(rule.head, binding);
    const key = serializeTuple(tuple);
    if (!seen.has(key)) {
      seen.add(key);
      result.push(tuple);
    }
  }

  return result;
}

/**
 * Recursively evaluate body literals against the database.
 * Returns all valid bindings that satisfy all body literals.
 *
 * @param body - Array of body literals to evaluate
 * @param index - Current literal index being processed
 * @param binding - Current variable bindings
 * @param db - Fact database
 * @returns Array of complete bindings satisfying all literals
 */
function evaluateBody(
  body: BodyLiteral[],
  index: number,
  binding: Binding,
  db: FactDB,
): Binding[] {
  // Base case: all literals satisfied
  if (index >= body.length) {
    return [binding];
  }

  const literal = body[index];
  const results: Binding[] = [];

  if (literal.kind === 'positive') {
    // Try unifying the atom against all matching facts
    const facts = db.get(literal.atom.predicate);
    for (const factTuple of facts) {
      const newBinding = unifyAtom(literal.atom, factTuple, binding);
      if (newBinding !== null) {
        const subResults = evaluateBody(body, index + 1, newBinding, db);
        for (const r of subResults) {
          results.push(r);
        }
      }
    }
  } else if (literal.kind === 'negated') {
    // Negation: succeeds if NO facts match under current binding
    const facts = db.get(literal.atom.predicate);
    let anyMatch = false;
    for (const factTuple of facts) {
      const newBinding = unifyAtom(literal.atom, factTuple, binding);
      if (newBinding !== null) {
        anyMatch = true;
        break;
      }
    }
    if (!anyMatch) {
      // Negation succeeds — continue with current binding
      const subResults = evaluateBody(body, index + 1, binding, db);
      for (const r of subResults) {
        results.push(r);
      }
    }
  } else if (literal.kind === 'comparison') {
    // Comparison: evaluate against bound values
    if (evaluateComparison(literal.op, literal.left, literal.right, binding)) {
      const subResults = evaluateBody(body, index + 1, binding, db);
      for (const r of subResults) {
        results.push(r);
      }
    }
  }

  return results;
}

// ============================================================
// Unification
// ============================================================

/**
 * Attempt to unify an atom's arguments with a fact tuple,
 * extending the given binding. Returns a new binding on success,
 * or null if unification fails.
 */
function unifyAtom(
  atom: Atom,
  factTuple: Tuple,
  binding: Binding,
): Binding | null {
  // Arity mismatch
  if (atom.args.length !== factTuple.length) {
    return null;
  }

  // Work on a copy so we don't mutate the input
  let current = new Map(binding);

  for (let i = 0; i < atom.args.length; i++) {
    const term = atom.args[i];
    const value = factTuple[i];

    const result = unifyTerm(term, value, current);
    if (result === null) {
      return null;
    }
    current = result;
  }

  return current;
}

/**
 * Unify a single term against a concrete value.
 * Returns updated binding on success, null on failure.
 */
function unifyTerm(
  term: Term,
  value: string | number,
  binding: Binding,
): Binding | null {
  if (term.kind === 'constant') {
    // Constant must match exactly
    return term.value === value ? binding : null;
  }

  // Variable — check if already bound
  const existing = binding.get(term.name);
  if (existing !== undefined) {
    // Must match the existing binding
    return existing === value ? binding : null;
  }

  // Bind the variable
  const newBinding = new Map(binding);
  newBinding.set(term.name, value);
  return newBinding;
}

// ============================================================
// Comparison evaluation
// ============================================================

/**
 * Evaluate a comparison operator against bound term values.
 * Returns false if any term is unbound (which shouldn't happen
 * in safe Datalog, but we handle it defensively).
 */
function evaluateComparison(
  op: ComparisonOp,
  left: Term,
  right: Term,
  binding: Binding,
): boolean {
  const leftVal = resolveTerm(left, binding);
  const rightVal = resolveTerm(right, binding);

  if (leftVal === null || rightVal === null) {
    return false;
  }

  switch (op) {
    case '=':
      return leftVal === rightVal;
    case '!=':
      return leftVal !== rightVal;
    case '<':
      return leftVal < rightVal;
    case '>':
      return leftVal > rightVal;
    case '<=':
      return leftVal <= rightVal;
    case '>=':
      return leftVal >= rightVal;
  }
}

/**
 * Resolve a term to its concrete value using the current binding.
 * Returns null if a variable is unbound.
 */
function resolveTerm(
  term: Term,
  binding: Binding,
): string | number | null {
  if (term.kind === 'constant') {
    return term.value;
  }
  const val = binding.get(term.name);
  return val !== undefined ? val : null;
}

// ============================================================
// Head instantiation
// ============================================================

/**
 * Instantiate a rule head with the given binding,
 * producing a concrete tuple.
 */
function instantiateHead(head: Atom, binding: Binding): Tuple {
  return head.args.map((term) => {
    if (term.kind === 'constant') {
      return term.value;
    }
    const val = binding.get(term.name);
    if (val === undefined) {
      // This shouldn't happen in a safe Datalog program
      return term.name;
    }
    return val;
  });
}

// ============================================================
// Query evaluation
// ============================================================

/**
 * Evaluate a query atom against the final fact database.
 * Returns matching tuples and the column names (variable names in the query).
 */
function evaluateQuery(atom: Atom, db: FactDB): QueryAnswer {
  // Extract column names (variable names in query)
  const columns: string[] = [];
  for (const arg of atom.args) {
    if (arg.kind === 'variable') {
      columns.push(arg.name);
    }
  }

  // Find matching tuples
  const facts = db.get(atom.predicate);
  const tuples: Tuple[] = [];
  const seen = new Set<string>();

  for (const factTuple of facts) {
    const binding = unifyAtom(atom, factTuple, new Map());
    if (binding !== null) {
      // For the result, return the full fact tuple (not just bound vars)
      const key = serializeTuple(factTuple);
      if (!seen.has(key)) {
        seen.add(key);
        tuples.push(factTuple);
      }
    }
  }

  return {
    query: atom,
    tuples,
    columns,
  };
}

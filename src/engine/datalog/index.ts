/**
 * sonobat — Datalog inference engine public API
 *
 * Provides three main functions:
 * - listFacts: Show database contents as Datalog facts
 * - runDatalog: Execute a custom Datalog program against the database
 * - queryAttackPaths: Run a preset attack pattern analysis
 */

import type Database from 'better-sqlite3';
import type { EvalConfig, EvalResult, Fact } from './types.js';
import { parse } from './parser.js';
import { evaluate } from './evaluator.js';
import { extractFacts, extractFactsByPredicate } from './fact-extractor.js';
import { getPresetRule, getPresetRules } from './preset-rules.js';
import type { PresetRule } from './preset-rules.js';
import { DatalogRuleRepository } from '../../db/repository/datalog-rule-repository.js';

export type { PresetRule };

/**
 * List facts from the database, optionally filtered by predicate.
 */
export function listFacts(db: Database.Database, predicate?: string, limit?: number): Fact[] {
  if (predicate !== undefined) {
    return extractFactsByPredicate(db, predicate, limit);
  }
  const facts = extractFacts(db);
  if (limit !== undefined && limit > 0) {
    return facts.slice(0, limit);
  }
  return facts;
}

/**
 * Run a custom Datalog program against the database.
 * Optionally save the program as a named rule for future reuse.
 */
export function runDatalog(
  db: Database.Database,
  program: string,
  options?: {
    config?: Partial<EvalConfig>;
    saveName?: string;
    saveDescription?: string;
    generatedBy?: 'human' | 'ai';
  },
): EvalResult {
  const ast = parse(program);
  const facts = extractFacts(db);
  const result = evaluate(ast, facts, options?.config);

  // Optionally save the rule
  if (options?.saveName !== undefined) {
    const ruleRepo = new DatalogRuleRepository(db);
    ruleRepo.create({
      name: options.saveName,
      description: options.saveDescription,
      ruleText: program,
      generatedBy: options.generatedBy ?? 'ai',
    });
  }

  return result;
}

/**
 * Run a preset or saved attack pattern query.
 */
export function queryAttackPaths(
  db: Database.Database,
  pattern: string,
  config?: Partial<EvalConfig>,
): EvalResult {
  // Try preset rules first
  const preset = getPresetRule(pattern);
  if (preset !== undefined) {
    const ast = parse(preset.ruleText);
    const facts = extractFacts(db);
    return evaluate(ast, facts, config);
  }

  // Then try saved rules from DB
  const ruleRepo = new DatalogRuleRepository(db);
  const savedRule = ruleRepo.findByName(pattern);
  if (savedRule !== undefined) {
    const ast = parse(savedRule.ruleText);
    const facts = extractFacts(db);
    return evaluate(ast, facts, config);
  }

  // Return empty result if pattern not found
  return {
    answers: [],
    stats: { iterations: 0, totalDerived: 0, elapsedMs: 0 },
  };
}

/**
 * List all available patterns (presets + saved rules).
 */
export function listPatterns(db: Database.Database): Array<{
  name: string;
  description?: string;
  source: 'preset' | 'saved';
  generatedBy?: string;
}> {
  const presets = getPresetRules().map((p) => ({
    name: p.name,
    description: p.description,
    source: 'preset' as const,
  }));

  const ruleRepo = new DatalogRuleRepository(db);
  const saved = ruleRepo.findAll().map((r) => ({
    name: r.name,
    description: r.description,
    source: 'saved' as const,
    generatedBy: r.generatedBy,
  }));

  return [...presets, ...saved];
}

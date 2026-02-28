import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { DatalogRule, CreateDatalogRuleInput } from '../../engine/datalog/types.js';

/**
 * Raw row shape returned by better-sqlite3 for the `datalog_rules` table.
 */
interface DatalogRuleRow {
  id: string;
  name: string;
  description: string | null;
  rule_text: string;
  generated_by: string;
  is_preset: number;
  created_at: string;
  updated_at: string;
}

/** Maps a snake_case DB row to a camelCase DatalogRule entity. */
function rowToDatalogRule(row: DatalogRuleRow): DatalogRule {
  return {
    id: row.id,
    name: row.name,
    description: row.description ?? undefined,
    ruleText: row.rule_text,
    generatedBy: row.generated_by as DatalogRule['generatedBy'],
    isPreset: row.is_preset === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

/**
 * Repository for the `datalog_rules` table.
 */
export class DatalogRuleRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /** Insert a new DatalogRule and return the full entity. */
  create(input: CreateDatalogRuleInput): DatalogRule {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const stmt = this.db.prepare<
      [string, string, string | null, string, string, number, string, string]
    >(
      `INSERT INTO datalog_rules (id, name, description, rule_text, generated_by, is_preset, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    stmt.run(
      id,
      input.name,
      input.description ?? null,
      input.ruleText,
      input.generatedBy,
      input.isPreset ? 1 : 0,
      now,
      now,
    );

    return {
      id,
      name: input.name,
      description: input.description,
      ruleText: input.ruleText,
      generatedBy: input.generatedBy,
      isPreset: input.isPreset ?? false,
      createdAt: now,
      updatedAt: now,
    };
  }

  /** Find a DatalogRule by its primary key. */
  findById(id: string): DatalogRule | undefined {
    const stmt = this.db.prepare<[string], DatalogRuleRow>(
      `SELECT id, name, description, rule_text, generated_by, is_preset, created_at, updated_at
       FROM datalog_rules WHERE id = ?`,
    );
    const row = stmt.get(id);
    return row ? rowToDatalogRule(row) : undefined;
  }

  /** Find a DatalogRule by name. */
  findByName(name: string): DatalogRule | undefined {
    const stmt = this.db.prepare<[string], DatalogRuleRow>(
      `SELECT id, name, description, rule_text, generated_by, is_preset, created_at, updated_at
       FROM datalog_rules WHERE name = ?`,
    );
    const row = stmt.get(name);
    return row ? rowToDatalogRule(row) : undefined;
  }

  /** Return all DatalogRules. */
  findAll(): DatalogRule[] {
    const stmt = this.db.prepare<[], DatalogRuleRow>(
      `SELECT id, name, description, rule_text, generated_by, is_preset, created_at, updated_at
       FROM datalog_rules ORDER BY created_at`,
    );
    return stmt.all().map(rowToDatalogRule);
  }

  /** Delete a DatalogRule by id. Returns true if a row was deleted. */
  delete(id: string): boolean {
    const stmt = this.db.prepare<[string]>('DELETE FROM datalog_rules WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }
}

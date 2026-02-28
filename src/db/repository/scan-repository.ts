import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type { Scan } from '../../types/entities.js';
import type { CreateScanInput } from '../../types/repository.js';

/** Row shape returned by better-sqlite3 for the scans table. */
interface ScanRow {
  id: string;
  started_at: string;
  finished_at: string | null;
  notes: string | null;
}

/** Maps a snake_case DB row to a camelCase Scan entity. */
function rowToScan(row: ScanRow): Scan {
  return {
    id: row.id,
    startedAt: row.started_at,
    ...(row.finished_at !== null ? { finishedAt: row.finished_at } : {}),
    ...(row.notes !== null ? { notes: row.notes } : {}),
  };
}

/**
 * Repository for the `scans` table.
 *
 * Provides CRUD operations with camelCase ↔ snake_case mapping
 * between the TypeScript entity layer and the SQLite storage layer.
 */
export class ScanRepository {
  private readonly db: Database.Database;

  private readonly insertStmt: Database.Statement;
  private readonly selectByIdStmt: Database.Statement;
  private readonly selectAllStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertStmt = this.db.prepare(
      'INSERT INTO scans (id, started_at, finished_at, notes) VALUES (?, ?, ?, ?)',
    );

    this.selectByIdStmt = this.db.prepare(
      'SELECT id, started_at, finished_at, notes FROM scans WHERE id = ?',
    );

    this.selectAllStmt = this.db.prepare('SELECT id, started_at, finished_at, notes FROM scans');
  }

  /** Create a new Scan record and return the full entity. */
  create(input: CreateScanInput): Scan {
    const id = crypto.randomUUID();

    this.insertStmt.run(id, input.startedAt, input.finishedAt ?? null, input.notes ?? null);

    return {
      id,
      startedAt: input.startedAt,
      ...(input.finishedAt !== undefined ? { finishedAt: input.finishedAt } : {}),
      ...(input.notes !== undefined ? { notes: input.notes } : {}),
    };
  }

  /** Find a Scan by its UUID. Returns undefined if not found. */
  findById(id: string): Scan | undefined {
    const row = this.selectByIdStmt.get(id) as ScanRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToScan(row);
  }

  /** Return all Scan records. */
  findAll(): Scan[] {
    const rows = this.selectAllStmt.all() as ScanRow[];
    return rows.map(rowToScan);
  }
}

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';

/** Technique documentation entity (camelCase). */
export interface TechniqueDoc {
  id: string;
  source: string;
  filePath: string;
  title: string;
  category: string;
  content: string;
  chunkIndex: number;
  indexedAt: string;
}

/** Input for creating a new technique document (no id/indexedAt). */
export interface CreateTechniqueDocInput {
  source: string;
  filePath: string;
  title: string;
  category: string;
  content: string;
  chunkIndex: number;
}

/**
 * Raw row shape returned by better-sqlite3 for the `technique_docs` table.
 */
interface TechniqueDocRow {
  id: string;
  source: string;
  file_path: string;
  title: string;
  category: string;
  content: string;
  chunk_index: number;
  indexed_at: string;
}

/**
 * Row shape for FTS5 search results with rank score.
 */
interface TechniqueDocSearchRow extends TechniqueDocRow {
  rank: number;
}

/** Maps a snake_case DB row to a camelCase TechniqueDoc entity. */
function rowToTechniqueDoc(row: TechniqueDocRow): TechniqueDoc {
  return {
    id: row.id,
    source: row.source,
    filePath: row.file_path,
    title: row.title,
    category: row.category,
    content: row.content,
    chunkIndex: row.chunk_index,
    indexedAt: row.indexed_at,
  };
}

/** TechniqueDoc with search relevance score. */
export interface TechniqueDocSearchResult extends TechniqueDoc {
  score: number;
}

/** Options for FTS5 search. */
export interface SearchOptions {
  limit?: number;
  category?: string;
}

const BATCH_SIZE = 100;

/**
 * Repository for the `technique_docs` table with FTS5 full-text search.
 *
 * All queries use prepared statements to prevent SQL injection.
 */
export class TechniqueDocRepository {
  private readonly db: Database.Database;

  constructor(db: Database.Database) {
    this.db = db;
  }

  /**
   * Bulk-insert technique documents. Runs in batches within transactions.
   * Returns the number of inserted documents.
   */
  index(docs: CreateTechniqueDocInput[]): number {
    if (docs.length === 0) return 0;

    const now = new Date().toISOString();
    const stmt = this.db.prepare(
      `INSERT INTO technique_docs (id, source, file_path, title, category, content, chunk_index, indexed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    let inserted = 0;

    for (let i = 0; i < docs.length; i += BATCH_SIZE) {
      const batch = docs.slice(i, i + BATCH_SIZE);
      const insertBatch = this.db.transaction(() => {
        for (const doc of batch) {
          const id = crypto.randomUUID();
          stmt.run(
            id,
            doc.source,
            doc.filePath,
            doc.title,
            doc.category,
            doc.content,
            doc.chunkIndex,
            now,
          );
          inserted++;
        }
      });
      insertBatch();
    }

    return inserted;
  }

  /**
   * Full-text search using FTS5 BM25 ranking.
   * User input is wrapped in double quotes for literal matching to prevent FTS5 syntax errors.
   */
  search(query: string, options: SearchOptions = {}): TechniqueDocSearchResult[] {
    const { limit = 20, category } = options;

    // Split query into individual terms, wrap each in double quotes for safety,
    // and join with spaces (FTS5 implicit AND). This prevents FTS5 syntax errors
    // while allowing flexible multi-word matching.
    const terms = query
      .trim()
      .split(/\s+/)
      .filter((t) => t.length > 0);
    const safeQuery = terms.map((t) => `"${t.replace(/"/g, '""')}"`).join(' ');

    let sql: string;
    const params: unknown[] = [safeQuery];

    if (category) {
      sql = `SELECT td.*, fts.rank
             FROM technique_docs td
             JOIN technique_docs_fts fts ON td.rowid = fts.rowid
             WHERE technique_docs_fts MATCH ?
               AND td.category = ?
             ORDER BY fts.rank
             LIMIT ?`;
      params.push(category, limit);
    } else {
      sql = `SELECT td.*, fts.rank
             FROM technique_docs td
             JOIN technique_docs_fts fts ON td.rowid = fts.rowid
             WHERE technique_docs_fts MATCH ?
             ORDER BY fts.rank
             LIMIT ?`;
      params.push(limit);
    }

    const rows = this.db.prepare(sql).all(...params) as TechniqueDocSearchRow[];

    return rows.map((row) => ({
      ...rowToTechniqueDoc(row),
      score: row.rank * -1,
    }));
  }

  /** Return all unique categories. */
  listCategories(): string[] {
    const rows = this.db
      .prepare('SELECT DISTINCT category FROM technique_docs ORDER BY category')
      .all() as Array<{ category: string }>;
    return rows.map((r) => r.category);
  }

  /** Return all documents in a given category. */
  findByCategory(category: string): TechniqueDoc[] {
    const rows = this.db
      .prepare<[string], TechniqueDocRow>(
        `SELECT id, source, file_path, title, category, content, chunk_index, indexed_at
         FROM technique_docs
         WHERE category = ?
         ORDER BY file_path, chunk_index`,
      )
      .all(category);
    return rows.map(rowToTechniqueDoc);
  }

  /**
   * Delete all documents from a given source.
   * Returns the number of deleted documents.
   */
  deleteBySource(source: string): number {
    const result = this.db.prepare('DELETE FROM technique_docs WHERE source = ?').run(source);
    return result.changes;
  }

  /** Return the total number of indexed documents. */
  count(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS cnt FROM technique_docs').get() as {
      cnt: number;
    };
    return row.cnt;
  }
}

/**
 * sonobat — FindingRepository
 *
 * findings + finding_events テーブルに対する CRUD 操作。
 * 親子関係が強いため、一つの Repository で管理する。
 */

import type Database from 'better-sqlite3';
import crypto from 'node:crypto';
import type {
  Finding,
  UpsertFindingInput,
  FindingEvent,
  CreateFindingEventInput,
} from '../../types/operational.js';

// ---------------------------------------------------------------------------
// DB row 型
// ---------------------------------------------------------------------------

/** better-sqlite3 から返る findings テーブルの行形状 */
interface FindingRow {
  id: string;
  engagement_id: string;
  canonical_key: string;
  node_id: string | null;
  title: string;
  severity: string;
  confidence: string;
  state: string;
  state_reason: string | null;
  owner: string | null;
  ticket_ref: string | null;
  first_seen_run_id: string | null;
  last_seen_run_id: string | null;
  first_seen_at: string;
  last_seen_at: string;
  sla_due_at: string | null;
  attrs_json: string;
}

/** better-sqlite3 から返る finding_events テーブルの行形状 */
interface FindingEventRow {
  id: string;
  finding_id: string;
  run_id: string | null;
  event_type: string;
  before_json: string;
  after_json: string;
  artifact_id: string | null;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Row → Entity 変換
// ---------------------------------------------------------------------------

/** snake_case DB row を camelCase Finding にマッピング */
function rowToFinding(row: FindingRow): Finding {
  return {
    id: row.id,
    engagementId: row.engagement_id,
    canonicalKey: row.canonical_key,
    ...(row.node_id !== null ? { nodeId: row.node_id } : {}),
    title: row.title,
    severity: row.severity,
    confidence: row.confidence,
    state: row.state,
    ...(row.state_reason !== null ? { stateReason: row.state_reason } : {}),
    ...(row.owner !== null ? { owner: row.owner } : {}),
    ...(row.ticket_ref !== null ? { ticketRef: row.ticket_ref } : {}),
    ...(row.first_seen_run_id !== null ? { firstSeenRunId: row.first_seen_run_id } : {}),
    ...(row.last_seen_run_id !== null ? { lastSeenRunId: row.last_seen_run_id } : {}),
    firstSeenAt: row.first_seen_at,
    lastSeenAt: row.last_seen_at,
    ...(row.sla_due_at !== null ? { slaDueAt: row.sla_due_at } : {}),
    attrsJson: row.attrs_json,
  };
}

/** snake_case DB row を camelCase FindingEvent にマッピング */
function rowToFindingEvent(row: FindingEventRow): FindingEvent {
  return {
    id: row.id,
    findingId: row.finding_id,
    ...(row.run_id !== null ? { runId: row.run_id } : {}),
    eventType: row.event_type,
    beforeJson: row.before_json,
    afterJson: row.after_json,
    ...(row.artifact_id !== null ? { artifactId: row.artifact_id } : {}),
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// FindingRepository
// ---------------------------------------------------------------------------

/**
 * findings + finding_events テーブルの CRUD リポジトリ。
 *
 * - upsert() は engagement_id + canonical_key の UNIQUE 制約を活用
 * - finding_events は Finding のライフサイクルイベントを記録
 * - ID は crypto.randomUUID() で生成
 */
export class FindingRepository {
  private readonly db: Database.Database;

  private readonly insertFindingStmt: Database.Statement;
  private readonly selectFindingByIdStmt: Database.Statement;
  private readonly deleteFindingStmt: Database.Statement;
  private readonly updateLastSeenStmt: Database.Statement;
  private readonly updateStateStmt: Database.Statement;
  private readonly insertEventStmt: Database.Statement;
  private readonly selectEventsByFindingStmt: Database.Statement;

  constructor(db: Database.Database) {
    this.db = db;

    this.insertFindingStmt = this.db.prepare(
      `INSERT INTO findings
         (id, engagement_id, canonical_key, node_id, title, severity, confidence,
          state, state_reason, owner, ticket_ref,
          first_seen_run_id, last_seen_run_id, first_seen_at, last_seen_at,
          sla_due_at, attrs_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    this.selectFindingByIdStmt = this.db.prepare(
      `SELECT id, engagement_id, canonical_key, node_id, title, severity, confidence,
              state, state_reason, owner, ticket_ref,
              first_seen_run_id, last_seen_run_id, first_seen_at, last_seen_at,
              sla_due_at, attrs_json
       FROM findings WHERE id = ?`,
    );

    this.deleteFindingStmt = this.db.prepare(`DELETE FROM findings WHERE id = ?`);

    this.updateLastSeenStmt = this.db.prepare(
      `UPDATE findings
       SET last_seen_at = ?, last_seen_run_id = ?,
           title = ?, severity = ?, confidence = ?, attrs_json = ?
       WHERE id = ?`,
    );

    this.updateStateStmt = this.db.prepare(
      `UPDATE findings SET state = ?, state_reason = ? WHERE id = ?`,
    );

    this.insertEventStmt = this.db.prepare(
      `INSERT INTO finding_events
         (id, finding_id, run_id, event_type, before_json, after_json, artifact_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    );

    this.selectEventsByFindingStmt = this.db.prepare(
      `SELECT id, finding_id, run_id, event_type, before_json, after_json, artifact_id, created_at
       FROM finding_events
       WHERE finding_id = ?
       ORDER BY created_at DESC`,
    );
  }

  /**
   * Finding を upsert する。
   *
   * engagement_id + canonical_key が一致する既存レコードがあれば更新（re_observed）、
   * なければ新規作成（discovered）。いずれの場合も finding_events にイベントを追加する。
   *
   * @returns { finding, created } — created は新規作成時 true、既存更新時 false
   */
  upsert(input: UpsertFindingInput): { finding: Finding; created: boolean } {
    const upsertTx = this.db.transaction((inp: UpsertFindingInput) => {
      const now = new Date().toISOString();
      const existing = this.db
        .prepare('SELECT * FROM findings WHERE engagement_id = ? AND canonical_key = ?')
        .get(inp.engagementId, inp.canonicalKey) as FindingRow | undefined;

      if (existing) {
        // 既存 Finding を更新
        this.updateLastSeenStmt.run(
          now,
          inp.runId ?? null,
          inp.title,
          inp.severity,
          inp.confidence,
          inp.attrsJson ?? existing.attrs_json,
          existing.id,
        );

        // re_observed イベントを追加
        this.insertEventStmt.run(
          crypto.randomUUID(),
          existing.id,
          inp.runId ?? null,
          're_observed',
          '{}',
          '{}',
          null,
          now,
        );

        const updated = this.findById(existing.id);
        if (updated === undefined) {
          throw new Error(`Finding ${existing.id} not found after update`);
        }
        return { finding: updated, created: false };
      } else {
        // 新規 Finding を作成
        const id = crypto.randomUUID();
        this.insertFindingStmt.run(
          id,
          inp.engagementId,
          inp.canonicalKey,
          inp.nodeId ?? null,
          inp.title,
          inp.severity,
          inp.confidence,
          inp.state ?? 'open',
          null, // state_reason
          null, // owner
          null, // ticket_ref
          inp.runId ?? null, // first_seen_run_id
          inp.runId ?? null, // last_seen_run_id
          now, // first_seen_at
          now, // last_seen_at
          null, // sla_due_at
          inp.attrsJson ?? '{}',
        );

        // discovered イベントを追加
        this.insertEventStmt.run(
          crypto.randomUUID(),
          id,
          inp.runId ?? null,
          'discovered',
          '{}',
          '{}',
          null,
          now,
        );

        const created = this.findById(id);
        if (created === undefined) {
          throw new Error(`Finding ${id} not found after insert`);
        }
        return { finding: created, created: true };
      }
    });

    return upsertTx(input);
  }

  /**
   * ID で Finding を取得する。存在しなければ undefined。
   */
  findById(id: string): Finding | undefined {
    const row = this.selectFindingByIdStmt.get(id) as FindingRow | undefined;
    if (row === undefined) {
      return undefined;
    }
    return rowToFinding(row);
  }

  /**
   * エンゲージメント ID で Finding 一覧を取得する。
   *
   * opts で state, severity を指定して絞り込み可能。
   * ORDER BY last_seen_at DESC。
   */
  findByEngagement(
    engagementId: string,
    opts?: { state?: string; severity?: string },
  ): Finding[] {
    const whereClauses: string[] = ['engagement_id = ?'];
    const params: unknown[] = [engagementId];

    if (opts?.state !== undefined) {
      whereClauses.push('state = ?');
      params.push(opts.state);
    }

    if (opts?.severity !== undefined) {
      whereClauses.push('severity = ?');
      params.push(opts.severity);
    }

    const sql = `SELECT id, engagement_id, canonical_key, node_id, title, severity, confidence,
                        state, state_reason, owner, ticket_ref,
                        first_seen_run_id, last_seen_run_id, first_seen_at, last_seen_at,
                        sla_due_at, attrs_json
                 FROM findings
                 WHERE ${whereClauses.join(' AND ')}
                 ORDER BY last_seen_at DESC`;

    const rows = this.db.prepare(sql).all(...params) as FindingRow[];
    return rows.map(rowToFinding);
  }

  /**
   * Finding の状態を更新する。
   *
   * state と state_reason を更新し、'state_change' イベントを自動追加する。
   * 存在しない ID の場合 undefined を返す。
   */
  updateState(id: string, state: string, reason?: string): Finding | undefined {
    const updateStateTx = this.db.transaction(
      (findingId: string, newState: string, stateReason?: string) => {
        // 既存 Finding を取得
        const existing = this.findById(findingId);
        if (existing === undefined) {
          return undefined;
        }

        const oldState = existing.state;

        // state と state_reason を更新
        this.updateStateStmt.run(newState, stateReason ?? null, findingId);

        // state_change イベントを追加
        const now = new Date().toISOString();
        this.insertEventStmt.run(
          crypto.randomUUID(),
          findingId,
          null, // run_id
          'state_change',
          JSON.stringify({ state: oldState }),
          JSON.stringify({ state: newState }),
          null, // artifact_id
          now,
        );

        return this.findById(findingId);
      },
    );

    return updateStateTx(id, state, reason);
  }

  /**
   * Finding にイベントを手動追加する。
   */
  addEvent(findingId: string, event: CreateFindingEventInput): FindingEvent {
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    this.insertEventStmt.run(
      id,
      findingId,
      event.runId ?? null,
      event.eventType,
      event.beforeJson ?? '{}',
      event.afterJson ?? '{}',
      event.artifactId ?? null,
      now,
    );

    return {
      id,
      findingId,
      ...(event.runId !== undefined ? { runId: event.runId } : {}),
      eventType: event.eventType,
      beforeJson: event.beforeJson ?? '{}',
      afterJson: event.afterJson ?? '{}',
      ...(event.artifactId !== undefined ? { artifactId: event.artifactId } : {}),
      createdAt: now,
    };
  }

  /**
   * Finding のイベント一覧を取得する。
   *
   * ORDER BY created_at DESC（最新が先頭）。
   */
  getEvents(findingId: string): FindingEvent[] {
    const rows = this.selectEventsByFindingStmt.all(findingId) as FindingEventRow[];
    return rows.map(rowToFindingEvent);
  }

  /**
   * Finding を削除する。
   *
   * CASCADE により関連する finding_events も同時に削除される。
   *
   * @returns 削除成功時 true、id が存在しない場合 false。
   */
  delete(id: string): boolean {
    const result = this.deleteFindingStmt.run(id);
    return result.changes > 0;
  }
}

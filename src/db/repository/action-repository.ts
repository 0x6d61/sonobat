import { randomUUID } from 'node:crypto';
import type Database from 'better-sqlite3';

export interface Action {
  id: string;
  engagementId: string;
  missionId?: string;
  parentActionId?: string;
  kind: string;
  priority: number;
  dedupeKey: string;
  params: Record<string, unknown>;
  state: string;
  attemptCount: number;
  maxAttempts: number;
  availableAt: string;
  leaseOwner?: string;
  leaseExpiresAt?: string;
  lastError?: string;
  createdAt: string;
  updatedAt: string;
}

interface ActionRow {
  id: string;
  engagement_id: string;
  mission_id: string | null;
  parent_action_id: string | null;
  kind: string;
  priority: number;
  dedupe_key: string;
  params_json: string;
  state: string;
  attempt_count: number;
  max_attempts: number;
  available_at: string;
  lease_owner: string | null;
  lease_expires_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
}

function fromRow(row: ActionRow): Action {
  return {
    id: row.id,
    engagementId: row.engagement_id,
    ...(row.mission_id === null ? {} : { missionId: row.mission_id }),
    ...(row.parent_action_id === null ? {} : { parentActionId: row.parent_action_id }),
    kind: row.kind,
    priority: row.priority,
    dedupeKey: row.dedupe_key,
    params: JSON.parse(row.params_json) as Record<string, unknown>,
    state: row.state,
    attemptCount: row.attempt_count,
    maxAttempts: row.max_attempts,
    availableAt: row.available_at,
    ...(row.lease_owner === null ? {} : { leaseOwner: row.lease_owner }),
    ...(row.lease_expires_at === null ? {} : { leaseExpiresAt: row.lease_expires_at }),
    ...(row.last_error === null ? {} : { lastError: row.last_error }),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class ActionRepository {
  constructor(private readonly db: Database.Database) {}

  create(input: {
    engagementId: string;
    missionId?: string;
    parentActionId?: string;
    kind: string;
    dedupeKey: string;
    params?: Record<string, unknown>;
    priority?: number;
    state?: 'queued' | 'proposed';
    maxAttempts?: number;
  }): Action {
    if (input.kind.trim() === '' || input.dedupeKey.trim() === '') {
      throw new Error('kind and dedupeKey must not be empty');
    }
    const parent = input.parentActionId ? this.findById(input.parentActionId) : undefined;
    if (input.parentActionId !== undefined && parent === undefined) {
      throw new Error(`Parent action not found: ${input.parentActionId}`);
    }
    const engagementId = parent?.engagementId ?? input.engagementId;
    const missionId = parent?.missionId ?? input.missionId;
    if (parent !== undefined && input.engagementId !== parent.engagementId) {
      throw new Error('Child action must inherit the parent engagement');
    }
    if (parent !== undefined && input.missionId !== undefined && input.missionId !== missionId) {
      throw new Error('Child action must inherit the parent mission');
    }
    const id = randomUUID();
    const now = new Date().toISOString();
    this.db
      .prepare(
        `INSERT INTO actions
         (id, engagement_id, mission_id, parent_action_id, kind, priority, dedupe_key,
          params_json, state, attempt_count, max_attempts, available_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)`,
      )
      .run(
        id,
        engagementId,
        missionId ?? null,
        input.parentActionId ?? null,
        input.kind,
        input.priority ?? 100,
        input.dedupeKey,
        JSON.stringify(input.params ?? {}),
        input.state ?? 'queued',
        input.maxAttempts ?? 3,
        now,
        now,
        now,
      );
    return this.findById(id)!;
  }

  findById(id: string): Action | undefined {
    const row = this.db.prepare('SELECT * FROM actions WHERE id = ?').get(id) as
      | ActionRow
      | undefined;
    return row === undefined ? undefined : fromRow(row);
  }

  list(missionId?: string): Action[] {
    const rows = (
      missionId === undefined
        ? this.db.prepare('SELECT * FROM actions ORDER BY created_at').all()
        : this.db
            .prepare('SELECT * FROM actions WHERE mission_id = ? ORDER BY created_at')
            .all(missionId)
    ) as ActionRow[];
    return rows.map(fromRow);
  }

  adopt(id: string): Action | undefined {
    const now = new Date().toISOString();
    this.db
      .prepare(
        "UPDATE actions SET state = 'queued', updated_at = ? WHERE id = ? AND state = 'proposed'",
      )
      .run(now, id);
    return this.findById(id);
  }

  poll(workerId: string, kinds: string[], leaseSeconds = 300): Action | undefined {
    if (workerId.trim() === '' || kinds.length === 0)
      throw new Error('workerId and kinds are required');
    const now = new Date();
    const expires = new Date(now.getTime() + leaseSeconds * 1000).toISOString();
    const placeholders = kinds.map(() => '?').join(', ');
    const poll = this.db.transaction(() => {
      this.db
        .prepare(
          `UPDATE actions SET state = 'queued', lease_owner = NULL, lease_expires_at = NULL,
           updated_at = ? WHERE state = 'running' AND lease_expires_at <= ?`,
        )
        .run(now.toISOString(), now.toISOString());
      const row = this.db
        .prepare(
          `SELECT id FROM actions WHERE state = 'queued' AND available_at <= ?
           AND attempt_count < max_attempts AND kind IN (${placeholders})
           ORDER BY priority, created_at LIMIT 1`,
        )
        .get(now.toISOString(), ...kinds) as { id: string } | undefined;
      if (row === undefined) return undefined;
      this.db
        .prepare(
          `UPDATE actions SET state = 'running', lease_owner = ?, lease_expires_at = ?,
           attempt_count = attempt_count + 1, updated_at = ? WHERE id = ? AND state = 'queued'`,
        )
        .run(workerId, expires, now.toISOString(), row.id);
      return this.findById(row.id);
    });
    return poll();
  }

  renew(id: string, workerId: string, leaseSeconds = 300): Action | undefined {
    const expires = new Date(Date.now() + leaseSeconds * 1000).toISOString();
    const result = this.db
      .prepare(
        `UPDATE actions SET lease_expires_at = ?, updated_at = ?
         WHERE id = ? AND state = 'running' AND lease_owner = ?`,
      )
      .run(expires, new Date().toISOString(), id, workerId);
    return result.changes === 1 ? this.findById(id) : undefined;
  }

  finish(id: string, workerId: string, state: 'completed' | 'failed', error?: string): Action {
    const result = this.db
      .prepare(
        `UPDATE actions SET state = ?, last_error = ?, lease_owner = NULL,
         lease_expires_at = NULL, updated_at = ?
         WHERE id = ? AND state = 'running' AND lease_owner = ?`,
      )
      .run(state, error ?? null, new Date().toISOString(), id, workerId);
    if (result.changes !== 1) throw new Error('Action lease is not owned by this worker');
    return this.findById(id)!;
  }
}

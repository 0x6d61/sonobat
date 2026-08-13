import type Database from 'better-sqlite3';
import { EngagementScopeSchema, type TargetRef } from '../../types/mission.js';

export class TargetValidator {
  constructor(private readonly db: Database.Database) {}

  validate(engagementId: string, targets: TargetRef[]): void {
    const engagement = this.db
      .prepare('SELECT scope_json FROM engagements WHERE id = ?')
      .get(engagementId) as { scope_json: string } | undefined;
    if (engagement === undefined) throw new Error(`Engagement not found: ${engagementId}`);
    const scope = EngagementScopeSchema.parse(JSON.parse(engagement.scope_json));
    for (const target of targets) {
      if (target.type === 'finding') {
        const row = this.db
          .prepare('SELECT engagement_id FROM findings WHERE id = ?')
          .get(target.id) as { engagement_id: string } | undefined;
        if (row === undefined) throw new Error(`Finding target not found: ${target.id}`);
        if (row.engagement_id !== engagementId)
          throw new Error('Finding target is outside engagement');
      } else if (target.type === 'action') {
        const row = this.db
          .prepare('SELECT engagement_id FROM action_queue WHERE id = ?')
          .get(target.id) as { engagement_id: string } | undefined;
        if (row === undefined) throw new Error(`Action target not found: ${target.id}`);
        if (row.engagement_id !== engagementId)
          throw new Error('Action target is outside engagement');
      } else {
        this.validateNode(target.id, scope.nodeIds, scope.hostAuthorities);
      }
    }
  }

  private validateNode(id: string, nodeIds?: string[], hostAuthorities?: string[]): void {
    const node = this.db.prepare('SELECT id, kind, props_json FROM nodes WHERE id = ?').get(id) as
      | { id: string; kind: string; props_json: string }
      | undefined;
    if (node === undefined) throw new Error(`Node target not found: ${id}`);
    if (nodeIds !== undefined && !this.isReachableFrom(id, nodeIds)) {
      throw new Error(`Node target is outside engagement scope: ${id}`);
    }
    if (hostAuthorities !== undefined) {
      const authorityRows = this.db
        .prepare(
          `WITH RECURSIVE ancestors(id) AS (
             SELECT ? UNION
             SELECT e.source_id FROM edges e JOIN ancestors a ON e.target_id = a.id
           )
           SELECT props_json FROM nodes WHERE id IN ancestors AND kind = 'host'`,
        )
        .all(id) as Array<{ props_json: string }>;
      const matches = authorityRows.some((row) => {
        const props = JSON.parse(row.props_json) as { authority?: string };
        return props.authority !== undefined && hostAuthorities.includes(props.authority);
      });
      if (!matches) throw new Error(`Node target is outside engagement host scope: ${id}`);
    }
  }

  private isReachableFrom(targetId: string, scopeNodeIds: string[]): boolean {
    if (scopeNodeIds.includes(targetId)) return true;
    if (scopeNodeIds.length === 0) return false;
    const row = this.db
      .prepare(
        `WITH RECURSIVE reachable(id) AS (
           SELECT id FROM nodes WHERE id IN (${scopeNodeIds.map(() => '?').join(', ')})
           UNION SELECT e.target_id FROM edges e JOIN reachable r ON e.source_id = r.id
         ) SELECT 1 ok FROM reachable WHERE id = ? LIMIT 1`,
      )
      .get(...scopeNodeIds, targetId) as { ok: number } | undefined;
    return row !== undefined;
  }
}

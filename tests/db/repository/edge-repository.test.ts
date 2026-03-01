import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { EdgeRepository } from '../../../src/db/repository/edge-repository.js';
import type { GraphEdge } from '../../../src/types/graph.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

function createTestDb(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  return db;
}

function insertTestNode(
  db: InstanceType<typeof Database>,
  kind: string,
  naturalKey: string,
  props: string = '{}',
): string {
  const id = crypto.randomUUID();
  const ts = new Date().toISOString();
  db.prepare(
    'INSERT INTO nodes (id, kind, natural_key, props_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(id, kind, naturalKey, props, ts, ts);
  return id;
}

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('EdgeRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: EdgeRepository;
  let hostNodeId: string;
  let serviceNodeId: string;
  let endpointNodeId: string;

  beforeEach(() => {
    db = createTestDb();
    repo = new EdgeRepository(db);

    // テスト用ノードを作成
    hostNodeId = insertTestNode(db, 'host', 'host:192.168.1.1');
    serviceNodeId = insertTestNode(db, 'service', 'svc:192.168.1.1:tcp:80');
    endpointNodeId = insertTestNode(db, 'endpoint', 'ep:svc1:GET:/index');
  });

  // -----------------------------------------------------------------------
  // create
  // -----------------------------------------------------------------------

  describe('create', () => {
    it('2つのノードを結ぶエッジを作成して返す', () => {
      const edge: GraphEdge = repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);

      expect(edge.id).toBeDefined();
      expect(edge.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(edge.kind).toBe('HOST_SERVICE');
      expect(edge.sourceId).toBe(hostNodeId);
      expect(edge.targetId).toBe(serviceNodeId);
      expect(edge.propsJson).toBe('{}');
      expect(edge.evidenceArtifactId).toBeUndefined();
      expect(edge.createdAt).toBeDefined();
    });

    it('propsJson を指定してエッジを作成できる', () => {
      const props = JSON.stringify({ weight: 1.0 });
      const edge = repo.create('HOST_SERVICE', hostNodeId, serviceNodeId, undefined, props);

      expect(edge.propsJson).toBe(props);
    });

    it('同じ (kind, sourceId, targetId) の重複作成は例外になる', () => {
      repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);

      expect(() => {
        repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);
      }).toThrow();
    });
  });

  // -----------------------------------------------------------------------
  // upsert
  // -----------------------------------------------------------------------

  describe('upsert', () => {
    it('新しいエッジの場合 created: true を返す', () => {
      const result = repo.upsert('HOST_SERVICE', hostNodeId, serviceNodeId);

      expect(result.created).toBe(true);
      expect(result.edge.kind).toBe('HOST_SERVICE');
      expect(result.edge.sourceId).toBe(hostNodeId);
      expect(result.edge.targetId).toBe(serviceNodeId);
      expect(result.edge.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
    });

    it('既存の (kind, sourceId, targetId) の場合 created: false を返す', () => {
      const first = repo.upsert('HOST_SERVICE', hostNodeId, serviceNodeId);
      const second = repo.upsert('HOST_SERVICE', hostNodeId, serviceNodeId);

      expect(second.created).toBe(false);
      expect(second.edge.id).toBe(first.edge.id);
      expect(second.edge.kind).toBe('HOST_SERVICE');
      expect(second.edge.sourceId).toBe(hostNodeId);
      expect(second.edge.targetId).toBe(serviceNodeId);
    });
  });

  // -----------------------------------------------------------------------
  // findBySource
  // -----------------------------------------------------------------------

  describe('findBySource', () => {
    it('指定ソースノードからのエッジを全件返す', () => {
      repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);
      repo.create('HOST_VHOST', hostNodeId, endpointNodeId);

      const edges = repo.findBySource(hostNodeId);

      expect(edges).toHaveLength(2);
      const kinds = edges.map((e) => e.kind);
      expect(kinds).toContain('HOST_SERVICE');
      expect(kinds).toContain('HOST_VHOST');
    });

    it('edgeKind でフィルタできる', () => {
      repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);
      repo.create('HOST_VHOST', hostNodeId, endpointNodeId);

      const edges = repo.findBySource(hostNodeId, 'HOST_SERVICE');

      expect(edges).toHaveLength(1);
      expect(edges[0].kind).toBe('HOST_SERVICE');
      expect(edges[0].sourceId).toBe(hostNodeId);
      expect(edges[0].targetId).toBe(serviceNodeId);
    });

    it('該当エッジがない場合は空配列を返す', () => {
      const edges = repo.findBySource(crypto.randomUUID());

      expect(edges).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // findByTarget
  // -----------------------------------------------------------------------

  describe('findByTarget', () => {
    it('指定ターゲットノードへのエッジを全件返す', () => {
      repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);
      repo.create('SERVICE_ENDPOINT', serviceNodeId, endpointNodeId);

      const edges = repo.findByTarget(serviceNodeId);

      expect(edges).toHaveLength(1);
      expect(edges[0].kind).toBe('HOST_SERVICE');
      expect(edges[0].targetId).toBe(serviceNodeId);
    });

    it('edgeKind でフィルタできる', () => {
      // serviceNodeId をターゲットにする 2 つの edge を作る
      const anotherHostId = insertTestNode(db, 'host', 'host:10.0.0.1');
      repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);
      repo.create('HOST_SERVICE', anotherHostId, serviceNodeId);

      // HOST_SERVICE でフィルタ
      const edges = repo.findByTarget(serviceNodeId, 'HOST_SERVICE');

      expect(edges).toHaveLength(2);
      edges.forEach((e) => {
        expect(e.kind).toBe('HOST_SERVICE');
        expect(e.targetId).toBe(serviceNodeId);
      });
    });

    it('該当エッジがない場合は空配列を返す', () => {
      const edges = repo.findByTarget(crypto.randomUUID());

      expect(edges).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // findByKind
  // -----------------------------------------------------------------------

  describe('findByKind', () => {
    it('指定した種類のエッジを全件返す', () => {
      repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);
      repo.create('SERVICE_ENDPOINT', serviceNodeId, endpointNodeId);

      const edges = repo.findByKind('HOST_SERVICE');

      expect(edges).toHaveLength(1);
      expect(edges[0].kind).toBe('HOST_SERVICE');
    });

    it('該当エッジがない場合は空配列を返す', () => {
      const edges = repo.findByKind('VULNERABILITY_CVE');

      expect(edges).toEqual([]);
    });
  });

  // -----------------------------------------------------------------------
  // delete
  // -----------------------------------------------------------------------

  describe('delete', () => {
    it('存在するエッジを削除して true を返す', () => {
      const edge = repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);

      const result = repo.delete(edge.id);

      expect(result).toBe(true);

      // 再度検索しても見つからないことを確認
      const edges = repo.findByKind('HOST_SERVICE');
      expect(edges).toHaveLength(0);
    });

    it('存在しないエッジの削除は false を返す', () => {
      const result = repo.delete(crypto.randomUUID());

      expect(result).toBe(false);
    });
  });

  // -----------------------------------------------------------------------
  // CASCADE 削除
  // -----------------------------------------------------------------------

  describe('CASCADE 削除', () => {
    it('ソースノードを削除すると関連エッジも削除される', () => {
      repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);

      // ソースノード (host) を削除
      db.prepare('DELETE FROM nodes WHERE id = ?').run(hostNodeId);

      const edges = repo.findByKind('HOST_SERVICE');
      expect(edges).toHaveLength(0);
    });

    it('ターゲットノードを削除すると関連エッジも削除される', () => {
      repo.create('HOST_SERVICE', hostNodeId, serviceNodeId);

      // ターゲットノード (service) を削除
      db.prepare('DELETE FROM nodes WHERE id = ?').run(serviceNodeId);

      const edges = repo.findByKind('HOST_SERVICE');
      expect(edges).toHaveLength(0);
    });
  });
});

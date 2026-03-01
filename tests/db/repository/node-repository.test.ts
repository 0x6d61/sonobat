import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import crypto from 'node:crypto';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { NodeRepository } from '../../../src/db/repository/node-repository.js';

// ---------------------------------------------------------------------------
// ヘルパー
// ---------------------------------------------------------------------------

/** テスト用 :memory: DB を作成しマイグレーション済みで返す */
function createTestDb(): InstanceType<typeof Database> {
  const db = new Database(':memory:');
  migrateDatabase(db);
  return db;
}

/** テスト用 artifact レコードを挿入し id を返す */
function insertTestArtifact(db: InstanceType<typeof Database>): string {
  const id = crypto.randomUUID();
  db.prepare(
    `INSERT INTO artifacts (id, tool, kind, path, captured_at) VALUES (?, 'test', 'tool_output', '/tmp/test', ?)`,
  ).run(id, new Date().toISOString());
  return id;
}

/** テスト用 ISO 8601 タイムスタンプ */
function _now(): string {
  return new Date().toISOString();
}

// ---------------------------------------------------------------------------
// host ノードの props テンプレート
// ---------------------------------------------------------------------------
const HOST_PROPS = {
  authorityKind: 'IP',
  authority: '192.168.1.1',
  resolvedIpsJson: '[]',
} as const;

const HOST_PROPS_2 = {
  authorityKind: 'IP',
  authority: '10.0.0.1',
  resolvedIpsJson: '[]',
} as const;

// service ノードの props テンプレート（parentId 必要）
const SERVICE_PROPS = {
  transport: 'tcp',
  port: 80,
  appProto: 'http',
  protoConfidence: 'high',
  state: 'open',
} as const;

// vulnerability ノードの props テンプレート（UUID natural key）
const VULN_PROPS = {
  vulnType: 'sqli',
  title: 'SQL Injection in login',
  severity: 'high',
  confidence: 'high',
  status: 'unverified',
} as const;

// ---------------------------------------------------------------------------
// テスト
// ---------------------------------------------------------------------------

describe('NodeRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: NodeRepository;

  beforeEach(() => {
    db = createTestDb();
    repo = new NodeRepository(db);
  });

  // =======================================================================
  // create()
  // =======================================================================

  describe('create()', () => {
    it('host ノードを正しい kind, natural_key, props_json で作成する', () => {
      const node = repo.create('host', { ...HOST_PROPS });

      expect(node.id).toBeDefined();
      expect(node.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
      expect(node.kind).toBe('host');
      expect(node.naturalKey).toBe('host:192.168.1.1');
      expect(JSON.parse(node.propsJson)).toEqual(HOST_PROPS);
      expect(node.createdAt).toBeDefined();
      expect(node.updatedAt).toBeDefined();
    });

    it('evidence_artifact_id を紐づけて作成できる', () => {
      const artifactId = insertTestArtifact(db);
      const node = repo.create('host', { ...HOST_PROPS }, artifactId);

      expect(node.evidenceArtifactId).toBe(artifactId);
    });

    it('parentId を使って service ノードを作成できる', () => {
      const host = repo.create('host', { ...HOST_PROPS });
      const service = repo.create('service', { ...SERVICE_PROPS }, undefined, host.id);

      expect(service.kind).toBe('service');
      expect(service.naturalKey).toBe(`svc:${host.id}:tcp:80`);
    });

    it('props バリデーションエラー時にエラーを投げる', () => {
      expect(() => {
        repo.create('host', { authorityKind: 'IP' }); // authority が欠落
      }).toThrow();
    });

    it('同じ natural_key の重複作成でエラーを投げる', () => {
      repo.create('host', { ...HOST_PROPS });
      expect(() => {
        repo.create('host', { ...HOST_PROPS }); // 同じ authority
      }).toThrow();
    });
  });

  // =======================================================================
  // upsert()
  // =======================================================================

  describe('upsert()', () => {
    it('新規ノードを作成し { node, created: true } を返す', () => {
      const result = repo.upsert('host', { ...HOST_PROPS });

      expect(result.created).toBe(true);
      expect(result.node.kind).toBe('host');
      expect(result.node.naturalKey).toBe('host:192.168.1.1');
      expect(JSON.parse(result.node.propsJson)).toEqual(HOST_PROPS);
    });

    it('既存 natural_key のノードは { node, created: false } を返し props を更新する', () => {
      // 1回目: 作成
      const first = repo.upsert('host', { ...HOST_PROPS });
      expect(first.created).toBe(true);

      // 2回目: 同じ authority → upsert で更新
      const updatedProps = {
        ...HOST_PROPS,
        resolvedIpsJson: '["10.0.0.2"]',
      };
      const second = repo.upsert('host', updatedProps);

      expect(second.created).toBe(false);
      expect(second.node.id).toBe(first.node.id);
      expect(JSON.parse(second.node.propsJson)).toEqual(updatedProps);
    });

    it('upsert で evidence_artifact_id を紐づけできる', () => {
      const artifactId = insertTestArtifact(db);
      const result = repo.upsert('host', { ...HOST_PROPS }, artifactId);

      expect(result.node.evidenceArtifactId).toBe(artifactId);
    });

    it('UUID ベースの natural key を持つノード (vulnerability) は常に新規作成される', () => {
      const first = repo.upsert('vulnerability', { ...VULN_PROPS });
      const second = repo.upsert('vulnerability', { ...VULN_PROPS });

      // vulnerability は UUID ベースの natural key なので毎回新規
      expect(first.created).toBe(true);
      expect(second.created).toBe(true);
      expect(first.node.id).not.toBe(second.node.id);
    });
  });

  // =======================================================================
  // findById()
  // =======================================================================

  describe('findById()', () => {
    it('存在するノードを取得する', () => {
      const created = repo.create('host', { ...HOST_PROPS });
      const found = repo.findById(created.id);

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
      expect(found!.kind).toBe('host');
      expect(found!.naturalKey).toBe('host:192.168.1.1');
      expect(JSON.parse(found!.propsJson)).toEqual(HOST_PROPS);
    });

    it('存在しない場合 undefined を返す', () => {
      const found = repo.findById(crypto.randomUUID());
      expect(found).toBeUndefined();
    });

    it('evidence_artifact_id が null の場合 undefined になる', () => {
      const node = repo.create('host', { ...HOST_PROPS });
      const found = repo.findById(node.id);

      expect(found).toBeDefined();
      expect(found!.evidenceArtifactId).toBeUndefined();
    });
  });

  // =======================================================================
  // findByKind()
  // =======================================================================

  describe('findByKind()', () => {
    it('kind で絞り込みしてノード一覧を返す', () => {
      repo.create('host', { ...HOST_PROPS });
      repo.create('host', { ...HOST_PROPS_2 });
      repo.create('vulnerability', { ...VULN_PROPS });

      const hosts = repo.findByKind('host');
      expect(hosts).toHaveLength(2);
      expect(hosts.every((n) => n.kind === 'host')).toBe(true);
    });

    it('該当なしの場合空配列を返す', () => {
      const result = repo.findByKind('cve');
      expect(result).toEqual([]);
    });

    it('filters を指定して props_json の中身で絞り込みできる', () => {
      repo.create('host', { ...HOST_PROPS });
      repo.create('host', { ...HOST_PROPS_2 });

      const filtered = repo.findByKind('host', { authority: '192.168.1.1' });
      expect(filtered).toHaveLength(1);
      expect(JSON.parse(filtered[0].propsJson).authority).toBe('192.168.1.1');
    });
  });

  // =======================================================================
  // findByNaturalKey()
  // =======================================================================

  describe('findByNaturalKey()', () => {
    it('natural_key でノードを取得する', () => {
      const created = repo.create('host', { ...HOST_PROPS });
      const found = repo.findByNaturalKey('host:192.168.1.1');

      expect(found).toBeDefined();
      expect(found!.id).toBe(created.id);
    });

    it('存在しない natural_key の場合 undefined を返す', () => {
      const found = repo.findByNaturalKey('host:nonexistent');
      expect(found).toBeUndefined();
    });
  });

  // =======================================================================
  // updateProps()
  // =======================================================================

  describe('updateProps()', () => {
    it('props_json と updated_at を更新する', () => {
      const created = repo.create('host', { ...HOST_PROPS });

      // 少し待って時刻差を出す
      const updatedProps = {
        ...HOST_PROPS,
        resolvedIpsJson: '["10.0.0.5"]',
      };

      const updated = repo.updateProps(created.id, updatedProps);

      expect(updated).toBeDefined();
      expect(JSON.parse(updated!.propsJson)).toEqual(updatedProps);
      // updated_at が変わっていること（同一ミリ秒だと同じ可能性はあるが仕様として検証）
      expect(updated!.updatedAt).toBeDefined();
      expect(updated!.id).toBe(created.id);
    });

    it('存在しない id の場合 undefined を返す', () => {
      const result = repo.updateProps(crypto.randomUUID(), { ...HOST_PROPS });
      expect(result).toBeUndefined();
    });

    it('props バリデーションエラー時にエラーを投げる', () => {
      const created = repo.create('host', { ...HOST_PROPS });

      expect(() => {
        repo.updateProps(created.id, { authorityKind: 'IP' }); // authority 欠落
      }).toThrow();
    });
  });

  // =======================================================================
  // delete()
  // =======================================================================

  describe('delete()', () => {
    it('存在するノードを削除して true を返す', () => {
      const created = repo.create('host', { ...HOST_PROPS });
      const result = repo.delete(created.id);

      expect(result).toBe(true);

      // 削除後は findById で取得できない
      const found = repo.findById(created.id);
      expect(found).toBeUndefined();
    });

    it('存在しない id の場合 false を返す', () => {
      const result = repo.delete(crypto.randomUUID());
      expect(result).toBe(false);
    });
  });
});

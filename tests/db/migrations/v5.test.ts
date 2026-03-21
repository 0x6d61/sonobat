import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';

describe('Migration v5: file_mtime + 複合インデックス', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
  });

  afterEach(() => {
    db.close();
  });

  it('technique_docs テーブルに file_mtime カラムが存在する', () => {
    const columns = db.prepare("PRAGMA table_info('technique_docs')").all() as Array<{
      name: string;
      type: string;
      notnull: number;
    }>;

    const fileMtimeCol = columns.find((c) => c.name === 'file_mtime');
    expect(fileMtimeCol).toBeDefined();
    expect(fileMtimeCol!.type).toBe('TEXT');
    expect(fileMtimeCol!.notnull).toBe(0); // NULL 許容
  });

  it('idx_technique_docs_source_filepath インデックスが存在する', () => {
    const indexes = db
      .prepare(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='technique_docs' AND name='idx_technique_docs_source_filepath'",
      )
      .all() as Array<{ name: string }>;

    expect(indexes).toHaveLength(1);
  });

  it('既存データの file_mtime は NULL になる', () => {
    // Insert a doc without file_mtime (existing behavior)
    db.prepare(
      `INSERT INTO technique_docs (id, source, file_path, title, category, content, chunk_index, indexed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('test-id', 'hacktricks', 'test.md', 'Test', 'test', 'content', 0, '2024-01-01T00:00:00Z');

    const row = db.prepare('SELECT file_mtime FROM technique_docs WHERE id = ?').get('test-id') as {
      file_mtime: string | null;
    };
    expect(row.file_mtime).toBeNull();
  });

  it('file_mtime に値を設定してインサートできる', () => {
    db.prepare(
      `INSERT INTO technique_docs (id, source, file_path, title, category, content, chunk_index, indexed_at, file_mtime)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      'test-id-2',
      'hacktricks',
      'test.md',
      'Test',
      'test',
      'content',
      0,
      '2024-01-01T00:00:00Z',
      '2024-06-15T12:00:00.000Z',
    );

    const row = db
      .prepare('SELECT file_mtime FROM technique_docs WHERE id = ?')
      .get('test-id-2') as { file_mtime: string | null };
    expect(row.file_mtime).toBe('2024-06-15T12:00:00.000Z');
  });

  it('スキーマバージョンが 5 になっている', () => {
    const row = db.prepare('PRAGMA user_version').get() as { user_version: number };
    expect(row.user_version).toBe(5);
  });
});

describe('Migration v5: 運用テーブル (engagements, runs, action_queue, etc.)', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
  });

  afterEach(() => {
    db.close();
  });

  // --- 7 新テーブルの存在確認 ---
  const newTables = [
    'engagements',
    'runs',
    'action_queue',
    'action_executions',
    'findings',
    'finding_events',
    'risk_snapshots',
  ];

  for (const table of newTables) {
    it(`${table} テーブルが存在する`, () => {
      const row = db
        .prepare("SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='table' AND name=?")
        .get(table) as { cnt: number };
      expect(row.cnt).toBe(1);
    });
  }

  // --- 主要インデックスの存在確認 ---
  const expectedIndexes = [
    { name: 'idx_engagements_status', table: 'engagements' },
    { name: 'idx_runs_engagement_created', table: 'runs' },
    { name: 'idx_runs_status', table: 'runs' },
    { name: 'idx_action_queue_poll', table: 'action_queue' },
    { name: 'idx_action_queue_engagement_state', table: 'action_queue' },
    { name: 'uq_action_queue_active_dedupe', table: 'action_queue' },
    { name: 'idx_action_exec_action_started', table: 'action_executions' },
    { name: 'idx_action_exec_run_started', table: 'action_executions' },
    { name: 'idx_findings_engagement_state_sev', table: 'findings' },
    { name: 'idx_findings_node', table: 'findings' },
    { name: 'idx_finding_events_finding_created', table: 'finding_events' },
    { name: 'idx_risk_snapshots_engagement_created', table: 'risk_snapshots' },
    { name: 'idx_scans_engagement_started', table: 'scans' },
    { name: 'idx_artifacts_engagement_captured', table: 'artifacts' },
    { name: 'idx_artifacts_run_captured', table: 'artifacts' },
  ];

  for (const idx of expectedIndexes) {
    it(`インデックス ${idx.name} が ${idx.table} に存在する`, () => {
      const row = db
        .prepare(
          "SELECT COUNT(*) AS cnt FROM sqlite_master WHERE type='index' AND name=? AND tbl_name=?",
        )
        .get(idx.name, idx.table) as { cnt: number };
      expect(row.cnt).toBe(1);
    });
  }

  // --- action_queue 部分ユニークインデックス ---
  it('action_queue: 同じ dedupe_key で queued 状態 2 件は失敗する', () => {
    const now = new Date().toISOString();
    // engagement を先に作成
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-1', 'test', 'stg', '{}', '{}', 'active', now, now);

    db.prepare(
      `INSERT INTO action_queue (id, engagement_id, kind, priority, dedupe_key, params_json, state, available_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('aq-1', 'eng-1', 'nmap_scan', 100, 'scan:target1', '{}', 'queued', now, now, now);

    expect(() =>
      db
        .prepare(
          `INSERT INTO action_queue (id, engagement_id, kind, priority, dedupe_key, params_json, state, available_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run('aq-2', 'eng-1', 'nmap_scan', 100, 'scan:target1', '{}', 'queued', now, now, now),
    ).toThrow();
  });

  it('action_queue: succeeded 済みなら同じ dedupe_key で queued を追加できる', () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-2', 'test', 'stg', '{}', '{}', 'active', now, now);

    // succeeded 状態の既存アクション
    db.prepare(
      `INSERT INTO action_queue (id, engagement_id, kind, priority, dedupe_key, params_json, state, available_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('aq-3', 'eng-2', 'nmap_scan', 100, 'scan:target2', '{}', 'succeeded', now, now, now);

    // queued 状態の新アクション — succeeded は部分インデックスの対象外なので成功する
    expect(() =>
      db
        .prepare(
          `INSERT INTO action_queue (id, engagement_id, kind, priority, dedupe_key, params_json, state, available_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run('aq-4', 'eng-2', 'nmap_scan', 100, 'scan:target2', '{}', 'queued', now, now, now),
    ).not.toThrow();
  });

  // --- findings UNIQUE(engagement_id, canonical_key) ---
  it('findings: 同じ engagement_id + canonical_key の重複は失敗する', () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-f1', 'test', 'stg', '{}', '{}', 'active', now, now);

    db.prepare(
      `INSERT INTO findings (id, engagement_id, canonical_key, title, severity, confidence, state, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('find-1', 'eng-f1', 'vuln:sqli:login', 'SQLi in login', 'high', 'high', 'open', now, now);

    expect(() =>
      db
        .prepare(
          `INSERT INTO findings (id, engagement_id, canonical_key, title, severity, confidence, state, first_seen_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          'find-2',
          'eng-f1',
          'vuln:sqli:login',
          'SQLi in login (dup)',
          'high',
          'high',
          'open',
          now,
          now,
        ),
    ).toThrow();
  });

  // --- scans / artifacts の新カラム確認 ---
  it('scans テーブルに engagement_id, run_id カラムが追加されている', () => {
    const columns = db.prepare("PRAGMA table_info('scans')").all() as Array<{ name: string }>;
    const colNames = columns.map((c) => c.name);
    expect(colNames).toContain('engagement_id');
    expect(colNames).toContain('run_id');
  });

  it('artifacts テーブルに engagement_id, run_id, action_execution_id カラムが追加されている', () => {
    const columns = db.prepare("PRAGMA table_info('artifacts')").all() as Array<{ name: string }>;
    const colNames = columns.map((c) => c.name);
    expect(colNames).toContain('engagement_id');
    expect(colNames).toContain('run_id');
    expect(colNames).toContain('action_execution_id');
  });

  // --- action_queue 部分ユニーク: running 状態でも重複拒否 ---
  it('action_queue: 同じ dedupe_key で running 状態 2 件は失敗する', () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-r1', 'test', 'stg', '{}', '{}', 'active', now, now);

    db.prepare(
      `INSERT INTO action_queue (id, engagement_id, kind, priority, dedupe_key, params_json, state, available_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('aq-r1', 'eng-r1', 'nmap_scan', 100, 'scan:running', '{}', 'running', now, now, now);

    expect(() =>
      db
        .prepare(
          `INSERT INTO action_queue (id, engagement_id, kind, priority, dedupe_key, params_json, state, available_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run('aq-r2', 'eng-r1', 'nmap_scan', 100, 'scan:running', '{}', 'running', now, now, now),
    ).toThrow();
  });

  // --- ON DELETE SET NULL: run 削除 → action_queue.run_id が NULL ---
  it('run 削除で action_queue.run_id が SET NULL される', () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-sn1', 'test', 'stg', '{}', '{}', 'active', now, now);

    db.prepare(
      `INSERT INTO runs (id, engagement_id, trigger_kind, status, summary_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run('run-sn1', 'eng-sn1', 'manual', 'succeeded', '{}', now);

    db.prepare(
      `INSERT INTO action_queue (id, engagement_id, run_id, kind, priority, dedupe_key, params_json, state, available_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      'aq-sn1',
      'eng-sn1',
      'run-sn1',
      'nmap_scan',
      100,
      'scan:sn',
      '{}',
      'succeeded',
      now,
      now,
      now,
    );

    // run 削除前: run_id が設定されている
    const before = db.prepare('SELECT run_id FROM action_queue WHERE id = ?').get('aq-sn1') as {
      run_id: string | null;
    };
    expect(before.run_id).toBe('run-sn1');

    // run を削除
    db.prepare('DELETE FROM runs WHERE id = ?').run('run-sn1');

    // run 削除後: run_id が NULL になっている
    const after = db.prepare('SELECT run_id FROM action_queue WHERE id = ?').get('aq-sn1') as {
      run_id: string | null;
    };
    expect(after.run_id).toBeNull();
  });

  // --- Multi-level cascade: engagement → action_queue → action_executions ---
  it('engagements 削除で action_queue + action_executions がカスケード削除される', () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-ml1', 'cascade test', 'stg', '{}', '{}', 'active', now, now);

    db.prepare(
      `INSERT INTO action_queue (id, engagement_id, kind, priority, dedupe_key, params_json, state, available_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('aq-ml1', 'eng-ml1', 'nmap_scan', 100, 'scan:ml', '{}', 'succeeded', now, now, now);

    db.prepare(
      `INSERT INTO action_executions (id, action_id, executor, input_json, output_json, started_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run('ae-ml1', 'aq-ml1', 'worker-1', '{}', '{}', now);

    // engagement 削除
    db.prepare('DELETE FROM engagements WHERE id = ?').run('eng-ml1');

    const aqCount = db
      .prepare("SELECT COUNT(*) AS cnt FROM action_queue WHERE engagement_id = 'eng-ml1'")
      .get() as { cnt: number };
    const aeCount = db
      .prepare("SELECT COUNT(*) AS cnt FROM action_executions WHERE action_id = 'aq-ml1'")
      .get() as { cnt: number };
    expect(aqCount.cnt).toBe(0);
    expect(aeCount.cnt).toBe(0);
  });

  // --- Multi-level cascade: engagement → findings → finding_events ---
  it('engagements 削除で findings + finding_events がカスケード削除される', () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-ml2', 'cascade test', 'stg', '{}', '{}', 'active', now, now);

    db.prepare(
      `INSERT INTO findings (id, engagement_id, canonical_key, title, severity, confidence, state, first_seen_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('find-ml1', 'eng-ml2', 'vuln:xss:search', 'XSS', 'medium', 'high', 'open', now, now);

    db.prepare(
      `INSERT INTO finding_events (id, finding_id, event_type, before_json, after_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run('fe-ml1', 'find-ml1', 'discovered', '{}', '{}', now);

    // engagement 削除
    db.prepare('DELETE FROM engagements WHERE id = ?').run('eng-ml2');

    const fCount = db
      .prepare("SELECT COUNT(*) AS cnt FROM findings WHERE engagement_id = 'eng-ml2'")
      .get() as { cnt: number };
    const feCount = db
      .prepare("SELECT COUNT(*) AS cnt FROM finding_events WHERE finding_id = 'find-ml1'")
      .get() as { cnt: number };
    expect(fCount.cnt).toBe(0);
    expect(feCount.cnt).toBe(0);
  });

  // --- Multi-level cascade: engagement → risk_snapshots ---
  it('engagements 削除で risk_snapshots がカスケード削除される', () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-ml3', 'cascade test', 'stg', '{}', '{}', 'active', now, now);

    db.prepare(
      `INSERT INTO risk_snapshots (id, engagement_id, score, created_at)
       VALUES (?, ?, ?, ?)`,
    ).run('rs-ml1', 'eng-ml3', 7.5, now);

    db.prepare('DELETE FROM engagements WHERE id = ?').run('eng-ml3');

    const rsCount = db
      .prepare("SELECT COUNT(*) AS cnt FROM risk_snapshots WHERE engagement_id = 'eng-ml3'")
      .get() as { cnt: number };
    expect(rsCount.cnt).toBe(0);
  });

  // --- engagements 削除 → runs カスケード削除 ---
  it('engagements 削除で runs がカスケード削除される', () => {
    const now = new Date().toISOString();
    db.prepare(
      `INSERT INTO engagements (id, name, environment, scope_json, policy_json, status, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run('eng-c1', 'cascade test', 'stg', '{}', '{}', 'active', now, now);

    db.prepare(
      `INSERT INTO runs (id, engagement_id, trigger_kind, status, summary_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run('run-c1', 'eng-c1', 'manual', 'queued', '{}', now);

    db.prepare(
      `INSERT INTO runs (id, engagement_id, trigger_kind, status, summary_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run('run-c2', 'eng-c1', 'schedule', 'running', '{}', now);

    // 削除前: runs が 2 件
    const before = db
      .prepare("SELECT COUNT(*) AS cnt FROM runs WHERE engagement_id = 'eng-c1'")
      .get() as {
      cnt: number;
    };
    expect(before.cnt).toBe(2);

    // engagement を削除
    db.prepare('DELETE FROM engagements WHERE id = ?').run('eng-c1');

    // 削除後: runs が 0 件
    const after = db
      .prepare("SELECT COUNT(*) AS cnt FROM runs WHERE engagement_id = 'eng-c1'")
      .get() as {
      cnt: number;
    };
    expect(after.cnt).toBe(0);
  });
});

describe('Migration v5: backfill（既存データのデフォルト engagement 付与）', () => {
  let db: InstanceType<typeof Database>;

  afterEach(() => {
    db.close();
  });

  it('既存 scans がある場合、デフォルト engagement が作成され scans.engagement_id に設定される', async () => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');

    // v0〜v4 の migration を個別にインポートして適用
    const { setSchemaVersion } = await import('../../../src/db/migrations/index.js');
    const v0 = (await import('../../../src/db/migrations/v0.js')).default;
    const v1 = (await import('../../../src/db/migrations/v1.js')).default;
    const v2 = (await import('../../../src/db/migrations/v2.js')).default;
    const v3 = (await import('../../../src/db/migrations/v3.js')).default;
    const v4 = (await import('../../../src/db/migrations/v4.js')).default;

    for (const m of [v0, v1, v2, v3, v4]) {
      db.transaction(() => m.up(db))();
    }
    setSchemaVersion(db, 4);

    // 既存 scans データを挿入
    db.prepare(`INSERT INTO scans (id, started_at) VALUES (?, ?)`).run(
      'scan-bf1',
      '2025-01-01T00:00:00Z',
    );

    db.prepare(
      `INSERT INTO artifacts (id, scan_id, tool, kind, path, captured_at) VALUES (?, ?, ?, ?, ?, ?)`,
    ).run('art-bf1', 'scan-bf1', 'nmap', 'xml', '/tmp/scan.xml', '2025-01-01T00:00:00Z');

    db.prepare(
      `INSERT INTO artifacts (id, scan_id, tool, kind, path, captured_at) VALUES (?, ?, ?, ?, ?, ?)`,
    ).run('art-bf2', null, 'ffuf', 'json', '/tmp/fuzz.json', '2025-01-02T00:00:00Z');

    // v5 を適用
    const v5 = (await import('../../../src/db/migrations/v5.js')).default;
    db.transaction(() => v5.up(db))();
    setSchemaVersion(db, 5);

    // デフォルト engagement が存在する
    const eng = db.prepare("SELECT * FROM engagements WHERE name = 'default'").get() as
      | Record<string, unknown>
      | undefined;
    expect(eng).toBeDefined();
    expect(eng!.status).toBe('active');

    // scans.engagement_id がデフォルト engagement に設定されている
    const scan = db.prepare('SELECT engagement_id FROM scans WHERE id = ?').get('scan-bf1') as {
      engagement_id: string | null;
    };
    expect(scan.engagement_id).toBe(eng!.id);

    // scan_id がある artifact はデフォルト engagement に設定されている
    const art1 = db.prepare('SELECT engagement_id FROM artifacts WHERE id = ?').get('art-bf1') as {
      engagement_id: string | null;
    };
    expect(art1.engagement_id).toBe(eng!.id);

    // scan_id が NULL の artifact もデフォルト engagement に設定されている
    const art2 = db.prepare('SELECT engagement_id FROM artifacts WHERE id = ?').get('art-bf2') as {
      engagement_id: string | null;
    };
    expect(art2.engagement_id).toBe(eng!.id);
  });

  it('既存 scans がない fresh DB ではデフォルト engagement は作成されない', () => {
    db = new Database(':memory:');
    migrateDatabase(db);

    const count = db.prepare('SELECT COUNT(*) AS cnt FROM engagements').get() as { cnt: number };
    expect(count.cnt).toBe(0);
  });

  it('artifacts のみ存在し scans がない場合、backfill はスキップされ engagement_id は NULL のまま', async () => {
    db = new Database(':memory:');
    db.pragma('foreign_keys = ON');

    const { setSchemaVersion } = await import('../../../src/db/migrations/index.js');
    const v0 = (await import('../../../src/db/migrations/v0.js')).default;
    const v1 = (await import('../../../src/db/migrations/v1.js')).default;
    const v2 = (await import('../../../src/db/migrations/v2.js')).default;
    const v3 = (await import('../../../src/db/migrations/v3.js')).default;
    const v4 = (await import('../../../src/db/migrations/v4.js')).default;

    for (const m of [v0, v1, v2, v3, v4]) {
      db.transaction(() => m.up(db))();
    }
    setSchemaVersion(db, 4);

    // scans なしで artifact だけ挿入（scan_id = NULL）
    db.prepare(
      `INSERT INTO artifacts (id, scan_id, tool, kind, path, captured_at) VALUES (?, ?, ?, ?, ?, ?)`,
    ).run('art-orphan', null, 'manual', 'txt', '/tmp/note.txt', '2025-01-01T00:00:00Z');

    // v5 を適用
    const v5 = (await import('../../../src/db/migrations/v5.js')).default;
    db.transaction(() => v5.up(db))();
    setSchemaVersion(db, 5);

    // engagement は作成されない
    const engCount = db.prepare('SELECT COUNT(*) AS cnt FROM engagements').get() as { cnt: number };
    expect(engCount.cnt).toBe(0);

    // artifact の engagement_id は NULL のまま
    const art = db
      .prepare('SELECT engagement_id FROM artifacts WHERE id = ?')
      .get('art-orphan') as { engagement_id: string | null };
    expect(art.engagement_id).toBeNull();
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import {
  listFacts,
  runDatalog,
  queryAttackPaths,
  listPatterns,
} from '../../../src/engine/datalog/index.js';
import { HostRepository } from '../../../src/db/repository/host-repository.js';
import { ArtifactRepository } from '../../../src/db/repository/artifact-repository.js';
import { ServiceRepository } from '../../../src/db/repository/service-repository.js';
import { DatalogRuleRepository } from '../../../src/db/repository/datalog-rule-repository.js';

function now(): string {
  return new Date().toISOString();
}

describe('Datalog public API', () => {
  let db: InstanceType<typeof Database>;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
  });

  describe('listFacts', () => {
    it('空 DB → 空配列', () => {
      const facts = listFacts(db);
      expect(facts).toHaveLength(0);
    });

    it('データあり → ファクトを返す', () => {
      const hostRepo = new HostRepository(db);
      hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

      const facts = listFacts(db);
      expect(facts.length).toBeGreaterThan(0);
      expect(facts.some((f) => f.predicate === 'host')).toBe(true);
    });

    it('predicate フィルタが効く', () => {
      const hostRepo = new HostRepository(db);
      hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

      const facts = listFacts(db, 'host');
      expect(facts.every((f) => f.predicate === 'host')).toBe(true);
    });

    it('limit が効く', () => {
      const hostRepo = new HostRepository(db);
      hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });
      hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.2', resolvedIpsJson: '[]' });

      const facts = listFacts(db, 'host', 1);
      expect(facts).toHaveLength(1);
    });
  });

  describe('runDatalog', () => {
    it('クエリを実行して結果を返す', () => {
      const hostRepo = new HostRepository(db);
      hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

      const result = runDatalog(db, '?- host(Id, Authority, Kind).');
      expect(result.answers).toHaveLength(1);
      expect(result.answers[0].tuples.length).toBeGreaterThan(0);
    });

    it('saveName 指定で DB にルールを保存', () => {
      const program = 'ip_host(Authority) :- host(_, Authority, "IP").\n?- ip_host(Authority).';
      runDatalog(db, program, {
        saveName: 'ip_hosts',
        saveDescription: 'IP hosts only',
        generatedBy: 'ai',
      });

      const ruleRepo = new DatalogRuleRepository(db);
      const saved = ruleRepo.findByName('ip_hosts');
      expect(saved).toBeDefined();
      expect(saved?.generatedBy).toBe('ai');
      expect(saved?.ruleText).toBe(program);
    });
  });

  describe('queryAttackPaths', () => {
    it('プリセットパターンを実行', () => {
      const hostRepo = new HostRepository(db);
      const artifactRepo = new ArtifactRepository(db);
      const serviceRepo = new ServiceRepository(db);

      const host = hostRepo.create({
        authorityKind: 'IP',
        authority: '10.0.0.1',
        resolvedIpsJson: '[]',
      });
      const artifact = artifactRepo.create({
        tool: 'nmap',
        kind: 'tool_output',
        path: '/tmp/scan.xml',
        capturedAt: now(),
      });
      serviceRepo.create({
        hostId: host.id,
        transport: 'tcp',
        port: 80,
        appProto: 'http',
        protoConfidence: 'high',
        state: 'open',
        evidenceArtifactId: artifact.id,
      });

      const result = queryAttackPaths(db, 'reachable_services');
      expect(result.answers).toHaveLength(1);
      expect(result.answers[0].tuples.length).toBeGreaterThan(0);
    });

    it('保存済みルールを実行', () => {
      const ruleRepo = new DatalogRuleRepository(db);
      ruleRepo.create({
        name: 'custom_rule',
        ruleText: '?- host(Id, Authority, Kind).',
        generatedBy: 'human',
      });

      const hostRepo = new HostRepository(db);
      hostRepo.create({ authorityKind: 'IP', authority: '10.0.0.1', resolvedIpsJson: '[]' });

      const result = queryAttackPaths(db, 'custom_rule');
      expect(result.answers).toHaveLength(1);
    });

    it('存在しないパターン → 空結果', () => {
      const result = queryAttackPaths(db, 'nonexistent');
      expect(result.answers).toHaveLength(0);
    });
  });

  describe('listPatterns', () => {
    it('プリセット + 保存済みルールを返す', () => {
      const ruleRepo = new DatalogRuleRepository(db);
      ruleRepo.create({
        name: 'my_rule',
        ruleText: 'a(X) :- b(X).\n?- a(X).',
        generatedBy: 'ai',
      });

      const patterns = listPatterns(db);
      const presets = patterns.filter((p) => p.source === 'preset');
      const saved = patterns.filter((p) => p.source === 'saved');

      expect(presets.length).toBeGreaterThan(0);
      expect(saved).toHaveLength(1);
      expect(saved[0].name).toBe('my_rule');
      expect(saved[0].generatedBy).toBe('ai');
    });
  });
});

import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import { migrateDatabase } from '../../../src/db/migrate.js';
import { DatalogRuleRepository } from '../../../src/db/repository/datalog-rule-repository.js';

describe('DatalogRuleRepository', () => {
  let db: InstanceType<typeof Database>;
  let repo: DatalogRuleRepository;

  beforeEach(() => {
    db = new Database(':memory:');
    migrateDatabase(db);
    repo = new DatalogRuleRepository(db);
  });

  it('create — ルールを作成して返す', () => {
    const rule = repo.create({
      name: 'test_rule',
      description: 'A test rule',
      ruleText: 'test(X) :- fact(X).\n?- test(X).',
      generatedBy: 'human',
    });

    expect(rule.name).toBe('test_rule');
    expect(rule.description).toBe('A test rule');
    expect(rule.ruleText).toBe('test(X) :- fact(X).\n?- test(X).');
    expect(rule.generatedBy).toBe('human');
    expect(rule.isPreset).toBe(false);
    expect(rule.id).toBeDefined();
  });

  it('findById — 作成したルールを取得できる', () => {
    const created = repo.create({
      name: 'find_test',
      ruleText: 'a(X) :- b(X).\n?- a(X).',
      generatedBy: 'ai',
    });

    const found = repo.findById(created.id);
    expect(found).toBeDefined();
    expect(found?.name).toBe('find_test');
    expect(found?.generatedBy).toBe('ai');
  });

  it('findByName — 名前でルールを取得できる', () => {
    repo.create({
      name: 'by_name_test',
      ruleText: 'x(A) :- y(A).\n?- x(A).',
      generatedBy: 'preset',
      isPreset: true,
    });

    const found = repo.findByName('by_name_test');
    expect(found).toBeDefined();
    expect(found?.isPreset).toBe(true);
  });

  it('findByName — 存在しない名前は undefined', () => {
    const found = repo.findByName('nonexistent');
    expect(found).toBeUndefined();
  });

  it('findAll — 全ルールを取得', () => {
    repo.create({ name: 'rule1', ruleText: 'a(X) :- b(X).', generatedBy: 'human' });
    repo.create({ name: 'rule2', ruleText: 'c(X) :- d(X).', generatedBy: 'ai' });

    const all = repo.findAll();
    expect(all).toHaveLength(2);
  });

  it('delete — ルールを削除できる', () => {
    const rule = repo.create({ name: 'to_delete', ruleText: 'a(X) :- b(X).', generatedBy: 'human' });

    expect(repo.delete(rule.id)).toBe(true);
    expect(repo.findById(rule.id)).toBeUndefined();
  });

  it('delete — 存在しない ID は false を返す', () => {
    expect(repo.delete('nonexistent')).toBe(false);
  });

  it('create — 重複する名前はエラー', () => {
    repo.create({ name: 'unique_name', ruleText: 'a(X) :- b(X).', generatedBy: 'human' });

    expect(() => {
      repo.create({ name: 'unique_name', ruleText: 'c(X) :- d(X).', generatedBy: 'ai' });
    }).toThrow();
  });
});

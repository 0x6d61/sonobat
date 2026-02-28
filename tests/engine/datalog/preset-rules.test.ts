import { describe, it, expect } from 'vitest';
import {
  getPresetRules,
  getPresetRule,
} from '../../../src/engine/datalog/preset-rules.js';
import { parse } from '../../../src/engine/datalog/parser.js';

describe('preset-rules', () => {
  describe('getPresetRules', () => {
    it('6つのプリセットルールを返す', () => {
      const rules = getPresetRules();
      expect(rules).toHaveLength(6);
    });

    it('全プリセットルールに name, description, ruleText がある', () => {
      const rules = getPresetRules();
      for (const rule of rules) {
        expect(rule.name).toBeDefined();
        expect(rule.name.length).toBeGreaterThan(0);
        expect(rule.description).toBeDefined();
        expect(rule.description.length).toBeGreaterThan(0);
        expect(rule.ruleText).toBeDefined();
        expect(rule.ruleText.length).toBeGreaterThan(0);
      }
    });

    it('期待される名前のプリセットルールが全て存在する', () => {
      const rules = getPresetRules();
      const names = rules.map((r) => r.name);

      expect(names).toContain('reachable_services');
      expect(names).toContain('authenticated_access');
      expect(names).toContain('exploitable_endpoints');
      expect(names).toContain('critical_vulns');
      expect(names).toContain('attack_surface');
      expect(names).toContain('unfuzzed_inputs');
    });
  });

  describe('getPresetRule', () => {
    it('名前で特定のプリセットルールを取得できる', () => {
      const rule = getPresetRule('reachable_services');
      expect(rule).toBeDefined();
      expect(rule?.name).toBe('reachable_services');
      expect(rule?.ruleText).toContain('reachable');
    });

    it('存在しない名前を指定すると undefined を返す', () => {
      const rule = getPresetRule('nonexistent');
      expect(rule).toBeUndefined();
    });

    it('各プリセットルールを名前で個別に取得できる', () => {
      const names = [
        'reachable_services',
        'authenticated_access',
        'exploitable_endpoints',
        'critical_vulns',
        'attack_surface',
        'unfuzzed_inputs',
      ];

      for (const name of names) {
        const rule = getPresetRule(name);
        expect(rule).toBeDefined();
        expect(rule?.name).toBe(name);
      }
    });
  });

  describe('パーサーによる構文検証', () => {
    it('全プリセットルールの ruleText がパーサーで正常にパースできる', () => {
      const rules = getPresetRules();

      for (const rule of rules) {
        // パースエラーがスローされないことを確認
        expect(() => parse(rule.ruleText)).not.toThrow();

        // パース結果が rules と queries を含むことを確認
        const program = parse(rule.ruleText);
        expect(program.rules.length).toBeGreaterThan(0);
        expect(program.queries.length).toBeGreaterThan(0);
      }
    });
  });
});

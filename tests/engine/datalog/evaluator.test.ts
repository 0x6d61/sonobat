import { describe, it, expect } from 'vitest';
import { evaluate } from '../../../src/engine/datalog/evaluator.js';
import { parse } from '../../../src/engine/datalog/parser.js';
import type { Fact, EvalConfig } from '../../../src/engine/datalog/types.js';
import { DatalogResourceError } from '../../../src/engine/datalog/types.js';

/**
 * Helper: parse a Datalog program and evaluate with base facts.
 */
function evalDatalog(
  source: string,
  baseFacts: Fact[] = [],
  config?: Partial<EvalConfig>,
): ReturnType<typeof evaluate> {
  const program = parse(source);
  return evaluate(program, baseFacts, config);
}

describe('Evaluator', () => {
  // ============================================================
  // 単純なファクトクエリ
  // ============================================================

  describe('単純なファクトクエリ', () => {
    it('baseFacts からクエリに一致するタプルを返す', () => {
      const facts: Fact[] = [
        { predicate: 'parent', values: ['alice', 'bob'] },
        { predicate: 'parent', values: ['bob', 'carol'] },
      ];
      const result = evalDatalog('?- parent(X, Y).', facts);

      expect(result.answers).toHaveLength(1);
      expect(result.answers[0].tuples).toHaveLength(2);
      expect(result.answers[0].tuples).toContainEqual(['alice', 'bob']);
      expect(result.answers[0].tuples).toContainEqual(['bob', 'carol']);
    });

    it('ソース中のファクト（空ボディルール）を認識する', () => {
      const source = `
        parent("alice", "bob").
        parent("bob", "carol").
        ?- parent(X, Y).
      `;
      const result = evalDatalog(source);

      expect(result.answers).toHaveLength(1);
      expect(result.answers[0].tuples).toHaveLength(2);
      expect(result.answers[0].tuples).toContainEqual(['alice', 'bob']);
      expect(result.answers[0].tuples).toContainEqual(['bob', 'carol']);
    });

    it('baseFacts とソース中のファクトの両方を統合する', () => {
      const facts: Fact[] = [{ predicate: 'parent', values: ['alice', 'bob'] }];
      const source = `
        parent("bob", "carol").
        ?- parent(X, Y).
      `;
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(2);
      expect(result.answers[0].tuples).toContainEqual(['alice', 'bob']);
      expect(result.answers[0].tuples).toContainEqual(['bob', 'carol']);
    });
  });

  // ============================================================
  // ルール評価（推移的閉包）
  // ============================================================

  describe('ルール評価', () => {
    it('単純なルールによる推論: ancestor from parent', () => {
      const source = `
        ancestor(X, Y) :- parent(X, Y).
        ?- ancestor(X, Y).
      `;
      const facts: Fact[] = [
        { predicate: 'parent', values: ['alice', 'bob'] },
        { predicate: 'parent', values: ['bob', 'carol'] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(2);
      expect(result.answers[0].tuples).toContainEqual(['alice', 'bob']);
      expect(result.answers[0].tuples).toContainEqual(['bob', 'carol']);
    });

    it('再帰ルールによる推移的閉包: ancestor', () => {
      const source = `
        ancestor(X, Y) :- parent(X, Y).
        ancestor(X, Z) :- parent(X, Y), ancestor(Y, Z).
        ?- ancestor(X, Y).
      `;
      const facts: Fact[] = [
        { predicate: 'parent', values: ['alice', 'bob'] },
        { predicate: 'parent', values: ['bob', 'carol'] },
        { predicate: 'parent', values: ['carol', 'dave'] },
      ];
      const result = evalDatalog(source, facts);

      const tuples = result.answers[0].tuples;
      // 直接の親子: 3
      expect(tuples).toContainEqual(['alice', 'bob']);
      expect(tuples).toContainEqual(['bob', 'carol']);
      expect(tuples).toContainEqual(['carol', 'dave']);
      // 推移的: alice->carol, alice->dave, bob->dave
      expect(tuples).toContainEqual(['alice', 'carol']);
      expect(tuples).toContainEqual(['alice', 'dave']);
      expect(tuples).toContainEqual(['bob', 'dave']);
      expect(tuples).toHaveLength(6);
    });
  });

  // ============================================================
  // 複数ルールのジョイン
  // ============================================================

  describe('複数ルールのジョイン', () => {
    it('異なる述語のジョインで新ファクトを導出する', () => {
      const source = `
        access(User, Resource) :- role(User, Role), permission(Role, Resource).
        ?- access(X, Y).
      `;
      const facts: Fact[] = [
        { predicate: 'role', values: ['alice', 'admin'] },
        { predicate: 'role', values: ['bob', 'viewer'] },
        { predicate: 'permission', values: ['admin', 'secret_doc'] },
        { predicate: 'permission', values: ['admin', 'public_doc'] },
        { predicate: 'permission', values: ['viewer', 'public_doc'] },
      ];
      const result = evalDatalog(source, facts);

      const tuples = result.answers[0].tuples;
      expect(tuples).toContainEqual(['alice', 'secret_doc']);
      expect(tuples).toContainEqual(['alice', 'public_doc']);
      expect(tuples).toContainEqual(['bob', 'public_doc']);
      expect(tuples).toHaveLength(3);
    });
  });

  // ============================================================
  // 否定サポート
  // ============================================================

  describe('否定サポート', () => {
    it('否定リテラルでファクトを除外する', () => {
      const source = `
        safe(X) :- node(X), not danger(X).
        ?- safe(X).
      `;
      const facts: Fact[] = [
        { predicate: 'node', values: ['a'] },
        { predicate: 'node', values: ['b'] },
        { predicate: 'node', values: ['c'] },
        { predicate: 'danger', values: ['b'] },
      ];
      const result = evalDatalog(source, facts);

      const tuples = result.answers[0].tuples;
      expect(tuples).toContainEqual(['a']);
      expect(tuples).toContainEqual(['c']);
      expect(tuples).toHaveLength(2);
    });

    it('否定リテラルの対象が空の場合、全て通過する', () => {
      const source = `
        safe(X) :- node(X), not danger(X).
        ?- safe(X).
      `;
      const facts: Fact[] = [
        { predicate: 'node', values: ['a'] },
        { predicate: 'node', values: ['b'] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(2);
    });
  });

  // ============================================================
  // 定数を含むクエリ
  // ============================================================

  describe('定数を含むクエリ', () => {
    it('文字列定数でフィルタリングする', () => {
      const source = `?- parent(X, "carol").`;
      const facts: Fact[] = [
        { predicate: 'parent', values: ['alice', 'bob'] },
        { predicate: 'parent', values: ['bob', 'carol'] },
        { predicate: 'parent', values: ['carol', 'dave'] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(1);
      expect(result.answers[0].tuples).toContainEqual(['bob', 'carol']);
    });

    it('数値定数でフィルタリングする', () => {
      const source = `?- score(X, 100).`;
      const facts: Fact[] = [
        { predicate: 'score', values: ['alice', 95] },
        { predicate: 'score', values: ['bob', 100] },
        { predicate: 'score', values: ['carol', 100] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(2);
      expect(result.answers[0].tuples).toContainEqual(['bob', 100]);
      expect(result.answers[0].tuples).toContainEqual(['carol', 100]);
    });
  });

  // ============================================================
  // 比較演算子
  // ============================================================

  describe('比較演算子', () => {
    it('大なり比較で数値フィルタリング', () => {
      const source = `
        big(X) :- size(X, N), N > 100.
        ?- big(X).
      `;
      const facts: Fact[] = [
        { predicate: 'size', values: ['a', 50] },
        { predicate: 'size', values: ['b', 150] },
        { predicate: 'size', values: ['c', 200] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(2);
      expect(result.answers[0].tuples).toContainEqual(['b']);
      expect(result.answers[0].tuples).toContainEqual(['c']);
    });

    it('等号比較', () => {
      const source = `
        match(X) :- pair(X, N), N = 42.
        ?- match(X).
      `;
      const facts: Fact[] = [
        { predicate: 'pair', values: ['a', 42] },
        { predicate: 'pair', values: ['b', 99] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(1);
      expect(result.answers[0].tuples).toContainEqual(['a']);
    });

    it('不等号比較', () => {
      const source = `
        diff(X) :- pair(X, N), N != 42.
        ?- diff(X).
      `;
      const facts: Fact[] = [
        { predicate: 'pair', values: ['a', 42] },
        { predicate: 'pair', values: ['b', 99] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(1);
      expect(result.answers[0].tuples).toContainEqual(['b']);
    });

    it('以下比較（<=）', () => {
      const source = `
        small(X) :- size(X, N), N <= 100.
        ?- small(X).
      `;
      const facts: Fact[] = [
        { predicate: 'size', values: ['a', 50] },
        { predicate: 'size', values: ['b', 100] },
        { predicate: 'size', values: ['c', 150] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].tuples).toHaveLength(2);
      expect(result.answers[0].tuples).toContainEqual(['a']);
      expect(result.answers[0].tuples).toContainEqual(['b']);
    });
  });

  // ============================================================
  // リソース制限
  // ============================================================

  describe('リソース制限', () => {
    it('maxRules を超えた場合に DatalogResourceError をスローする', () => {
      const source = `
        a(X) :- b(X).
        b(X) :- c(X).
        c(X) :- d(X).
        ?- a(X).
      `;
      const facts: Fact[] = [{ predicate: 'd', values: ['x'] }];
      expect(() => evalDatalog(source, facts, { maxRules: 2 })).toThrow(DatalogResourceError);
    });

    it('maxIterations を超えた場合に DatalogResourceError をスローする', () => {
      // 再帰ルールで多くのイテレーションが必要なケース
      // 長いチェーンを baseFacts で作る
      const facts: Fact[] = [];
      for (let i = 0; i < 100; i++) {
        facts.push({ predicate: 'next', values: [i, i + 1] });
      }
      const source = `
        reach(X, Y) :- next(X, Y).
        reach(X, Z) :- next(X, Y), reach(Y, Z).
        ?- reach(X, Y).
      `;
      // maxIterations = 1 は不十分なので失敗する
      expect(() => evalDatalog(source, facts, { maxIterations: 1 })).toThrow(DatalogResourceError);
    });

    it('maxTuples を超えた場合に DatalogResourceError をスローする', () => {
      const facts: Fact[] = [];
      for (let i = 0; i < 50; i++) {
        facts.push({ predicate: 'next', values: [i, i + 1] });
      }
      const source = `
        reach(X, Y) :- next(X, Y).
        reach(X, Z) :- next(X, Y), reach(Y, Z).
        ?- reach(X, Y).
      `;
      // maxTuples = 10 は不十分なので失敗する
      expect(() => evalDatalog(source, facts, { maxTuples: 10 })).toThrow(DatalogResourceError);
    });
  });

  // ============================================================
  // エッジケース
  // ============================================================

  describe('エッジケース', () => {
    it('空のファクト・空のルールでも正常に動作する', () => {
      const source = `?- something(X).`;
      const result = evalDatalog(source);

      expect(result.answers).toHaveLength(1);
      expect(result.answers[0].tuples).toHaveLength(0);
    });

    it('クエリがないプログラムでは空の answers を返す', () => {
      const source = `parent("alice", "bob").`;
      const result = evalDatalog(source);

      expect(result.answers).toHaveLength(0);
    });

    it('ルールもクエリもない空プログラム', () => {
      const source = '';
      const result = evalDatalog(source);

      expect(result.answers).toHaveLength(0);
      expect(result.stats.iterations).toBe(0);
    });
  });

  // ============================================================
  // 統計情報
  // ============================================================

  describe('統計情報', () => {
    it('stats に iterations, totalDerived, elapsedMs が含まれる', () => {
      const source = `
        ancestor(X, Y) :- parent(X, Y).
        ancestor(X, Z) :- parent(X, Y), ancestor(Y, Z).
        ?- ancestor(X, Y).
      `;
      const facts: Fact[] = [
        { predicate: 'parent', values: ['alice', 'bob'] },
        { predicate: 'parent', values: ['bob', 'carol'] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.stats.iterations).toBeGreaterThanOrEqual(1);
      expect(result.stats.totalDerived).toBeGreaterThanOrEqual(1);
      expect(result.stats.elapsedMs).toBeGreaterThanOrEqual(0);
    });

    it('ファクトのみ（ルールなし）の場合 iterations は 0', () => {
      const source = `
        parent("alice", "bob").
        ?- parent(X, Y).
      `;
      const result = evalDatalog(source);

      expect(result.stats.iterations).toBe(0);
      expect(result.stats.totalDerived).toBe(0);
    });
  });

  // ============================================================
  // columns の検証
  // ============================================================

  describe('columns の検証', () => {
    it('クエリ内の変数名が columns として返される', () => {
      const source = `?- parent(X, Y).`;
      const facts: Fact[] = [{ predicate: 'parent', values: ['alice', 'bob'] }];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].columns).toEqual(['X', 'Y']);
    });

    it('定数を含むクエリでは変数のみが columns に含まれる', () => {
      const source = `?- parent(X, "bob").`;
      const facts: Fact[] = [{ predicate: 'parent', values: ['alice', 'bob'] }];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].columns).toEqual(['X']);
    });

    it('変数がないクエリでは columns は空', () => {
      const source = `?- parent("alice", "bob").`;
      const facts: Fact[] = [{ predicate: 'parent', values: ['alice', 'bob'] }];
      const result = evalDatalog(source, facts);

      expect(result.answers[0].columns).toEqual([]);
      // マッチするので tuples は 1 つ
      expect(result.answers[0].tuples).toHaveLength(1);
    });
  });

  // ============================================================
  // 複数クエリ
  // ============================================================

  describe('複数クエリ', () => {
    it('複数のクエリそれぞれに対して回答を返す', () => {
      const source = `
        ?- parent(X, "bob").
        ?- parent("bob", Y).
      `;
      const facts: Fact[] = [
        { predicate: 'parent', values: ['alice', 'bob'] },
        { predicate: 'parent', values: ['bob', 'carol'] },
      ];
      const result = evalDatalog(source, facts);

      expect(result.answers).toHaveLength(2);
      expect(result.answers[0].tuples).toContainEqual(['alice', 'bob']);
      expect(result.answers[1].tuples).toContainEqual(['bob', 'carol']);
    });
  });
});

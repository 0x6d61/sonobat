import { describe, it, expect } from 'vitest';
import { parse } from '../../../src/engine/datalog/parser.js';
import { DatalogSyntaxError, DatalogSafetyError } from '../../../src/engine/datalog/types.js';

describe('Parser', () => {
  it('単純なファクト: parent("alice", "bob").', () => {
    const program = parse('parent("alice", "bob").');
    expect(program.rules).toHaveLength(1);
    expect(program.queries).toHaveLength(0);

    const rule = program.rules[0];
    expect(rule.head.predicate).toBe('parent');
    expect(rule.head.args).toHaveLength(2);
    expect(rule.head.args[0]).toEqual({ kind: 'constant', value: 'alice' });
    expect(rule.head.args[1]).toEqual({ kind: 'constant', value: 'bob' });
    expect(rule.body).toHaveLength(0);
  });

  it('単純なルール: ancestor(X, Y) :- parent(X, Y).', () => {
    const program = parse('ancestor(X, Y) :- parent(X, Y).');
    expect(program.rules).toHaveLength(1);

    const rule = program.rules[0];
    expect(rule.head.predicate).toBe('ancestor');
    expect(rule.head.args).toEqual([
      { kind: 'variable', name: 'X' },
      { kind: 'variable', name: 'Y' },
    ]);
    expect(rule.body).toHaveLength(1);
    expect(rule.body[0]).toEqual({
      kind: 'positive',
      atom: {
        predicate: 'parent',
        args: [
          { kind: 'variable', name: 'X' },
          { kind: 'variable', name: 'Y' },
        ],
      },
    });
  });

  it('複数ボディリテラルのルール: ancestor(X, Z) :- parent(X, Y), ancestor(Y, Z).', () => {
    const program = parse('ancestor(X, Z) :- parent(X, Y), ancestor(Y, Z).');
    expect(program.rules).toHaveLength(1);

    const rule = program.rules[0];
    expect(rule.head.predicate).toBe('ancestor');
    expect(rule.body).toHaveLength(2);

    expect(rule.body[0]).toEqual({
      kind: 'positive',
      atom: {
        predicate: 'parent',
        args: [
          { kind: 'variable', name: 'X' },
          { kind: 'variable', name: 'Y' },
        ],
      },
    });

    expect(rule.body[1]).toEqual({
      kind: 'positive',
      atom: {
        predicate: 'ancestor',
        args: [
          { kind: 'variable', name: 'Y' },
          { kind: 'variable', name: 'Z' },
        ],
      },
    });
  });

  it('否定: safe(X) :- node(X), not danger(X).', () => {
    const program = parse('safe(X) :- node(X), not danger(X).');
    expect(program.rules).toHaveLength(1);

    const rule = program.rules[0];
    expect(rule.body).toHaveLength(2);
    expect(rule.body[0]).toEqual({
      kind: 'positive',
      atom: {
        predicate: 'node',
        args: [{ kind: 'variable', name: 'X' }],
      },
    });
    expect(rule.body[1]).toEqual({
      kind: 'negated',
      atom: {
        predicate: 'danger',
        args: [{ kind: 'variable', name: 'X' }],
      },
    });
  });

  it('比較: big(X) :- size(X, N), N > 100.', () => {
    const program = parse('big(X) :- size(X, N), N > 100.');
    expect(program.rules).toHaveLength(1);

    const rule = program.rules[0];
    expect(rule.body).toHaveLength(2);
    expect(rule.body[1]).toEqual({
      kind: 'comparison',
      op: '>',
      left: { kind: 'variable', name: 'N' },
      right: { kind: 'constant', value: 100 },
    });
  });

  it('クエリ: ?- ancestor(X, "alice").', () => {
    const program = parse('?- ancestor(X, "alice").');
    expect(program.rules).toHaveLength(0);
    expect(program.queries).toHaveLength(1);

    const query = program.queries[0];
    expect(query.atom.predicate).toBe('ancestor');
    expect(query.atom.args).toEqual([
      { kind: 'variable', name: 'X' },
      { kind: 'constant', value: 'alice' },
    ]);
  });

  it('匿名変数: has_child(X) :- parent(X, _). — アンダースコアがユニーク変数にリネームされる', () => {
    const program = parse('has_child(X) :- parent(X, _).');
    expect(program.rules).toHaveLength(1);

    const rule = program.rules[0];
    const bodyArgs = rule.body[0];
    expect(bodyArgs.kind).toBe('positive');
    if (bodyArgs.kind === 'positive') {
      const secondArg = bodyArgs.atom.args[1];
      expect(secondArg.kind).toBe('variable');
      if (secondArg.kind === 'variable') {
        expect(secondArg.name).toMatch(/^_anon_\d+$/);
        // ユニーク変数名であること
        expect(secondArg.name).not.toBe('_');
      }
    }
  });

  it('複数の匿名変数がそれぞれ異なるユニーク名を持つ', () => {
    const program = parse('r(X) :- a(X, _), b(_, X).');
    const rule = program.rules[0];

    const names: string[] = [];
    for (const lit of rule.body) {
      if (lit.kind === 'positive') {
        for (const arg of lit.atom.args) {
          if (arg.kind === 'variable' && arg.name.startsWith('_anon_')) {
            names.push(arg.name);
          }
        }
      }
    }
    expect(names).toHaveLength(2);
    expect(names[0]).not.toBe(names[1]);
  });

  it('複数ルール + クエリを含むプログラム', () => {
    const source = `
      parent("alice", "bob").
      parent("bob", "carol").
      ancestor(X, Y) :- parent(X, Y).
      ancestor(X, Z) :- parent(X, Y), ancestor(Y, Z).
      ?- ancestor(X, "carol").
    `;
    const program = parse(source);
    expect(program.rules).toHaveLength(4);
    expect(program.queries).toHaveLength(1);

    // ファクトは空ボディのルール
    expect(program.rules[0].body).toHaveLength(0);
    expect(program.rules[1].body).toHaveLength(0);

    // 通常ルール
    expect(program.rules[2].body).toHaveLength(1);
    expect(program.rules[3].body).toHaveLength(2);

    // クエリ
    expect(program.queries[0].atom.predicate).toBe('ancestor');
  });

  it('文字列と数値の定数をアトム内で扱える', () => {
    const program = parse('score("alice", 95).');
    const rule = program.rules[0];
    expect(rule.head.args[0]).toEqual({ kind: 'constant', value: 'alice' });
    expect(rule.head.args[1]).toEqual({ kind: 'constant', value: 95 });
  });

  it('安全性違反: ヘッドの変数がボディに出現しない場合 DatalogSafetyError', () => {
    expect(() => parse('bad(X, Y) :- thing(X).')).toThrow(DatalogSafetyError);
  });

  it('空プログラム', () => {
    const program = parse('');
    expect(program.rules).toHaveLength(0);
    expect(program.queries).toHaveLength(0);
  });

  it('構文エラー: ルール末尾のドットが欠如', () => {
    expect(() => parse('parent("alice", "bob")')).toThrow(DatalogSyntaxError);
  });

  it('比較演算子すべてをパースできる', () => {
    const ops = ['=', '!=', '<', '>', '<=', '>='] as const;
    for (const op of ops) {
      const source = `check(X) :- val(X, N), N ${op} 10.`;
      const program = parse(source);
      expect(program.rules).toHaveLength(1);
      const cmp = program.rules[0].body[1];
      expect(cmp.kind).toBe('comparison');
      if (cmp.kind === 'comparison') {
        expect(cmp.op).toBe(op);
      }
    }
  });

  it('ファクトでは安全性チェックをスキップする（ボディなし）', () => {
    // ファクトはボディがないので、ヘッドの定数のみで有効
    const program = parse('fact("a", "b").');
    expect(program.rules).toHaveLength(1);
    expect(program.rules[0].body).toHaveLength(0);
  });

  it('コメント付きソースをパースできる', () => {
    const source = `
      % これは家族関係のファクト
      parent("alice", "bob").  % アリスはボブの親
      ?- parent(X, "bob").     % ボブの親は誰？
    `;
    const program = parse(source);
    expect(program.rules).toHaveLength(1);
    expect(program.queries).toHaveLength(1);
  });
});

import { describe, it, expect } from 'vitest';
import { tokenize } from '../../../src/engine/datalog/tokenizer.js';
import type { Token } from '../../../src/engine/datalog/types.js';
import { DatalogSyntaxError } from '../../../src/engine/datalog/types.js';

/** Helper: extract kinds from token array (excluding EOF) */
function kinds(tokens: Token[]): string[] {
  return tokens.filter((t) => t.kind !== 'EOF').map((t) => t.kind);
}

/** Helper: extract values from token array (excluding EOF) */
function values(tokens: Token[]): string[] {
  return tokens.filter((t) => t.kind !== 'EOF').map((t) => t.value);
}

describe('Tokenizer', () => {
  it('空文字列 → EOF のみ', () => {
    const tokens = tokenize('');
    expect(tokens).toHaveLength(1);
    expect(tokens[0].kind).toBe('EOF');
  });

  it('述語名（小文字始まり）を IDENT として認識', () => {
    const tokens = tokenize('host service http_endpoint');
    expect(values(tokens)).toEqual(['host', 'service', 'http_endpoint']);
    expect(kinds(tokens)).toEqual(['IDENT', 'IDENT', 'IDENT']);
  });

  it('変数（大文字始まり）を VARIABLE として認識', () => {
    const tokens = tokenize('X Host ServiceId');
    expect(values(tokens)).toEqual(['X', 'Host', 'ServiceId']);
    expect(kinds(tokens)).toEqual(['VARIABLE', 'VARIABLE', 'VARIABLE']);
  });

  it('アンダースコア（匿名変数）を UNDERSCORE として認識', () => {
    const tokens = tokenize('_');
    expect(kinds(tokens)).toEqual(['UNDERSCORE']);
  });

  it('文字列リテラルを認識（ダブルクォート）', () => {
    const tokens = tokenize('"hello" "world"');
    expect(values(tokens)).toEqual(['hello', 'world']);
    expect(kinds(tokens)).toEqual(['STRING', 'STRING']);
  });

  it('数値リテラルを認識（整数・小数）', () => {
    const tokens = tokenize('42 3.14 0');
    expect(values(tokens)).toEqual(['42', '3.14', '0']);
    expect(kinds(tokens)).toEqual(['NUMBER', 'NUMBER', 'NUMBER']);
  });

  it('記号トークンを認識', () => {
    const tokens = tokenize('( ) , .');
    expect(kinds(tokens)).toEqual(['LPAREN', 'RPAREN', 'COMMA', 'DOT']);
  });

  it(':- を COLON_DASH として認識', () => {
    const tokens = tokenize(':-');
    expect(kinds(tokens)).toEqual(['COLON_DASH']);
  });

  it('?- を QUERY として認識', () => {
    const tokens = tokenize('?-');
    expect(kinds(tokens)).toEqual(['QUERY']);
  });

  it('not を NOT として認識', () => {
    const tokens = tokenize('not');
    expect(kinds(tokens)).toEqual(['NOT']);
  });

  it('比較演算子を認識', () => {
    const tokens = tokenize('= != < > <= >=');
    expect(kinds(tokens)).toEqual(['EQ', 'NEQ', 'LT', 'GT', 'LTE', 'GTE']);
  });

  it('完全なルールをトークナイズ', () => {
    const tokens = tokenize('parent(X, Y) :- person(X), child_of(Y, X).');
    const expected = [
      'IDENT',
      'LPAREN',
      'VARIABLE',
      'COMMA',
      'VARIABLE',
      'RPAREN',
      'COLON_DASH',
      'IDENT',
      'LPAREN',
      'VARIABLE',
      'RPAREN',
      'COMMA',
      'IDENT',
      'LPAREN',
      'VARIABLE',
      'COMMA',
      'VARIABLE',
      'RPAREN',
      'DOT',
    ];
    expect(kinds(tokens)).toEqual(expected);
  });

  it('クエリをトークナイズ', () => {
    const tokens = tokenize('?- parent(X, "Alice").');
    expect(kinds(tokens)).toEqual([
      'QUERY',
      'IDENT',
      'LPAREN',
      'VARIABLE',
      'COMMA',
      'STRING',
      'RPAREN',
      'DOT',
    ]);
  });

  it('% コメントを無視', () => {
    const tokens = tokenize('host(X). % this is a comment\nservice(Y).');
    const idents = tokens.filter((t) => t.kind === 'IDENT');
    expect(idents.map((t) => t.value)).toEqual(['host', 'service']);
  });

  it('行番号・列番号を追跡', () => {
    const tokens = tokenize('foo\nbar');
    const foo = tokens.find((t) => t.value === 'foo');
    const bar = tokens.find((t) => t.value === 'bar');
    expect(foo?.line).toBe(1);
    expect(foo?.col).toBe(1);
    expect(bar?.line).toBe(2);
    expect(bar?.col).toBe(1);
  });

  it('閉じていない文字列でエラー', () => {
    expect(() => tokenize('"unclosed')).toThrow(DatalogSyntaxError);
  });

  it('不正な文字でエラー', () => {
    expect(() => tokenize('@')).toThrow(DatalogSyntaxError);
  });

  it('否定付きリテラルをトークナイズ', () => {
    const tokens = tokenize('safe(X) :- node(X), not danger(X).');
    const notIdx = tokens.findIndex((t) => t.kind === 'NOT');
    expect(notIdx).toBeGreaterThan(0);
    expect(tokens[notIdx + 1].kind).toBe('IDENT');
    expect(tokens[notIdx + 1].value).toBe('danger');
  });
});

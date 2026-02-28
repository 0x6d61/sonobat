/**
 * sonobat — Datalog tokenizer
 *
 * Single-pass character scanner that converts Datalog source text
 * into a token array. Tracks line/column numbers and supports % comments.
 */

import { DatalogSyntaxError } from './types.js';
import type { Token } from './types.js';

/**
 * Tokenize a Datalog source string into an array of tokens.
 * The last token is always EOF.
 */
export function tokenize(source: string): Token[] {
  const tokens: Token[] = [];
  let pos = 0;
  let line = 1;
  let col = 1;

  while (pos < source.length) {
    const ch = source[pos];

    // Whitespace
    if (ch === ' ' || ch === '\t' || ch === '\r') {
      pos++;
      col++;
      continue;
    }

    // Newline
    if (ch === '\n') {
      pos++;
      line++;
      col = 1;
      continue;
    }

    // Comment (% to end of line)
    if (ch === '%') {
      while (pos < source.length && source[pos] !== '\n') {
        pos++;
      }
      continue;
    }

    // String literal
    if (ch === '"') {
      const startCol = col;
      pos++;
      col++;
      let value = '';
      while (pos < source.length && source[pos] !== '"') {
        if (source[pos] === '\n') {
          throw new DatalogSyntaxError('Unterminated string literal', line, startCol);
        }
        if (source[pos] === '\\' && pos + 1 < source.length) {
          pos++;
          col++;
          const escaped = source[pos];
          if (escaped === '"') value += '"';
          else if (escaped === '\\') value += '\\';
          else if (escaped === 'n') value += '\n';
          else if (escaped === 't') value += '\t';
          else value += escaped;
        } else {
          value += source[pos];
        }
        pos++;
        col++;
      }
      if (pos >= source.length) {
        throw new DatalogSyntaxError('Unterminated string literal', line, startCol);
      }
      pos++; // skip closing quote
      col++;
      tokens.push({ kind: 'STRING', value, line, col: startCol });
      continue;
    }

    // Number literal
    if (ch >= '0' && ch <= '9') {
      const startCol = col;
      let value = '';
      while (pos < source.length && source[pos] >= '0' && source[pos] <= '9') {
        value += source[pos];
        pos++;
        col++;
      }
      // Decimal part
      if (
        pos < source.length &&
        source[pos] === '.' &&
        pos + 1 < source.length &&
        source[pos + 1] >= '0' &&
        source[pos + 1] <= '9'
      ) {
        value += '.';
        pos++;
        col++;
        while (pos < source.length && source[pos] >= '0' && source[pos] <= '9') {
          value += source[pos];
          pos++;
          col++;
        }
      }
      tokens.push({ kind: 'NUMBER', value, line, col: startCol });
      continue;
    }

    // Identifier, variable, keyword, or underscore
    if (isIdentStart(ch)) {
      const startCol = col;
      let value = '';
      while (pos < source.length && isIdentPart(source[pos])) {
        value += source[pos];
        pos++;
        col++;
      }

      // Keywords
      if (value === 'not') {
        tokens.push({ kind: 'NOT', value, line, col: startCol });
      } else if (value === '_') {
        tokens.push({ kind: 'UNDERSCORE', value, line, col: startCol });
      } else if (ch >= 'A' && ch <= 'Z') {
        tokens.push({ kind: 'VARIABLE', value, line, col: startCol });
      } else {
        tokens.push({ kind: 'IDENT', value, line, col: startCol });
      }
      continue;
    }

    // Underscore alone
    if (ch === '_') {
      const startCol = col;
      let value = '_';
      pos++;
      col++;
      while (pos < source.length && isIdentPart(source[pos])) {
        value += source[pos];
        pos++;
        col++;
      }
      if (value === '_') {
        tokens.push({ kind: 'UNDERSCORE', value, line, col: startCol });
      } else {
        // _something is treated as a variable
        tokens.push({ kind: 'VARIABLE', value, line, col: startCol });
      }
      continue;
    }

    // Single/multi-character symbols
    const startCol = col;

    if (ch === '(') {
      tokens.push({ kind: 'LPAREN', value: '(', line, col: startCol });
      pos++;
      col++;
      continue;
    }
    if (ch === ')') {
      tokens.push({ kind: 'RPAREN', value: ')', line, col: startCol });
      pos++;
      col++;
      continue;
    }
    if (ch === ',') {
      tokens.push({ kind: 'COMMA', value: ',', line, col: startCol });
      pos++;
      col++;
      continue;
    }
    if (ch === '.') {
      tokens.push({ kind: 'DOT', value: '.', line, col: startCol });
      pos++;
      col++;
      continue;
    }

    // :- (COLON_DASH)
    if (ch === ':' && pos + 1 < source.length && source[pos + 1] === '-') {
      tokens.push({ kind: 'COLON_DASH', value: ':-', line, col: startCol });
      pos += 2;
      col += 2;
      continue;
    }

    // ?- (QUERY)
    if (ch === '?' && pos + 1 < source.length && source[pos + 1] === '-') {
      tokens.push({ kind: 'QUERY', value: '?-', line, col: startCol });
      pos += 2;
      col += 2;
      continue;
    }

    // Comparison operators
    if (ch === '!' && pos + 1 < source.length && source[pos + 1] === '=') {
      tokens.push({ kind: 'NEQ', value: '!=', line, col: startCol });
      pos += 2;
      col += 2;
      continue;
    }
    if (ch === '<' && pos + 1 < source.length && source[pos + 1] === '=') {
      tokens.push({ kind: 'LTE', value: '<=', line, col: startCol });
      pos += 2;
      col += 2;
      continue;
    }
    if (ch === '>' && pos + 1 < source.length && source[pos + 1] === '=') {
      tokens.push({ kind: 'GTE', value: '>=', line, col: startCol });
      pos += 2;
      col += 2;
      continue;
    }
    if (ch === '<') {
      tokens.push({ kind: 'LT', value: '<', line, col: startCol });
      pos++;
      col++;
      continue;
    }
    if (ch === '>') {
      tokens.push({ kind: 'GT', value: '>', line, col: startCol });
      pos++;
      col++;
      continue;
    }
    if (ch === '=') {
      tokens.push({ kind: 'EQ', value: '=', line, col: startCol });
      pos++;
      col++;
      continue;
    }

    throw new DatalogSyntaxError(`Unexpected character '${ch}'`, line, col);
  }

  tokens.push({ kind: 'EOF', value: '', line, col });
  return tokens;
}

function isIdentStart(ch: string): boolean {
  return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

function isIdentPart(ch: string): boolean {
  return (
    (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch === '_'
  );
}

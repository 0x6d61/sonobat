/**
 * sonobat — Datalog recursive descent parser
 *
 * Converts a Datalog source string into a Program AST.
 * Calls the tokenizer to produce a token stream, then parses
 * rules, facts, and queries using a recursive descent approach.
 *
 * Grammar:
 *   program     = (rule | query)*
 *   rule        = atom ":-" body "." | atom "."
 *   query       = "?-" atom "."
 *   body        = bodyLiteral ("," bodyLiteral)*
 *   bodyLiteral = "not" atom | comparison | atom
 *   comparison  = term compOp term
 *   atom        = IDENT "(" termList ")"
 *   termList    = term ("," term)*
 *   term        = VARIABLE | STRING | NUMBER | UNDERSCORE
 *   compOp      = "=" | "!=" | "<" | ">" | "<=" | ">="
 */

import { tokenize } from './tokenizer.js';
import { DatalogSyntaxError, DatalogSafetyError } from './types.js';
import type {
  Token,
  TokenKind,
  Program,
  Rule,
  Query,
  Atom,
  BodyLiteral,
  Term,
  ComparisonOp,
} from './types.js';

/** Comparison operator token kinds */
const COMPARISON_OPS: ReadonlySet<TokenKind> = new Set(['EQ', 'NEQ', 'LT', 'GT', 'LTE', 'GTE']);

/** Map from token kind to ComparisonOp string */
const TOKEN_TO_COMP_OP: Readonly<Record<string, ComparisonOp>> = {
  EQ: '=',
  NEQ: '!=',
  LT: '<',
  GT: '>',
  LTE: '<=',
  GTE: '>=',
};

/**
 * Parse a Datalog source string into a Program AST.
 *
 * @param source - Datalog source code
 * @returns Parsed program containing rules and queries
 * @throws DatalogSyntaxError on parse failure
 * @throws DatalogSafetyError when a rule head contains unsafe variables
 */
export function parse(source: string): Program {
  const tokens = tokenize(source);
  const parser = new Parser(tokens);
  return parser.parseProgram();
}

/**
 * Recursive descent parser for Datalog.
 *
 * Maintains a cursor position into the token stream and provides
 * helper methods for peeking, advancing, and expecting tokens.
 */
class Parser {
  private readonly tokens: Token[];
  private pos: number;
  private anonCounter: number;

  constructor(tokens: Token[]) {
    this.tokens = tokens;
    this.pos = 0;
    this.anonCounter = 0;
  }

  // ===========================================================
  // Token stream helpers
  // ===========================================================

  /** Return the current token without advancing. */
  private peek(): Token {
    return this.tokens[this.pos];
  }

  /** Advance and return the consumed token. */
  private advance(): Token {
    const token = this.tokens[this.pos];
    this.pos++;
    return token;
  }

  /** If the current token matches `kind`, consume and return it; otherwise return null. */
  private match(kind: TokenKind): Token | null {
    if (this.peek().kind === kind) {
      return this.advance();
    }
    return null;
  }

  /** Consume the current token if it matches `kind`; throw if it does not. */
  private expect(kind: TokenKind): Token {
    const token = this.peek();
    if (token.kind !== kind) {
      throw new DatalogSyntaxError(
        `Expected ${kind}, got ${token.kind} ('${token.value}')`,
        token.line,
        token.col,
      );
    }
    return this.advance();
  }

  /** Generate a unique name for an anonymous variable. */
  private freshAnon(): string {
    const name = `_anon_${this.anonCounter}`;
    this.anonCounter++;
    return name;
  }

  // ===========================================================
  // Grammar productions
  // ===========================================================

  /** program = (rule | query)* EOF */
  parseProgram(): Program {
    const rules: Rule[] = [];
    const queries: Query[] = [];

    while (this.peek().kind !== 'EOF') {
      if (this.peek().kind === 'QUERY') {
        queries.push(this.parseQuery());
      } else {
        rules.push(this.parseRule());
      }
    }

    return { rules, queries };
  }

  /** query = "?-" atom "." */
  private parseQuery(): Query {
    this.expect('QUERY');
    const atom = this.parseAtom();
    this.expect('DOT');
    return { atom };
  }

  /**
   * rule = atom ":-" body "." | atom "."
   *
   * A fact (atom followed by ".") is represented as a rule with an empty body.
   * After parsing, safety validation is performed for non-fact rules.
   */
  private parseRule(): Rule {
    const head = this.parseAtom();

    let body: BodyLiteral[] = [];
    if (this.match('COLON_DASH')) {
      body = this.parseBody();
    }

    this.expect('DOT');

    const rule: Rule = { head, body };
    this.validateSafety(rule);
    return rule;
  }

  /** body = bodyLiteral ("," bodyLiteral)* */
  private parseBody(): BodyLiteral[] {
    const literals: BodyLiteral[] = [];
    literals.push(this.parseBodyLiteral());

    while (this.match('COMMA')) {
      literals.push(this.parseBodyLiteral());
    }

    return literals;
  }

  /**
   * bodyLiteral = "not" atom | comparison | atom
   *
   * Disambiguation logic:
   * - If the next token is NOT, parse a negated atom.
   * - If the next token is a VARIABLE or constant that could start a comparison
   *   (i.e. the token after it is a comparison operator), parse a comparison.
   * - Otherwise, parse a positive atom.
   */
  private parseBodyLiteral(): BodyLiteral {
    // Negation
    if (this.peek().kind === 'NOT') {
      this.advance();
      const atom = this.parseAtom();
      return { kind: 'negated', atom };
    }

    // Try to detect comparison: term compOp term
    if (this.isComparisonStart()) {
      return this.parseComparison();
    }

    // Positive atom
    const atom = this.parseAtom();
    return { kind: 'positive', atom };
  }

  /**
   * Detect whether the current position starts a comparison.
   *
   * A comparison starts with a term (VARIABLE, STRING, NUMBER, UNDERSCORE)
   * followed by a comparison operator. We look ahead to distinguish this
   * from an atom (which starts with IDENT followed by LPAREN).
   */
  private isComparisonStart(): boolean {
    const current = this.peek();
    // A comparison starts with a term, not an IDENT (atoms start with IDENT)
    if (
      current.kind === 'VARIABLE' ||
      current.kind === 'STRING' ||
      current.kind === 'NUMBER' ||
      current.kind === 'UNDERSCORE'
    ) {
      // Check if the next token after the term is a comparison op
      if (this.pos + 1 < this.tokens.length) {
        const next = this.tokens[this.pos + 1];
        return COMPARISON_OPS.has(next.kind);
      }
    }
    return false;
  }

  /** comparison = term compOp term */
  private parseComparison(): BodyLiteral {
    const left = this.parseTerm();
    const opToken = this.advance();
    if (!COMPARISON_OPS.has(opToken.kind)) {
      throw new DatalogSyntaxError(
        `Expected comparison operator, got ${opToken.kind}`,
        opToken.line,
        opToken.col,
      );
    }
    const op = TOKEN_TO_COMP_OP[opToken.kind];
    const right = this.parseTerm();
    return { kind: 'comparison', op, left, right };
  }

  /** atom = IDENT "(" termList ")" */
  private parseAtom(): Atom {
    const identToken = this.expect('IDENT');
    const predicate = identToken.value;

    this.expect('LPAREN');
    const args = this.parseTermList();
    this.expect('RPAREN');

    return { predicate, args };
  }

  /** termList = term ("," term)* */
  private parseTermList(): Term[] {
    const terms: Term[] = [];
    terms.push(this.parseTerm());

    while (this.match('COMMA')) {
      terms.push(this.parseTerm());
    }

    return terms;
  }

  /** term = VARIABLE | STRING | NUMBER | UNDERSCORE */
  private parseTerm(): Term {
    const token = this.peek();

    if (token.kind === 'VARIABLE') {
      this.advance();
      return { kind: 'variable', name: token.value };
    }

    if (token.kind === 'STRING') {
      this.advance();
      return { kind: 'constant', value: token.value };
    }

    if (token.kind === 'NUMBER') {
      this.advance();
      return { kind: 'constant', value: Number(token.value) };
    }

    if (token.kind === 'UNDERSCORE') {
      this.advance();
      return { kind: 'variable', name: this.freshAnon() };
    }

    throw new DatalogSyntaxError(
      `Expected term (variable, string, number, or _), got ${token.kind} ('${token.value}')`,
      token.line,
      token.col,
    );
  }

  // ===========================================================
  // Safety validation
  // ===========================================================

  /**
   * Validate that every variable in the rule head appears in at least
   * one positive body literal.
   *
   * Facts (rules with empty body) are exempt: their head may only
   * contain constants, or variables that are trivially safe because
   * there is no body at all. In standard Datalog, facts should only
   * have constants, but we allow variable-free heads to pass.
   *
   * @throws DatalogSafetyError if a head variable is not grounded
   */
  private validateSafety(rule: Rule): void {
    // Facts (empty body) are exempt from safety checks
    if (rule.body.length === 0) {
      return;
    }

    // Collect variables from positive body literals
    const positiveVars = new Set<string>();
    for (const literal of rule.body) {
      if (literal.kind === 'positive') {
        for (const arg of literal.atom.args) {
          if (arg.kind === 'variable') {
            positiveVars.add(arg.name);
          }
        }
      }
    }

    // Check that every head variable appears in positiveVars
    for (const arg of rule.head.args) {
      if (arg.kind === 'variable') {
        if (!positiveVars.has(arg.name)) {
          throw new DatalogSafetyError(
            `Unsafe variable '${arg.name}' in head of rule '${rule.head.predicate}': ` +
              `it does not appear in any positive body literal`,
          );
        }
      }
    }
  }
}

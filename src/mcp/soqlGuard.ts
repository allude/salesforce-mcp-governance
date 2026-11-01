/**
 * Validates the caller-supplied `whereClause` of `soql_query` so it can only filter on fields the
 * caller's Profile may read. It accepts field names, literals (strings, numbers, dates, date
 * literals such as LAST_N_DAYS:30), comparison operators, AND / OR / NOT, LIKE, IN, INCLUDES and
 * EXCLUDES. Anything else (subqueries, other objects, bind variables, comments) is rejected.
 */

import { PolicyViolationError } from '../rbac/policyEngine.js';

const MAX_WHERE_CLAUSE_LENGTH = 2000;

const WHERE_KEYWORDS = new Set(['AND', 'OR', 'NOT', 'LIKE', 'IN', 'INCLUDES', 'EXCLUDES', 'NULL', 'TRUE', 'FALSE']);

const DATE_LITERALS = new Set([
  'YESTERDAY', 'TODAY', 'TOMORROW',
  'LAST_WEEK', 'THIS_WEEK', 'NEXT_WEEK',
  'LAST_MONTH', 'THIS_MONTH', 'NEXT_MONTH',
  'LAST_90_DAYS', 'NEXT_90_DAYS',
  'THIS_QUARTER', 'LAST_QUARTER', 'NEXT_QUARTER',
  'THIS_YEAR', 'LAST_YEAR', 'NEXT_YEAR',
  'THIS_FISCAL_QUARTER', 'LAST_FISCAL_QUARTER', 'NEXT_FISCAL_QUARTER',
  'THIS_FISCAL_YEAR', 'LAST_FISCAL_YEAR', 'NEXT_FISCAL_YEAR',
]);

const DATE_N_LITERAL = /^(LAST|NEXT)_N_(DAYS|WEEKS|MONTHS|QUARTERS|YEARS|FISCAL_QUARTERS|FISCAL_YEARS):\d+$|^N_(DAYS|WEEKS|MONTHS|QUARTERS|YEARS|FISCAL_QUARTERS|FISCAL_YEARS)_AGO:\d+$/;

// Order matters: the first alternative that matches at the current position wins.
const TOKEN_PATTERN = new RegExp(
  [
    String.raw`(?<ws>\s+)`,
    String.raw`(?<string>'(?:[^'\\\r\n]|\\.)*')`,
    String.raw`(?<datetime>\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2}))?(?![\w:.-]))`,
    String.raw`(?<number>-?\d+(?:\.\d+)?(?![\w.]))`,
    String.raw`(?<operator>!=|<>|<=|>=|=|<|>)`,
    String.raw`(?<punct>[(),])`,
    String.raw`(?<word>[A-Za-z_][A-Za-z0-9_]*(?::\d+)?)`,
  ].join('|'),
  'y'
);

export function assertSafeSoqlWhereClause(whereClause: string, allowedFields: string[]): void {
  if (whereClause.length > MAX_WHERE_CLAUSE_LENGTH) {
    throw new Error(`whereClause is longer than ${MAX_WHERE_CLAUSE_LENGTH} characters.`);
  }

  const permitted = new Set(['id', ...allowedFields.map((f) => f.toLowerCase())]);
  let depth = 0;
  let position = 0;

  while (position < whereClause.length) {
    TOKEN_PATTERN.lastIndex = position;
    const match = TOKEN_PATTERN.exec(whereClause);
    if (!match || !match.groups) {
      throw new Error(`whereClause contains an unsupported character at position ${position + 1}.`);
    }
    position = TOKEN_PATTERN.lastIndex;

    const { punct, word } = match.groups;
    if (punct === '(') depth++;
    if (punct === ')') {
      depth--;
      if (depth < 0) throw new Error('whereClause has unbalanced parentheses.');
    }

    if (word) {
      const upper = word.toUpperCase();
      if (WHERE_KEYWORDS.has(upper) || DATE_LITERALS.has(upper) || DATE_N_LITERAL.test(upper)) continue;
      if (word.includes(':') || !permitted.has(word.toLowerCase())) {
        throw new PolicyViolationError(`whereClause references '${word}', which is not an allowed field for this Profile.`);
      }
    }
  }

  if (depth !== 0) {
    throw new Error('whereClause has unbalanced parentheses.');
  }
}

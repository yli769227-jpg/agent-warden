/**
 * Unit tests for the trusted render layer (src/render/html.ts).
 */

/// <reference types="jest" />
import {
  escapeHtml,
  jsonForScript,
  escapeDotString,
  CLIENT_ESC_FN,
} from '../../src/render/html.js';

describe('escapeHtml', () => {
  test('escapes the five significant characters', () => {
    expect(escapeHtml('<a href="x">&</a>')).toBe(
      '&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;',
    );
  });
  test('null/undefined become empty string', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
  });
  test('coerces non-strings', () => {
    expect(escapeHtml(42)).toBe('42');
  });
});

describe('jsonForScript', () => {
  test('neutralizes a </script> breakout in string values', () => {
    const out = jsonForScript({ tool: 'x</script><img onerror=alert(1)>' });
    expect(out).not.toContain('</script>');
    expect(out).toContain('\\u003c/script\\u003e');
    // Still parses back to the original value.
    expect(JSON.parse(out).tool).toBe('x</script><img onerror=alert(1)>');
  });

  test('escapes U+2028 / U+2029 line separators', () => {
    const s = 'a\u2028b\u2029c';
    const out = jsonForScript({ s });
    expect(out).toContain('\\u2028');
    expect(out).toContain('\\u2029');
    expect(out).not.toContain('\u2028');
    expect(out).not.toContain('\u2029');
    expect(JSON.parse(out).s).toBe(s);
  });

  test('escapes ampersand', () => {
    expect(jsonForScript({ x: 'a&b' })).toContain('\\u0026');
  });
});

describe('escapeDotString', () => {
  test('escapes quotes and backslashes for DOT labels', () => {
    expect(escapeDotString('a"b\\c')).toBe('a\\"b\\\\c');
  });
  test('quote-injection cannot add DOT attributes', () => {
    const evil = 'x" color="red';
    const escaped = escapeDotString(evil);
    // Every quote is backslash-escaped, so none can close the DOT string and
    // start a new attribute. Exact form fully pins the behavior.
    expect(escaped).toBe('x\\" color=\\"red');
    // No bare (un-backslashed) double quote remains.
    expect(/(^|[^\\])"/.test(escaped)).toBe(false);
  });
});

describe('CLIENT_ESC_FN', () => {
  test('is a valid esc() definition producing the same result as escapeHtml', () => {
    // eslint-disable-next-line no-new-func
    const esc = new Function(`${CLIENT_ESC_FN} return esc;`)() as (s: unknown) => string;
    for (const v of ['<b>&"x"', null, undefined, 7]) {
      expect(esc(v)).toBe(escapeHtml(v as unknown));
    }
  });
});

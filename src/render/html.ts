/**
 * Trusted rendering helpers for agent-warden report output.
 *
 * Audit data (tool names, args, reasons) originates from downstream MCP servers
 * and is attacker-influenced. Every place that emits it into HTML, an inline
 * <script> data island, or a Graphviz DOT file MUST route the value through one
 * of these helpers so escaping lives in exactly one reviewed spot instead of
 * being re-implemented (and forgotten) per template.
 */

/**
 * Escapes the five characters that matter for HTML text and double-quoted
 * attribute contexts. Safe for both `>text<` and `attr="..."` positions.
 */
export function escapeHtml(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Serializes a value to JSON that is safe to inline inside a live `<script>`
 * block. JSON.stringify does NOT escape `</script>` or the U+2028/U+2029 line
 * separators, so a string containing `</script><img onerror=...>` would break
 * out of the script element. We escape the script-hostile characters into
 * `\uXXXX` form; the result is still valid JSON and valid JavaScript.
 */
export function jsonForScript(obj: unknown): string {
  return JSON.stringify(obj)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

/**
 * The client-side escape function, emitted verbatim into generated HTML so the
 * browser can escape values it builds into innerHTML at runtime. Kept here (as
 * a string) next to its server-side twin so the two definitions stay aligned.
 */
export const CLIENT_ESC_FN =
  "const esc=s=>String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');";

/**
 * Escapes a string for use inside a double-quoted Graphviz DOT identifier or
 * label. Backslashes are escaped first so we don't double-escape the quote
 * replacements.
 */
export function escapeDotString(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/\\/g, '\\\\')
    .replace(/"/g, '\\"');
}

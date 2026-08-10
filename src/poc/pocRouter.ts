/**
 * Phase F — POC router.
 *
 * Decides which backend handles a POC based on the vulnerability type.
 *
 * - DOM vulns (XSS) → Lightpanda (needs a real browser to render JS/DOM)
 * - HTTP vulns (SQLi, SSRF, redirect) → HTTP executor (raw HTTP suffices)
 * - Non-web vulns (command injection, proto pollution, crypto) → none
 *   (already proven deterministically by the taint tracker / guard evaluator)
 */

/** Which backend should handle this POC. */
export type PocBackend = 'lightpanda' | 'http' | 'none';

/** Vulnerability types that need a real browser (DOM rendering). */
const DOM_VULN_TYPES = new Set([
    'xss',
]);

/** Vulnerability types that can be verified via raw HTTP. */
const HTTP_VULN_TYPES = new Set([
    'sql_injection',
    'nosql_injection',
    'ssrf',
    'open_redirect',
    'broken_access_control',
]);

/**
 * Route a POC to the appropriate backend based on the vulnerability type.
 *
 * Returns 'none' for vulnerability types that are already covered by
 * deterministic analysis (taint tracker, guard evaluator) and don't
 * benefit from runtime POC verification.
 */
export function routePoc(vulnType: string): PocBackend {
    if (DOM_VULN_TYPES.has(vulnType)) return 'lightpanda';
    if (HTTP_VULN_TYPES.has(vulnType)) return 'http';
    return 'none';
}

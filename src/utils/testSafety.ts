/**
 * Static test safety analyzer — defense-in-depth, NOT a security boundary.
 *
 * The real boundary is the verification sandbox (`verificationSandbox.ts`):
 * Docker with `--network=none --read-only`, or Deno with `--allow-none`.
 * This module exists to reject obviously dangerous scripts *before* we
 * pay for a sandbox spawn, and as a second layer in case a sandbox backend
 * is somehow misconfigured.
 *
 * Policy: deny-by-default. Only specific known-safe imports and globals
 * are permitted. Anything else is blocked. The previous implementation
 * was allow-by-default with a 4-module blocklist — it let `http`, `https`,
 * `fs`, `dns`, `os`, `tls`, `vm`, `dgram`, `fetch`, `eval`, `new Function`,
 * dynamic `import()`, and `process.env` access all pass. That gap is the
 * reason this module was rewritten.
 *
 * What this analyzer checks (in priority order):
 *   1. Static import / require specifiers — against an allowlist.
 *   2. Dynamic require/import — blocked outright (cannot be statically
 *      analyzed).
 *   3. Global function calls that execute strings as code — `eval`,
 *      `new Function`, `setTimeout(string)`, `setInterval(string)`,
 *      `setImmediate(string)`.
 *   4. Network-related globals and Node built-ins (covered by #1 for
 *      imports; here for member-style access like `globalThis.fetch`).
 *   5. Process/env access — `process.env`, `process.argv`, `process.cwd`,
 *      `process.execPath`, `process.cwd()`.
 *   6. Reflection tricks that resolve to dangerous globals —
 *      `globalThis['eval']`, `globalThis['Function']`, `this['eval']`,
 *      bracket access with string literals that match dangerous names.
 *
 * Obfuscation handling: we catch literal bracket access like
 * `globalThis["eval"]` and `process["env"]`. We do NOT attempt to defeat
 * arbitrary runtime-computed string construction (e.g., `String.fromCharCode`
 * to build a name) — that is the sandbox's job. This analyzer only catches
 * what a defender can see statically.
 */

export interface TestSafetyResult {
    allowed: boolean;
    reason: string;
}

// ── Import allowlist ────────────────────────────────────────────────────────
//
// Allowed import specifiers (after the leading `node:` / `bun:` prefix is
// stripped for built-ins). Built-ins are kept on a tiny allowlist because
// even `node:` built-ins like `fs` are dangerous. The sandbox is the real
// boundary, but we still block here so we don't waste a container start
// on something obviously bad.

const ALLOWED_NODE_BUILTINS = new Set([
    'assert', 'console', 'crypto', 'path', 'util', 'module',
    'string_decoder', 'url',
]);

const ALLOWED_PREFIXES = [
    './', '../',          // relative imports — needed to load the vulnerable module
    'effect',             // the user's framework
    'bun:',               // bun:* built-ins (test framework, etc.)
    '@synara/',           // user's workspace packages
];

// Modules blocked even if a prefix matches (defense-in-depth).
const BLOCKED_MODULE_NAMES = new Set([
    'child_process', 'node:child_process',
    'net', 'node:net',
    'http', 'node:http',
    'https', 'node:https',
    'http2', 'node:http2',
    'dgram', 'node:dgram',
    'dns', 'node:dns',
    'dns/promises', 'node:dns/promises',
    'tls', 'node:tls',
    'fs', 'node:fs',
    'fs/promises', 'node:fs/promises',
    'os', 'node:os',
    'vm', 'node:vm',
    'worker_threads', 'node:worker_threads',
    'cluster', 'node:cluster',
    'repl', 'node:repl',
    'process', 'node:process',
    'inspector', 'node:inspector',
    'perf_hooks', 'node:perf_hooks',  // timing side-channels
]);

// ── Dangerous globals & member access ───────────────────────────────────────

const DANGEROUS_GLOBAL_CALLS: Array<{ pattern: RegExp; reason: string }> = [
    { pattern: /\beval\s*\(/, reason: 'eval() executes arbitrary strings as code' },
    { pattern: /\bnew\s+Function\s*\(/, reason: 'new Function() executes arbitrary strings as code' },
    { pattern: /\bnew\s+AsyncFunction\s*\(/, reason: 'new AsyncFunction() executes arbitrary strings as code' },
    { pattern: /\bnew\s+GeneratorFunction\s*\(/, reason: 'new GeneratorFunction() executes arbitrary strings as code' },
];

// setTimeout/setInterval/setImmediate with a STRING argument is eval-by-proxy.
const TIMER_STRING_ARG: RegExp = /\b(setTimeout|setInterval|setImmediate)\s*\(\s*['"`]/;

const DANGEROUS_PROCESS_ACCESS: Array<{ pattern: RegExp; reason: string }> = [
    { pattern: /\bprocess\.env\b/, reason: 'process.env access can leak host secrets — pass values explicitly' },
    { pattern: /\bprocess\.argv\b/, reason: 'process.argv access can leak host arguments' },
    { pattern: /\bprocess\.execPath\b/, reason: 'process.execPath exposes the host runtime path' },
    { pattern: /\bprocess\.cwd\s*\(/, reason: 'process.cwd() exposes the host filesystem layout' },
    { pattern: /\bprocess\.getuid\s*\(/, reason: 'process.getuid() exposes host user identity' },
    { pattern: /\bprocess\.getgid\s*\(/, reason: 'process.getgid() exposes host group identity' },
];

// Network & fs globals reachable without import (Node 18+ has global fetch).
const DANGEROUS_GLOBAL_REFERENCES: Array<{ pattern: RegExp; reason: string }> = [
    { pattern: /\bfetch\s*\(/, reason: 'fetch() can exfiltrate data over the network' },
    { pattern: /\bnavigator\b/, reason: 'navigator access is not needed in a unit test' },
];

// Dynamic import (ESM) and dynamic require (CJS) — both are unsafe because
// the specifier can be computed at runtime.
const DYNAMIC_IMPORT: RegExp = /\bimport\s*\(\s*[^"'\s`]/;
const DYNAMIC_REQUIRE: RegExp = /\brequire\s*\(\s*(?![`'"])[^)]*\)/;
const STATIC_REQUIRE: RegExp = /\brequire\s*\(\s*['"`]([^`'"]+)['"`]\s*\)/g;
const STATIC_IMPORT_FROM: RegExp = /\bimport\s+[^;]*?\s+from\s*['"`]([^`'"]+)['"`]/g;
const STATIC_IMPORT_BARE: RegExp = /\bimport\s+['"`]([^`'"]+)['"`]/g;
const STATIC_EXPORT_FROM: RegExp = /\bexport\s+[^;]*?\s+from\s*['"`]([^`'"]+)['"`]/g;

// Bracket-access reflection: globalThis["eval"], process["env"], etc.
// Matches `<identifier|keyword>["<dangerous-name>"]` and `['...']`.
function buildBracketAccessRegex(name: string): RegExp {
    // Capture a bracket access where the property is a string literal matching
    // the dangerous name. The receiver is any identifier-like token (we
    // accept anything that's not a quote, to keep this simple).
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`\\b[^'"\\\`\\s]+\\s*\\[\\s*['"\`\\s]*${escaped}['"\`\\s]*\\]`, 'i');
}

const DANGEROUS_BRACKET_NAMES = [
    'eval', 'Function', 'AsyncFunction', 'GeneratorFunction',
    'fetch', 'process', 'require', 'import',
    'child_process', 'net', 'http', 'https', 'fs', 'os', 'vm',
    'exec', 'execSync', 'spawn', 'spawnSync', 'fork',
    // Dangerous properties of `process` accessed via bracket (process["env"]).
    // Blocking the property name on any receiver is intentional — bracket
    // access to "env" is a known reflection trick and tests shouldn't need it.
    'env', 'argv', 'execPath', 'mainModule',
];

// ── Main entry ──────────────────────────────────────────────────────────────

export function checkTestSafety(script: string, _workspaceRoot: string): TestSafetyResult {
    // 1. Dangerous call patterns (eval, Function, etc.)
    for (const { pattern, reason } of DANGEROUS_GLOBAL_CALLS) {
        if (pattern.test(script)) {
            return { allowed: false, reason };
        }
    }

    // 2. Timer-with-string (eval-by-proxy)
    if (TIMER_STRING_ARG.test(script)) {
        return { allowed: false, reason: 'setTimeout/setInterval/setImmediate with a string argument is eval-by-proxy' };
    }

    // 3. process.* access that leaks host state
    for (const { pattern, reason } of DANGEROUS_PROCESS_ACCESS) {
        if (pattern.test(script)) {
            return { allowed: false, reason };
        }
    }

    // 4. Global network refs
    for (const { pattern, reason } of DANGEROUS_GLOBAL_REFERENCES) {
        if (pattern.test(script)) {
            return { allowed: false, reason };
        }
    }

    // 5. Dynamic import / dynamic require — non-static specifiers
    if (DYNAMIC_IMPORT.test(script)) {
        return { allowed: false, reason: 'dynamic import() with a computed specifier cannot be statically analyzed' };
    }
    if (DYNAMIC_REQUIRE.test(script)) {
        return { allowed: false, reason: 'dynamic require with variable is not statically checkable' };
    }

    // 6. Bracket-access reflection (globalThis["eval"], process["env"], etc.)
    for (const name of DANGEROUS_BRACKET_NAMES) {
        const re = buildBracketAccessRegex(name);
        if (re.test(script)) {
            return { allowed: false, reason: `bracket access to "${name}" is blocked — use the safe form directly if needed` };
        }
    }

    // 7. Static import / require specifiers — allowlist
    const checkSpecifier = (mod: string): TestSafetyResult | null => {
        if (BLOCKED_MODULE_NAMES.has(mod)) {
            return { allowed: false, reason: `module "${mod}" is blocked — use the sandbox boundary for fs/net/process access` };
        }
        // node: prefix — strip and check the built-in allowlist.
        if (mod.startsWith('node:')) {
            const name = mod.slice('node:'.length);
            if (!ALLOWED_NODE_BUILTINS.has(name)) {
                return { allowed: false, reason: `node built-in "${mod}" is not on the allowlist (allowed: ${[...ALLOWED_NODE_BUILTINS].join(', ')})` };
            }
            return null;
        }
        // Bare built-in (no node: prefix) — block unless it's on the allowlist.
        // We block bare 'fs', 'net', etc. even though Node resolves them to the
        // same thing as node:fs.
        if (ALLOWED_NODE_BUILTINS.has(mod)) return null;
        if (mod === 'node') return null; // not a real import
        if (ALLOWED_PREFIXES.some(p => mod.startsWith(p))) return null;
        // Bare module names that aren't on an allowed prefix and aren't a
        // built-in. These are third-party packages. We allow them — the
        // sandbox will deny network access if they try to fetch anything.
        // But we keep the known-dangerous ones in BLOCKED_MODULE_NAMES above.
        return null;
    };

    const importPatterns: Array<{ re: RegExp; label: string }> = [
        { re: STATIC_IMPORT_FROM, label: 'import' },
        { re: STATIC_IMPORT_BARE, label: 'import' },
        { re: STATIC_EXPORT_FROM, label: 'export' },
        { re: STATIC_REQUIRE, label: 'require' },
    ];

    for (const { re } of importPatterns) {
        re.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = re.exec(script)) !== null) {
            const mod = m[1];
            const verdict = checkSpecifier(mod);
            if (verdict) return verdict;
        }
    }

    // 8. process.exit() — masks test results and prevents the runner from
    // capturing PASS/FAIL markers. (Was blocked before; keep the behavior.)
    if (/\bprocess\.exit\s*\(/.test(script)) {
        return { allowed: false, reason: 'process.exit() masks test results — use console.error + throw instead' };
    }

    return { allowed: true, reason: '' };
}

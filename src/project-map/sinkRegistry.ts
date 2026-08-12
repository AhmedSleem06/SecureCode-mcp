/**
 * Phase B — declarative sink registry for the AST sink finder.
 *
 * Each entry describes a dangerous operation (a "sink") that the finder
 * matches against the parsed AST. The registry is deliberately conservative
 * on false negatives (high recall): a missed sink is a missed vulnerability,
 * while a false sink is dismissed by the Juror at no structural cost.
 *
 * The canonical types mirror `api/src/services/taxonomy.ts` CANONICAL_TYPES
 * so the API can consume findings without translation.
 */

/** Languages supported by the tree-sitter grammars we ship. */
export type SinkLanguage = 'javascript' | 'typescript' | 'tsx' | 'python';

/** How a sink is matched in the AST. */
export type SinkMatcher =
    | {
        kind: 'call';
        /** The method name being called: `exec`, `eval`, `query`, `system`. */
        method: string;
        /**
         * The base identifier the call is rooted at, or:
         *  - `undefined` → match only bare calls (no receiver): `eval(...)`
         *  - `'*'`       → match any receiver: `x.query(...)`, `query(...)`
         *  - a string    → match that exact receiver: `child_process.exec(...)`
         */
        receiver?: string | '*';
    }
    | {
        kind: 'member-assignment';
        /** The property being assigned: `innerHTML`, `outerHTML`, `href`. */
        property: string;
    }
    | {
        kind: 'jsx-attribute';
        /** The JSX attribute name: `dangerouslySetInnerHTML`. */
        name: string;
    };

export interface SinkDefinition {
    /** Stable id for dedup/logging: 'exec', 'eval', 'inner-html'. */
    id: string;
    /** Canonical vulnerability type (matches API taxonomy). */
    canonicalType: string;
    severity: 'Critical' | 'High' | 'Medium';
    languages: SinkLanguage[];
    matchers: SinkMatcher[];
    /**
     * Only report when at least one argument is non-literal (identifier,
     * template with interpolation, binary expression, or call expression).
     * Use for sinks where a literal argument is definitively safe:
     * `res.redirect("/home")`, `fs.readFile("config.json")`,
     * `db.query("SELECT * FROM users")`.
     */
    requireNonLiteralArg?: boolean;
    description: string;
}

/**
 * The sink registry. Superset of the 11 regex rules in
 * `api/src/services/sinkFloorService.ts` plus Python sinks.
 *
 * Ordering is by severity (Critical first) so the finder, which stops at the
 * first match per call site, prefers the most severe reading.
 */
export const SINK_REGISTRY: SinkDefinition[] = [
    // ── Command injection (JS/TS/TSX) ──────────────────────────────────────
    {
        id: 'exec',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [
            { kind: 'call', method: 'exec' },                // bare: const { exec } = require('child_process'); exec(cmd)
            { kind: 'call', method: 'exec', receiver: 'child_process' },
        ],
        description: 'child_process.exec / destructured exec — shell command execution',
    },
    {
        id: 'spawn',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [
            { kind: 'call', method: 'spawn' },                    // bare: const { spawn } = require('child_process'); spawn(cmd)
            { kind: 'call', method: 'spawn', receiver: 'child_process' },
        ],
        description: 'child_process.spawn — process spawning',
    },
    {
        id: 'execFile',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [
            { kind: 'call', method: 'execFile' },
            { kind: 'call', method: 'execFile', receiver: 'child_process' },
        ],
        description: 'child_process.execFile — file execution',
    },
    {
        id: 'fork',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [
            { kind: 'call', method: 'fork' },
            { kind: 'call', method: 'fork', receiver: 'child_process' },
        ],
        description: 'child_process.fork — process forking',
    },
    {
        id: 'eval',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx', 'python'],
        matchers: [{ kind: 'call', method: 'eval' }],
        description: 'eval() — arbitrary code execution',
    },
    {
        id: 'Function',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [{ kind: 'call', method: 'Function' }],
        description: 'Function() constructor — code execution from string',
    },

    // ── Command injection (Python) ─────────────────────────────────────────
    {
        id: 'os.system',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['python'],
        matchers: [{ kind: 'call', method: 'system', receiver: 'os' }],
        description: 'os.system() — shell command execution',
    },
    {
        id: 'subprocess',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['python'],
        matchers: [
            { kind: 'call', method: 'call', receiver: 'subprocess' },
            { kind: 'call', method: 'Popen', receiver: 'subprocess' },
            { kind: 'call', method: 'run', receiver: 'subprocess' },
            { kind: 'call', method: 'check_output', receiver: 'subprocess' },
        ],
        description: 'subprocess.* — process execution',
    },
    {
        id: 'py-exec',
        canonicalType: 'command_injection',
        severity: 'Critical',
        languages: ['python'],
        matchers: [{ kind: 'call', method: 'exec' }],
        description: 'Python exec() — arbitrary code execution',
    },

    // ── SQL injection (JS/TS/TSX) ──────────────────────────────────────────
    {
        id: 'queryRaw',
        canonicalType: 'sql_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [{ kind: 'call', method: '$queryRaw', receiver: '*' }],
        requireNonLiteralArg: true,
        description: 'Prisma $queryRaw with interpolation — SQL injection',
    },
    {
        id: 'sql-concat',
        canonicalType: 'sql_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [{ kind: 'call', method: 'query', receiver: '*' }],
        requireNonLiteralArg: true,
        description: 'db.query with non-literal argument — potential SQL injection',
    },
    {
        id: 'sql-prepare',
        canonicalType: 'sql_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [{ kind: 'call', method: 'prepare', receiver: '*' }],
        requireNonLiteralArg: true,
        description: 'db.prepare with non-literal argument — potential SQL injection (node:sqlite, better-sqlite3)',
    },
    {
        id: 'sql-exec',
        canonicalType: 'sql_injection',
        severity: 'Critical',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [
            { kind: 'call', method: 'exec', receiver: '*' },
            { kind: 'call', method: 'execute', receiver: '*' },
        ],
        requireNonLiteralArg: true,
        description: 'db.exec/execute with non-literal argument — potential SQL injection',
    },

    // ── SQL injection (Python) ─────────────────────────────────────────────
    {
        id: 'cursor-execute',
        canonicalType: 'sql_injection',
        severity: 'Critical',
        languages: ['python'],
        matchers: [{ kind: 'call', method: 'execute', receiver: '*' }],
        requireNonLiteralArg: true,
        description: 'cursor.execute with non-literal argument — potential SQL injection',
    },

    // ── XSS (JS/TS/TSX) ────────────────────────────────────────────────────
    {
        id: 'dangerouslySetInnerHTML',
        canonicalType: 'xss',
        severity: 'High',
        languages: ['tsx'],
        matchers: [{ kind: 'jsx-attribute', name: 'dangerouslySetInnerHTML' }],
        description: 'React dangerouslySetInnerHTML — XSS via DOM injection',
    },
    {
        id: 'innerHTML',
        canonicalType: 'xss',
        severity: 'High',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [{ kind: 'member-assignment', property: 'innerHTML' }],
        requireNonLiteralArg: true,
        description: '.innerHTML assignment — XSS via DOM injection',
    },

    // ── Open redirect (JS/TS/TSX) ──────────────────────────────────────────
    {
        id: 'res.redirect',
        canonicalType: 'open_redirect',
        severity: 'Medium',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [{ kind: 'call', method: 'redirect', receiver: '*' }],
        requireNonLiteralArg: true,
        description: 'res.redirect with non-literal argument — open redirect',
    },

    // ── Path traversal (JS/TS/TSX) ──────────────────────────────────────────
    {
        id: 'fs-read-write',
        canonicalType: 'path_traversal',
        severity: 'High',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [
            { kind: 'call', method: 'readFile', receiver: 'fs' },
            { kind: 'call', method: 'readFileSync', receiver: 'fs' },
            { kind: 'call', method: 'writeFile', receiver: 'fs' },
            { kind: 'call', method: 'writeFileSync', receiver: 'fs' },
            { kind: 'call', method: 'createReadStream', receiver: 'fs' },
            { kind: 'call', method: 'createWriteStream', receiver: 'fs' },
        ],
        requireNonLiteralArg: true,
        description: 'fs.readFile/writeFile with non-literal path — path traversal',
    },

    // ── Path traversal (Python) ─────────────────────────────────────────────
    {
        id: 'py-open',
        canonicalType: 'path_traversal',
        severity: 'High',
        languages: ['python'],
        matchers: [{ kind: 'call', method: 'open' }],
        requireNonLiteralArg: true,
        description: 'open() with non-literal path — path traversal',
    },

    // ── Insecure crypto (JS/TS/TSX) ─────────────────────────────────────────
    {
        id: 'createCipher',
        canonicalType: 'insecure_crypto',
        severity: 'Medium',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [
            { kind: 'call', method: 'createCipher', receiver: 'crypto' },
            { kind: 'call', method: 'createDecipher', receiver: 'crypto' },
        ],
        description: 'crypto.createCipher/createDecipher — deprecated, use createCipheriv',
    },

    // ── Prototype pollution (JS/TS/TSX) ────────────────────────────────────
    {
        id: 'proto-merge',
        canonicalType: 'prototype_pollution',
        severity: 'High',
        languages: ['javascript', 'typescript', 'tsx'],
        matchers: [
            { kind: 'call', method: 'merge', receiver: '*' },
            { kind: 'call', method: 'defaultsDeep', receiver: '*' },
            { kind: 'call', method: 'deepCopy', receiver: '*' },
            { kind: 'call', method: 'extend', receiver: '*' },
        ],
        requireNonLiteralArg: true,
        description: 'Object merge/extend with user input — prototype pollution',
    },

    // ── Insecure deserialization (Python) ───────────────────────────────────
    {
        id: 'pickle-loads',
        canonicalType: 'insecure_deserialization',
        severity: 'High',
        languages: ['python'],
        matchers: [
            { kind: 'call', method: 'loads', receiver: 'pickle' },
            { kind: 'call', method: 'load', receiver: 'pickle' },
        ],
        description: 'pickle.loads/load — insecure deserialization',
    },
    {
        id: 'yaml-load',
        canonicalType: 'insecure_deserialization',
        severity: 'High',
        languages: ['python'],
        matchers: [{ kind: 'call', method: 'load', receiver: 'yaml' }],
        description: 'yaml.load without SafeLoader — insecure deserialization',
    },
];

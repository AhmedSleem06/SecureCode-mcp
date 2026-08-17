/**
 * Phase C — taint source patterns.
 *
 * Defines what constitutes attacker-controlled input. A member expression
 * (or call on a member expression) is a source if its text starts with one
 * of the patterns below. The taint tracker uses this to seed the tainted
 * variable set during its forward walk.
 *
 * Two kinds of sources:
 *   1. Property access: `req.body`, `request.GET`, `ctx.query` — matched
 *      by prefix on the member expression text.
 *   2. Call expression: `req.json()`, `req.formData()`, `c.req.json()` —
 *      matched by prefix on the callee text (the part before `()`).
 */

import type { SinkLanguage } from './sinkRegistry';

export type TaintSourceType =
    | 'body' | 'query' | 'path' | 'header' | 'cookie'
    | 'stdin' | 'argv' | 'env';

export interface TaintSourcePattern {
    /** Text prefix that identifies this source: 'req.body', 'request.GET', etc. */
    prefix: string;
    languages: SinkLanguage[];
    sourceType: TaintSourceType;
    /** How likely this is attacker-controlled (0-1). Body/query/path = 1.0, env = 0.5. */
    confidence: number;
    /**
     * True if this source is a method call (e.g. `req.json()`), not a property
     * access (e.g. `req.body`). When true, `matchTaintSource` also matches the
     * callee text of a call expression — `req.json` matches `req.json()`.
     */
    isCall?: boolean;
}

/**
 * Source patterns for JS/TS/TSX and Python.
 *
 * JS/TS: Express, Fastify, Koa, Next.js App Router, Hono, Lambda event, Effect-TS.
 * Python: Flask, Django, FastAPI, sys.argv, os.environ.
 */
export const TAINT_SOURCES: TaintSourcePattern[] = [
    // ── JS/TS — Express / generic ───────────────────────────────────────
    { prefix: 'req.body',       languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'req.query',      languages: ['javascript', 'typescript', 'tsx'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'req.params',     languages: ['javascript', 'typescript', 'tsx'], sourceType: 'path',    confidence: 1.0 },
    { prefix: 'req.headers',    languages: ['javascript', 'typescript', 'tsx'], sourceType: 'header',  confidence: 0.9 },
    { prefix: 'req.cookies',    languages: ['javascript', 'typescript', 'tsx'], sourceType: 'cookie',  confidence: 0.9 },
    { prefix: 'req.files',      languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 0.9 },
    // ── JS/TS — generic `request` object ─────────────────────────────────
    { prefix: 'request.body',   languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'request.query',  languages: ['javascript', 'typescript', 'tsx'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'request.params', languages: ['javascript', 'typescript', 'tsx'], sourceType: 'path',    confidence: 1.0 },
    { prefix: 'request.headers',languages: ['javascript', 'typescript', 'tsx'], sourceType: 'header',  confidence: 0.9 },
    { prefix: 'request.cookies',languages: ['javascript', 'typescript', 'tsx'], sourceType: 'cookie',  confidence: 0.9 },
    // ── JS/TS — Koa ctx ───────────────────────────────────────────────────
    { prefix: 'ctx.request.body',   languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'ctx.request.query',  languages: ['javascript', 'typescript', 'tsx'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'ctx.request.params', languages: ['javascript', 'typescript', 'tsx'], sourceType: 'path',    confidence: 1.0 },
    { prefix: 'ctx.body',   languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'ctx.query',  languages: ['javascript', 'typescript', 'tsx'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'ctx.params', languages: ['javascript', 'typescript', 'tsx'], sourceType: 'path',    confidence: 1.0 },
    { prefix: 'ctx.headers',languages: ['javascript', 'typescript', 'tsx'], sourceType: 'header',  confidence: 0.9 },
    // ── JS/TS — Lambda event ──────────────────────────────────────────────
    { prefix: 'event.body',         languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'event.queryStringParameters', languages: ['javascript', 'typescript', 'tsx'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'event.pathParameters',languages: ['javascript', 'typescript', 'tsx'], sourceType: 'path',    confidence: 1.0 },
    { prefix: 'event.headers',      languages: ['javascript', 'typescript', 'tsx'], sourceType: 'header',  confidence: 0.9 },

    // ── JS/TS — Next.js App Router (call-based sources) ──────────────────
    // Next.js App Router uses `await req.json()` / `await req.formData()`
    // instead of `req.body` (property access). These are call expressions.
    { prefix: 'req.json',           languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'req.formData',       languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'req.text',           languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'req.blob',           languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 0.8, isCall: true },
    { prefix: 'req.arrayBuffer',    languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 0.8, isCall: true },
    { prefix: 'request.json',       languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'request.formData',   languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'request.text',       languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    // Next.js searchParams (route handler params destructure: { searchParams })
    // is a bare identifier — too noisy to match generically. The agent
    // prompt handles this case via reasoning.

    // ── JS/TS — Hono (call-based sources) ────────────────────────────────
    { prefix: 'c.req.json',         languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'c.req.text',         languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'c.req.formData',     languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'c.req.query',        languages: ['javascript', 'typescript', 'tsx'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'c.req.param',        languages: ['javascript', 'typescript', 'tsx'], sourceType: 'path',    confidence: 1.0, isCall: true },
    { prefix: 'c.req.header',       languages: ['javascript', 'typescript', 'tsx'], sourceType: 'header',  confidence: 0.9, isCall: true },
    { prefix: 'c.req.cookie',       languages: ['javascript', 'typescript', 'tsx'], sourceType: 'cookie',  confidence: 0.9, isCall: true },

    // ── JS/TS — Effect-TS (HttpServerRequest) ────────────────────────────
    // Effect-TS uses HttpServerRequest.readBody / readUrl / headers.
    // These are method calls on the request object.
    { prefix: 'HttpServerRequest.readBody',  languages: ['javascript', 'typescript', 'tsx'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'HttpServerRequest.readUrl',   languages: ['javascript', 'typescript', 'tsx'], sourceType: 'query',   confidence: 1.0, isCall: true },
    { prefix: 'HttpServerRequest.readHeaders',languages: ['javascript', 'typescript', 'tsx'],sourceType: 'header',  confidence: 0.9, isCall: true },
    { prefix: 'HttpServerRequest.headers',   languages: ['javascript', 'typescript', 'tsx'], sourceType: 'header',  confidence: 0.9 },
    { prefix: 'HttpServerRequest.url',       languages: ['javascript', 'typescript', 'tsx'], sourceType: 'query',   confidence: 1.0 },
    // Generic `request.json()` (covers Fastify, Remix, Astro, etc.)
    // already covered by the `request.json` call-source above.

    // ── Python — Flask / Django / FastAPI ────────────────────────────────
    { prefix: 'request.GET',     languages: ['python'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'request.POST',    languages: ['python'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'request.args',    languages: ['python'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'request.form',    languages: ['python'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'request.json',    languages: ['python'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'request.body',    languages: ['python'], sourceType: 'body',    confidence: 1.0 },
    { prefix: 'request.headers', languages: ['python'], sourceType: 'header',  confidence: 0.9 },
    { prefix: 'request.cookies', languages: ['python'], sourceType: 'cookie',  confidence: 0.9 },
    { prefix: 'request.values',  languages: ['python'], sourceType: 'query',   confidence: 1.0 },
    { prefix: 'request.data',    languages: ['python'], sourceType: 'body',    confidence: 1.0 },
    // ── Python — system ───────────────────────────────────────────────────
    { prefix: 'sys.argv',    languages: ['python'], sourceType: 'argv',   confidence: 0.7 },
    { prefix: 'os.environ',  languages: ['python'], sourceType: 'env',    confidence: 0.5 },
    { prefix: 'os.getenv',   languages: ['python'], sourceType: 'env',    confidence: 0.5 },
    // ── Python — FastAPI (call-based sources) ───────────────────────────
    // FastAPI uses Depends(), Query(), Path(), Body(), Header() as function
    // parameters. These are call expressions in the function signature.
    { prefix: 'Query',    languages: ['python'], sourceType: 'query',   confidence: 1.0, isCall: true },
    { prefix: 'Path',     languages: ['python'], sourceType: 'path',    confidence: 1.0, isCall: true },
    { prefix: 'Body',     languages: ['python'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'Header',   languages: ['python'], sourceType: 'header',  confidence: 0.9, isCall: true },
    { prefix: 'Cookie',   languages: ['python'], sourceType: 'cookie',  confidence: 0.9, isCall: true },
    { prefix: 'Form',     languages: ['python'], sourceType: 'body',    confidence: 1.0, isCall: true },
    { prefix: 'File',     languages: ['python'], sourceType: 'body',    confidence: 1.0, isCall: true },
    // ── Python — Django (additional patterns) ───────────────────────────
    { prefix: 'request.path_info',  languages: ['python'], sourceType: 'path',    confidence: 1.0 },
    { prefix: 'request.META',       languages: ['python'], sourceType: 'header',  confidence: 0.9 },
    { prefix: 'request.FILES',      languages: ['python'], sourceType: 'body',    confidence: 0.9 },
];

/**
 * Check if an expression's text matches a taint source pattern.
 * Returns the matching pattern, or null if not a source.
 *
 * Matching logic:
 *   - Property sources (req.body): exact match, or prefix followed by `.` or `[`
 *   - Call sources (req.json): exact match (the callee text is `req.json`)
 *     or prefix followed by `.` (e.g. `req.json` matches, `req.json()` does not
 *     because the caller strips the `()` before passing the callee text).
 */
export function matchTaintSource(
    text: string,
    language: SinkLanguage,
): TaintSourcePattern | null {
    for (const src of TAINT_SOURCES) {
        if (!src.languages.includes(language)) continue;

        if (src.isCall) {
            // Call source: match exact callee text or prefix (e.g. `req.json`
            // matches `req.json` exactly, and `req.json` matches `req.json.foo`
            // which shouldn't happen, but be safe).
            if (text === src.prefix || text.startsWith(src.prefix + '.')) {
                return src;
            }
            continue;
        }

        // Property source: exact match or prefix match (req.body.q starts with req.body)
        if (text === src.prefix || text.startsWith(src.prefix + '.') || text.startsWith(src.prefix + '[')) {
            return src;
        }
    }
    return null;
}

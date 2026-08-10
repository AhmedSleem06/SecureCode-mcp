/**
 * Phase C — taint source patterns.
 *
 * Defines what constitutes attacker-controlled input. A member expression
 * (or call on a member expression) is a source if its text starts with one
 * of the patterns below. The taint tracker uses this to seed the tainted
 * variable set during its forward walk.
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
}

/**
 * Source patterns for JS/TS/TSX and Python.
 *
 * JS/TS: Express, Fastify, Koa, Next.js, Lambda event.
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
];

/**
 * Check if an expression's text matches a taint source pattern.
 * Returns the matching pattern, or null if not a source.
 */
export function matchTaintSource(
    text: string,
    language: SinkLanguage,
): TaintSourcePattern | null {
    for (const src of TAINT_SOURCES) {
        if (!src.languages.includes(language)) continue;
        // Exact match or prefix match (req.body.q starts with req.body)
        if (text === src.prefix || text.startsWith(src.prefix + '.') || text.startsWith(src.prefix + '[')) {
            return src;
        }
    }
    return null;
}

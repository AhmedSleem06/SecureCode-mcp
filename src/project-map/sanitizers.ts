/**
 * Phase C — sanitizer registry.
 *
 * Functions that remove taint from data. When the taint tracker encounters
 * a call to a sanitizer, the result is NOT tainted (the sanitizer removes
 * the taint). Note: `String()` alone does NOT remove taint — it's a type
 * coercion, not a sanitizer.
 */

import type { SinkLanguage } from './sinkRegistry';

export interface SanitizerDef {
    /** Method name: 'parseInt', 'escape', 'sanitize', etc. */
    method: string;
    /** Optional receiver: 'DOMPurify' for DOMPurify.sanitize. */
    receiver?: string;
    languages: SinkLanguage[];
}

/**
 * Known sanitizers. A call to any of these with a tainted argument produces
 * a non-tainted result.
 *
 * Type coercions that reject non-numeric input (parseInt, parseFloat, Number)
 * ARE sanitizers for SQL injection — the result is always a number.
 * `String()` is NOT a sanitizer — it accepts anything.
 */
export const SANITIZERS: SanitizerDef[] = [
    // ── JS/TS — type coercions that reject invalid input ─────────────────
    { method: 'parseInt',      languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'parseFloat',    languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'Number',        languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'Boolean',       languages: ['javascript', 'typescript', 'tsx'] },
    // ── JS/TS — encoding functions ───────────────────────────────────────
    { method: 'encodeURIComponent', languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'encodeURI',         languages: ['javascript', 'typescript', 'tsx'] },
    // ── JS/TS — HTML/XSS sanitizers ──────────────────────────────────────
    { method: 'escape',        languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'escapeHtml',     languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'sanitize',      languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'sanitizeHtml',  languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'sanitize',  receiver: 'DOMPurify', languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'xss',            languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'clean',  receiver: 'xss',          languages: ['javascript', 'typescript', 'tsx'] },
    // ── JS/TS — validator library ────────────────────────────────────────
    // validator.isInt(x) etc. are validators, not sanitizers — they return
    // boolean, not cleaned data. The sanitizer is validator.toString(x, true)
    // etc. But `escape` from validator IS a sanitizer.
    { method: 'escape', receiver: 'validator',   languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'ltrim',  receiver: 'validator',   languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'rtrim',  receiver: 'validator',   languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'trim',   receiver: 'validator',   languages: ['javascript', 'typescript', 'tsx'] },

    // ── JS/TS — Zod schema validation ─────────────────────────────────────
    { method: 'parse',        languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'safeParse',    languages: ['javascript', 'typescript', 'tsx'] },
    // ── JS/TS — Effect-TS Schema validation ──────────────────────────────
    { method: 'decodeSync',   languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'decode',       languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'encodeSync',   languages: ['javascript', 'typescript', 'tsx'] },
    // ── JS/TS — Joi/express-validator ────────────────────────────────────
    { method: 'validate',     languages: ['javascript', 'typescript', 'tsx'] },
    { method: 'assert',       languages: ['javascript', 'typescript', 'tsx'] },

    // ── Python — type coercions ──────────────────────────────────────────
    { method: 'int',          languages: ['python'] },
    { method: 'float',        languages: ['python'] },
    { method: 'bool',         languages: ['python'] },
    // ── Python — HTML/XSS sanitizers ─────────────────────────────────────
    { method: 'escape',       languages: ['python'] },
    { method: 'escape', receiver: 'markupsafe', languages: ['python'] },
    { method: 'clean',  receiver: 'bleach',     languages: ['python'] },
    { method: 'clean',  receiver: 'nh3',       languages: ['python'] },
];

/**
 * Check if a call expression is a sanitizer call.
 * Returns the sanitizer name, or null if not a sanitizer.
 *
 * @param method   the method name from callParts
 * @param receiver the base identifier from callParts (or null for bare calls)
 * @param language the source language
 */
export function matchSanitizer(
    method: string,
    receiver: string | null,
    language: SinkLanguage,
): string | null {
    for (const san of SANITIZERS) {
        if (!san.languages.includes(language)) continue;
        if (san.method !== method) continue;
        if (san.receiver && receiver !== san.receiver) continue;
        return san.receiver ? `${san.receiver}.${san.method}` : san.method;
    }
    return null;
}

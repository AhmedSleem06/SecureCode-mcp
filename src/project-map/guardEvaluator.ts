/**
 * Phase E — guard effectiveness evaluator.
 *
 * Takes a guard (middleware function, sanitizer call, or validator) and
 * an attack type, and returns whether the guard actually stops the attack.
 *
 * The evaluator reuses:
 * - `detectAuthInFunction` from `detectors.ts` to identify auth guards
 * - The sanitizer registry from `sanitizers.ts` to identify sanitizer guards
 * - The pattern library in `guardPatterns.ts` to evaluate effectiveness
 *
 * The Juror sees these deterministic guard evaluations and doesn't have to
 * guess whether `parseInt()` stops XSS (it doesn't) or whether `escape()`
 * stops SQLi (it doesn't).
 */

import { parseSource, TreeSitterNode } from './parserLoader';
import { walk, callParts, isIdentifier } from './astHelpers';
import { detectAuthInFunction, AuthMatch } from './detectors';
import { matchSanitizer } from './sanitizers';
import {
    GUARD_EFFECTIVENESS, GUARD_BYPASS_EXAMPLES, GUARD_EFFECTIVE_REASONS,
    GuardType, GuardEvaluation, AttackType,
} from './guardPatterns';
import type { SinkLanguage } from './sinkRegistry';

// Re-export the types consumers need (they're declared in guardPatterns.ts
// but callers import them from guardEvaluator.ts for convenience).
export type { GuardEvaluation, AttackType };

// ── Guard identification ────────────────────────────────────────────────────

/**
 * Identify what type of guard a function body implements.
 * Returns the guard type, or 'unknown' if not recognized.
 */
function identifyGuardType(
    fnRoot: TreeSitterNode,
    source: string,
    language: SinkLanguage,
): GuardType {
    const text = source.slice(fnRoot.startIndex, fnRoot.endIndex);

    // ── 1. Auth guards ──────────────────────────────────────────────────────
    const auth = detectAuthInFunction(fnRoot, source);
    if (auth !== 'none') {
        if (auth === 'jwt') {
            // Check if algorithm is pinned
            const hasAlgorithmPin = /algorithms?\s*:/i.test(text)
                || /verifyOptions\.algorithms/i.test(text);
            return hasAlgorithmPin ? 'auth-jwt-verify' : 'auth-jwt-verify-noalg';
        }
        if (auth === 'session') return 'auth-session';
        if (auth === 'api-key') return 'auth-api-key';
    }

    // ── 2. Sanitizer calls ──────────────────────────────────────────────────
    for (const node of walk(fnRoot)) {
        if (node.type !== 'call_expression' && node.type !== 'call') continue;
        const p = callParts(node, source);
        if (!p) continue;
        const sanitizer = matchSanitizer(p.method, p.receiver, language);
        if (!sanitizer) continue;
        // Classify by sanitizer name
        if (['parseInt', 'parseFloat', 'Number', 'int', 'float', 'Boolean', 'bool'].includes(sanitizer)) {
            return 'sanitizer-numeric';
        }
        if (['escape', 'escapeHtml', 'sanitize', 'sanitizeHtml', 'clean', 'xss'].includes(sanitizer)
            || sanitizer.includes('DOMPurify') || sanitizer.includes('bleach')
            || sanitizer.includes('markupsafe') || sanitizer.includes('nh3')) {
            return 'sanitizer-html';
        }
        if (['encodeURIComponent', 'encodeURI'].includes(sanitizer)) {
            return 'sanitizer-url';
        }
    }

    // ── 3. Parameterized query ────────────────────────────────────────────
    // A parameterized query passes the query string (with ? placeholders)
    // and the params as separate arguments — no string concatenation.
    // Pattern: db.query("SELECT ... WHERE id = ?", [params]) — two args,
    // first is a string literal with ?, second is an array/expression.
    for (const node of walk(fnRoot)) {
        if (node.type !== 'call_expression' && node.type !== 'call') continue;
        const p = callParts(node, source);
        if (!p || !p.receiver) continue;
        if (['query', 'execute', 'raw', '$queryRaw'].includes(p.method)) {
            // Check for parameterized pattern: 2+ args, first is a string
            // literal containing ? or a named param, and no concatenation.
            if (p.args.length >= 2) {
                const firstArg = p.args[0];
                const argText = source.slice(firstArg.startIndex, firstArg.endIndex);
                const isStringLike = firstArg.type === 'string'
                    || firstArg.type === 'template_string'
                    || firstArg.type === 'template_literal';
                const hasPlaceholder = argText.includes('?') || /:\w+/.test(argText);
                const hasConcat = argText.includes('+');
                if (isStringLike && hasPlaceholder && !hasConcat) {
                    return 'parameterized-query';
                }
            }
        }
    }

    // ── 4. Allowlist ────────────────────────────────────────────────────────
    // A literal allowlist: if (['a', 'b', 'c'].includes(value))
    if (/if\s*\(\s*\[[^\]]*\]\s*\.(includes|indexOf|has)\s*\(/.test(text)
        || /if\s*\(\s*\w+\s+in\s+\[/.test(text)) {
        // Check if the array is a literal (not a variable)
        const hasLiteralArray = /\[\s*['"`][^\]]*\]\s*\.(includes|indexOf)/.test(text);
        return hasLiteralArray ? 'allowlist-literal' : 'allowlist-dynamic';
    }

    // ── 5. Rate limiting ──────────────────────────────────────────────────
    if (/rateLimit|rate_limit|RateLimit|express-rate-limit|slowDown/i.test(text)) {
        return 'rate-limit';
    }

    // ── 6. Helmet ──────────────────────────────────────────────────────────
    if (/helmet\s*\(|require\s*\(\s*['"]helmet['"]/.test(text)) {
        return 'helmet';
    }

    // ── 7. CORS ────────────────────────────────────────────────────────────
    if (/cors\s*\(|require\s*\(\s*['"]cors['"]/.test(text)) {
        // Check if origin is '*'
        if (/origin\s*:\s*['"]\*['"]/.test(text)) {
            return 'cors-permissive';
        }
        return 'cors-strict';
    }

    // ── 8. Validator (zod/joi/pydantic) ────────────────────────────────────
    if (/\.parse\s*\(|\.validate\s*\(|\.safeParse\s*\(/.test(text)
        && /(zod|joi|yup|pydantic|schema)/i.test(text)) {
        return 'validator';
    }

    return 'unknown';
}

// ── Evaluation ──────────────────────────────────────────────────────────────

/**
 * Evaluate a guard against a specific attack type.
 *
 * @param guardSource  the source text of the guard function
 * @param guardName    the guard's display name (middleware name)
 * @param attackType   the attack to evaluate against
 * @param language     the source language
 * @returns the evaluation result
 */
export async function evaluateGuard(
    guardSource: string,
    guardName: string,
    attackType: AttackType,
    language: SinkLanguage,
): Promise<GuardEvaluation> {
    const parsed = await parseSource(guardSource, language);
    let guardType: GuardType = 'unknown';

    if (parsed) {
        // Try to find a function body in the parsed source. The guard source
        // may be a full function declaration or just a function body.
        const { root } = parsed;
        // Look for a function declaration/definition
        let fnNode: TreeSitterNode | null = null;
        for (const n of walk(root)) {
            if (['function_declaration', 'function_definition', 'method_definition',
                'async_function_declaration', 'async_function_definition',
                'arrow_function', 'function_expression'].includes(n.type)) {
                fnNode = n;
                break;
            }
        }
        if (fnNode) {
            guardType = identifyGuardType(fnNode, guardSource, language);
        } else {
            // Parse as a bare expression/statement block
            guardType = identifyGuardType(root, guardSource, language);
        }
    }

    // Look up effectiveness
    const effective = GUARD_EFFECTIVENESS[guardType]?.[attackType];
    const isEffective = effective === true;
    const isKnown = effective !== undefined;

    // Build reason
    let reason: string;
    let bypassExample: string | undefined;

    if (isEffective) {
        reason = GUARD_EFFECTIVE_REASONS[guardType]?.[attackType]
            ?? `Guard type '${guardType}' is effective against ${attackType}`;
    } else if (isKnown) {
        // Not effective
        reason = `Guard type '${guardType}' is NOT effective against ${attackType}`;
        bypassExample = GUARD_BYPASS_EXAMPLES[guardType]?.[attackType];
    } else {
        // Unknown — guard detected but we can't determine effectiveness
        reason = `Guard detected as '${guardType}' but effectiveness against ${attackType} is unknown`;
        bypassExample = undefined;
    }

    return {
        guardName,
        guardType,
        attackType,
        effective: isEffective,
        reason,
        ...(bypassExample && { bypassExample }),
    };
}

/**
 * Evaluate multiple guards against multiple attack types.
 *
 * @param guards  array of { source, name } pairs
 * @param attacks array of attack types to evaluate each guard against
 * @param language the source language
 * @returns flat array of evaluations (one per guard×attack pair)
 */
export async function evaluateGuards(
    guards: Array<{ source: string; name: string }>,
    attacks: AttackType[],
    language: SinkLanguage,
): Promise<GuardEvaluation[]> {
    const results: GuardEvaluation[] = [];
    for (const guard of guards) {
        for (const attack of attacks) {
            try {
                const eval_ = await evaluateGuard(guard.source, guard.name, attack, language);
                results.push(eval_);
            } catch {
                // Best-effort: skip guards that fail to parse
            }
        }
    }
    return results;
}

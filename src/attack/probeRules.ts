/**
 * Runtime probe verdict rules — port of api/src/services/sandboxRules.ts.
 *
 * Seven deterministic response rules (zero LLM) that evaluate whether a probe
 * plan's attack request actually worked against the user's local dev server.
 * Pure functions: (attack request, attack response, baseline) → verdict.
 * No side effects, no I/O. Kept in semantic parity with the API's sandbox
 * rules — the same inputs must yield the same verdicts and rule identifiers.
 *
 * Verdict vocabulary:
 *   'confirmed-bypass' → PROVEN (the exploit worked)
 *   'refuted'          → UNPROVEN (the control held)
 *   'inconclusive'     → needs AI adjudicator
 *   'spawn-failed'     → server never came up
 */

export type ProbeVerdict = 'confirmed-bypass' | 'refuted' | 'inconclusive' | 'spawn-failed';

export type ConfirmationBasis = 'signature' | 'latency' | 'multi-request';

export interface ProbeRuleRequest {
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: unknown;
    expectedStatus?: number[];
    successStatus?: number[];
    successBodyPattern?: string;
    successHeaders?: Record<string, string>;
    successLatencyMs?: { gte?: number; lte?: number };
    successConfirmedBy?: ConfirmationBasis;
    successEvidenceNeeded?: string;
    authRequired?: boolean;
    authEnvVars?: string[];
}

export interface ProbeRuleResponse {
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    latencyMs: number;
}

export interface ProbeRuleResult {
    verdict: ProbeVerdict;
    rule: string;
    reason: string;
    requiredEvidence?: string[];
}

export const REJECTION_STATUSES = [400, 401, 403, 404, 405, 409, 415, 422, 429];

const REJECTION_STATUS_SET = new Set(REJECTION_STATUSES);

export const SECRET_PATTERN =
    '(' +
    'sk-[A-Za-z0-9]{20,}' +
    '|AKIA[0-9A-Z]{16}' +
    '|ghp_[A-Za-z0-9]{36}' +
    '|eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}' +
    '|-----BEGIN [A-Z ]*PRIVATE KEY-----' +
    '|password["\']?\\s*[:=]\\s*["\'][^"\']{4,}' +
    '|api[_-]?key["\']?\\s*[:=]\\s*["\'][^"\']{8,}' +
    '|secret["\']?\\s*[:=]\\s*["\'][^"\']{8,}' +
    ')';
const SECRET_REGEX_GLOBAL = new RegExp(SECRET_PATTERN, 'gi');

const EMAIL_REGEX = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
const PHONE_REGEX =
    /(?:\+\d{1,3}[\s.-]\d{2,4}[\s.-]?\d{3,4}[\s.-]\d{3,4}|\(\d{3}\)\s?\d{3}[\s.-]\d{4}|\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b)/g;
const CREDIT_CARD_REGEX = /\b(?:\d[ -]?){12,18}\d\b/g;
const STACKTRACE_REGEX =
    /at\s+[A-Za-z0-9_.]+\s+\(.*?:\d+:\d+\)|Traceback \(most recent call last\)|\bError:\s.+\n\s+at\b|stack\s+trace/i;

const MATCH_ANYTHING = new Set(['', '.*', '.+', '(.*)', '(.+)', '[\\s\\S]*', '[\\s\\S]+']);

function isMatchAnything(pattern: string): boolean {
    return MATCH_ANYTHING.has(pattern.trim().replace(/^\^/, '').replace(/\$$/, ''));
}

function bodySignatureMatches(pattern: string | undefined, body: string): boolean {
    if (!pattern || isMatchAnything(pattern)) return false;
    try { return new RegExp(pattern, 'i').test(body); } catch { return false; }
}

function headerSignatureMatches(
    patterns: Record<string, string> | undefined,
    headers: Record<string, string>,
): boolean {
    if (!patterns) return false;
    const entries = Object.entries(patterns);
    if (entries.length === 0) return false;
    const lower: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) lower[k.toLowerCase()] = v;
    return entries.every(([name, regex]) => {
        const value = lower[name.toLowerCase()];
        if (value === undefined) return false;
        try { return new RegExp(regex, 'i').test(value); } catch { return false; }
    });
}

export function passesLuhn(digits: string): boolean {
    if (digits.length < 13 || digits.length > 19) return false;
    let sum = 0, double = false;
    for (let i = digits.length - 1; i >= 0; i--) {
        let d = digits.charCodeAt(i) - 48;
        if (double) { d *= 2; if (d > 9) d -= 9; }
        sum += d;
        double = !double;
    }
    return sum % 10 === 0;
}

function extractPii(text: string): { strong: Set<string>; weak: Set<string> } {
    const strong = new Set<string>();
    const weak = new Set<string>();
    for (const m of text.match(EMAIL_REGEX) || []) strong.add(m);
    for (const m of text.match(CREDIT_CARD_REGEX) || []) {
        if (passesLuhn(m.replace(/[^0-9]/g, ''))) strong.add(m);
    }
    for (const m of text.match(PHONE_REGEX) || []) weak.add(m);
    return { strong, weak };
}

function newSecrets(baselineBody: string | null, attackBody: string): string[] {
    const baseMatches = new Set<string>();
    if (baselineBody) {
        for (const m of baselineBody.match(SECRET_REGEX_GLOBAL) || []) baseMatches.add(m);
    }
    SECRET_REGEX_GLOBAL.lastIndex = 0;
    const attackMatches = new Set<string>();
    for (const m of attackBody.match(SECRET_REGEX_GLOBAL) || []) attackMatches.add(m);
    return [...attackMatches].filter(m => !baseMatches.has(m));
}

function samplePii(items: string[]): string {
    return items.slice(0, 3).join(', ') + (items.length > 3 ? ` (+${items.length - 3} more)` : '');
}

interface SignatureDecision { confirmed: boolean; reason: string; declined?: string; }
const NOT_CONFIRMED: SignatureDecision = { confirmed: false, reason: '' };

function evaluateExploitSignature(
    request: ProbeRuleRequest,
    attack: ProbeRuleResponse,
): SignatureDecision {
    const basis = request.successConfirmedBy ?? 'signature';

    if (basis === 'multi-request') {
        return {
            confirmed: false, reason: '',
            declined: request.successEvidenceNeeded
                || 'This vulnerability class cannot be decided from one request and one response.',
        };
    }

    if (!request.successStatus || request.successStatus.length === 0) return NOT_CONFIRMED;
    if (!request.successStatus.includes(attack.statusCode)) return NOT_CONFIRMED;

    if (basis === 'latency') {
        const window = request.successLatencyMs;
        if (!window || window.gte === undefined) {
            return {
                confirmed: false, reason: '',
                declined: 'This class is detected by an induced delay, but the pattern declared no latency threshold.',
            };
        }
        if (attack.latencyMs < window.gte) return NOT_CONFIRMED;
        if (window.lte !== undefined && attack.latencyMs > window.lte) return NOT_CONFIRMED;
        if (request.successBodyPattern && !isMatchAnything(request.successBodyPattern) &&
            !bodySignatureMatches(request.successBodyPattern, attack.body)) return NOT_CONFIRMED;
        return {
            confirmed: true,
            reason: `Response took ${attack.latencyMs}ms against the pattern's ${window.gte}ms threshold at status ${attack.statusCode}.`,
        };
    }

    const hasBody = !!request.successBodyPattern && !isMatchAnything(request.successBodyPattern);
    const hasHeaders = !!request.successHeaders && Object.keys(request.successHeaders).length > 0;
    if (!hasBody && !hasHeaders) {
        return {
            confirmed: false, reason: '',
            declined: 'The attack pattern declared no evidence beyond a status code, and status is what an ordinary endpoint returns.',
        };
    }
    if (hasBody && !bodySignatureMatches(request.successBodyPattern, attack.body)) return NOT_CONFIRMED;
    if (hasHeaders && !headerSignatureMatches(request.successHeaders, attack.headers)) return NOT_CONFIRMED;

    const evidence = [
        hasBody ? `body matching /${request.successBodyPattern}/` : '',
        hasHeaders ? `headers matching ${JSON.stringify(request.successHeaders)}` : '',
    ].filter(Boolean).join(' and ');
    return {
        confirmed: true,
        reason: `Response matched the attack pattern's documented success signature (status ${attack.statusCode}, ${evidence}).`,
    };
}

export function applyProbeRules(
    attack: ProbeRuleRequest,
    attackResp: ProbeRuleResponse | null,
    baseline?: ProbeRuleRequest | null,
    baselineResp?: ProbeRuleResponse | null,
    env: Record<string, string | undefined> = process.env,
): ProbeRuleResult {
    if (!attackResp) {
        return {
            verdict: 'inconclusive', rule: 'none',
            reason: 'Attack request errored — no response to evaluate.',
        };
    }

    const expected = attack.expectedStatus || [];

    // Auth-precheck
    if (attack.authRequired && attackResp.statusCode === 200 &&
        attack.authEnvVars && attack.authEnvVars.length > 0) {
        const configured = attack.authEnvVars.every(v => !!env[v]);
        if (!configured) {
            return {
                verdict: 'inconclusive', rule: 'auth-precheck',
                reason: `Endpoint flagged auth-required but auth env (${attack.authEnvVars.join(', ')}) is not set in the sandbox.`,
            };
        }
    }

    // Rule 0: exploit signature
    const signature = evaluateExploitSignature(attack, attackResp);
    if (signature.confirmed) {
        return { verdict: 'confirmed-bypass', rule: 'exploit-signature', reason: signature.reason, requiredEvidence: ['exploit-signature-matched'] };
    }

    // Rule 1: status mismatch
    if (expected.length > 0 && !expected.includes(attackResp.statusCode)) {
        const predictedBlocked = expected.every(s => s === 401 || s === 403 || s === 404 || s >= 500);
        if (predictedBlocked && attackResp.statusCode >= 200 && attackResp.statusCode < 300) {
            return {
                verdict: 'confirmed-bypass', rule: 'status-mismatch',
                reason: `Predicted blocked (${expected.join('/')}) but got ${attackResp.statusCode}.`,
                requiredEvidence: ['baseline-returned-blocked-status', 'exploit-returned-success-status'],
            };
        }
    }

    // Rule 2: auth bypass
    if (baselineResp && (baselineResp.statusCode === 401 || baselineResp.statusCode === 403) &&
        attackResp.statusCode >= 200 && attackResp.statusCode < 300) {
        if (!attackResp.body || attackResp.body.trim().length === 0) {
            return {
                verdict: 'inconclusive', rule: 'auth-bypass',
                reason: `Baseline returned ${baselineResp.statusCode}, attack returned ${attackResp.statusCode}, but response body is empty — cannot confirm protected resource was accessed.`,
            };
        }
        return {
            verdict: 'confirmed-bypass', rule: 'auth-bypass',
            reason: `Baseline returned ${baselineResp.statusCode}, attack returned ${attackResp.statusCode} with ${attackResp.body.length} bytes of response body.`,
            requiredEvidence: ['baseline-returned-auth-error', 'exploit-returned-success', 'response-body-non-empty'],
        };
    }

    // Rule 3: secret leak
    const leakedSecrets = newSecrets(baselineResp?.body ?? null, attackResp.body);
    if (leakedSecrets.length > 0) {
        return {
            verdict: baselineResp ? 'confirmed-bypass' : 'inconclusive', rule: 'secret-leak',
            reason: baselineResp
                ? 'Attack response body contains a secret that the baseline did not return.'
                : 'Attack response body matches a secret pattern, but there is no baseline.',
            requiredEvidence: ['baseline-no-secret', 'exploit-secret-present'],
        };
    }

    // Rule 4: PII leak
    const atkPii = extractPii(attackResp.body);
    if (baselineResp) {
        const basePii = extractPii(baselineResp.body);
        const leakedStrong = [...atkPii.strong].filter(p => !basePii.strong.has(p));
        if (leakedStrong.length > 0) {
            return {
                verdict: 'confirmed-bypass', rule: 'pii-leak',
                reason: `Attack response leaked PII not present in baseline: ${samplePii(leakedStrong)}.`,
            };
        }
        const leakedWeak = [...atkPii.weak].filter(p => !basePii.weak.has(p));
        if (leakedWeak.length > 0) {
            return {
                verdict: 'inconclusive', rule: 'pii-leak',
                reason: `Attack response contains phone-shaped values absent from the baseline (${samplePii(leakedWeak)}).`,
            };
        }
    } else if (atkPii.strong.size > 0 || atkPii.weak.size > 0) {
        return {
            verdict: 'inconclusive', rule: 'pii-leak',
            reason: 'Attack response contains PII, but there is no baseline to tell a leak from normal output.',
        };
    }

    // Rule 5: stacktrace disclosure
    if (attackResp.statusCode >= 500 && STACKTRACE_REGEX.test(attackResp.body)) {
        return {
            verdict: 'inconclusive', rule: 'stacktrace-disclosure',
            reason: `Server returned ${attackResp.statusCode} with a stack trace — info leak.`,
        };
    }

    // Rule 6: blocked
    if (expected.length > 0 && expected.includes(attackResp.statusCode)) {
        return {
            verdict: 'refuted', rule: 'blocked',
            reason: `Attack returned ${attackResp.statusCode} (expected ${expected.join('/')}) with no leak — the control held.`,
        };
    }
    if (attack.successStatus && attack.successStatus.length > 0 &&
        REJECTION_STATUS_SET.has(attackResp.statusCode)) {
        return {
            verdict: 'refuted', rule: 'blocked',
            reason: `Attack was rejected with ${attackResp.statusCode} and never matched its success signature — the payload does not work.`,
        };
    }

    // Fallback
    if (signature.declined) {
        return {
            verdict: 'inconclusive', rule: 'none',
            reason: `Not confirmable from a single request (status ${attackResp.statusCode}). ${signature.declined}`,
        };
    }
    return {
        verdict: 'inconclusive', rule: 'none',
        reason: `No deterministic rule fired (status ${attackResp.statusCode}, no leak detected).`,
    };
}

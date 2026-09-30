/**
 * Runtime probe engine — executes a small baseline + attack HTTP plan against
 * the user's local dev server (127.0.0.1) and applies deterministic rules for
 * a PROVEN / UNPROVEN / INCONCLUSIVE verdict.
 *
 * Fires when sandbox verification cannot exercise an HTTP-endpoint-shaped
 * finding (e.g. "Effect-TS module requires full runtime", "Test timed out
 * after 12 rounds"): the probe replays the decisive requests against the
 * real listener instead of a sandboxed boot.
 */

import * as fs from 'fs';
import * as net from 'net';
import * as path from 'path';
import { executeHttpRequest } from './executor';
import { isLocalhostHost, PolicyError, validateTarget, type AttackBudget } from './policy';
import { redactText } from './report';
import { applyProbeRules, type ProbeRuleResponse, type ProbeRuleResult } from './probeRules';
import type { AgentHttpExpect } from './protocol';

export interface ProbeRequest {
    role: 'baseline' | 'attack';
    method: string;
    path: string;
    headers?: Record<string, string>;
    body?: unknown;
    expect?: AgentHttpExpect;
}

export interface ProbePlan {
    host: string;
    port: number;
    requests: ProbeRequest[];
}

export interface ProbeRequestObservation {
    role: 'baseline' | 'attack';
    method: string;
    path: string;
    statusCode: number;
    latencyMs: number;
}

export interface ProbeResult {
    verdict: 'PROVEN' | 'UNPROVEN' | 'INCONCLUSIVE';
    rule?: string;
    reason: string;
    baselineStatus?: number;
    attackStatus?: number;
    evidence: string;
    requests: ProbeRequestObservation[];
}

export interface DevServerTarget {
    host: string;
    port: number;
    source: 'config' | 'env' | 'autodetect';
}

const AUTODETECT_PORTS = [3000, 5173, 8080, 4000, 8000, 5174, 3001];

const PROBE_BUDGET: AttackBudget = {
    maxSteps: 8,
    maxRequests: 8,
    wallClockMs: 60_000,
    maxResponseBytes: 200_000,
    requestTimeoutMs: 10_000,
    costCapUsd: 0,
};

/** Vulnerability types a runtime probe can exercise (pocRouter HTTP list + xss). */
export const PROBE_ELIGIBLE_TYPES: ReadonlySet<string> = new Set([
    'sql_injection',
    'nosql_injection',
    'ssrf',
    'open_redirect',
    'broken_access_control',
    'xss',
]);

const PROBE_VERIFY_REASON_RE = /(timed? ?out|full runtime|cannot test in sandbox|runtime|DOM\/jsdom)/i;

/** Route-registration idioms the fallback derives endpoints from.
 *  Covers frameworks the deterministic project map does not extract
 *  (Effect-TS, NestJS, Hono/Koa receivers) plus the common
 *  Express/Fastify shapes as a safety net. */
const FALLBACK_ROUTE_PATTERNS: { re: RegExp; methodGroup: number; pathGroup: number; methodFrom: (m: RegExpMatchArray) => string }[] = [
    // Effect-TS: HttpApiEndpoint.get('path', ...) / HttpRouter.post('/path', ...)
    {
        re: /Http(?:ApiEndpoint|Router)\.(get|post|put|patch|delete|head|options)\s*\(\s*['"`]([^'"`]+)['"`]/,
        methodGroup: 1,
        pathGroup: 2,
        methodFrom: m => m[1].toUpperCase(),
    },
    // NestJS: @Get('path')
    {
        re: /@(Get|Post|Put|Patch|Delete|Head|Options)\s*\(\s*['"`]([^'"`]+)['"`]/,
        methodGroup: 1,
        pathGroup: 2,
        methodFrom: m => m[1].toUpperCase(),
    },
    // Express / Fastify / Hono / Koa: (app|router|...).(get|post|...)('/path', ...)
    {
        re: /\b(app|router|server|fastify|api|route|controller|rtr|koa)\.(get|post|put|patch|delete|head|options|all)\s*\(\s*['"`]([^'"`]+)['"`]/,
        methodGroup: 2,
        pathGroup: 3,
        methodFrom: m => m[2] === 'all' ? 'GET' : m[2].toUpperCase(),
    },
];

const FALLBACK_EVIDENCE_ROUTE_RE = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+['"`]?(\/[^\s'"`,;)]+)/i;

function redactResponseHeaders(headers?: Record<string, string>): Record<string, string> {
    if (!headers) return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
        if (/authorization|cookie|x-api-key|api-key/i.test(k)) {
            out[k] = '[REDACTED]';
        } else {
            out[k] = v;
        }
    }
    return out;
}

/** URL-encode the path so SQLi/XSS payloads with spaces/quotes survive the request. */
export function encodeProbePath(rawPath: string): string {
    try {
        const parsed = new URL(rawPath, 'http://127.0.0.1');
        return parsed.pathname + parsed.search;
    } catch {
        const qIdx = rawPath.indexOf('?');
        const pathPart = qIdx >= 0 ? rawPath.slice(0, qIdx) : rawPath;
        const queryPart = qIdx >= 0 ? rawPath.slice(qIdx + 1) : '';
        const encodedPath = pathPart.split('/').map((segment) => encodeURIComponent(segment)).join('/');
        const encodedQuery = queryPart
            .split('&')
            .map((pair) => {
                const eq = pair.indexOf('=');
                return eq >= 0
                    ? `${encodeURIComponent(pair.slice(0, eq))}=${encodeURIComponent(pair.slice(eq + 1))}`
                    : encodeURIComponent(pair);
            })
            .join('&');
        return qIdx >= 0 ? `${encodedPath}?${encodedQuery}` : encodedPath;
    }
}

function isPortOpen(host: string, port: number, timeoutMs: number): Promise<boolean> {
    return new Promise((resolve) => {
        let settled = false;
        const socket = net.createConnection({ host, port });
        const done = (open: boolean) => {
            if (settled) return;
            settled = true;
            socket.destroy();
            resolve(open);
        };
        socket.setTimeout(timeoutMs);
        socket.once('connect', () => done(true));
        socket.once('timeout', () => done(false));
        socket.once('error', () => done(false));
    });
}

export async function detectDevServer(
    workspaceRoot: string,
    opts?: { candidatePorts?: number[] },
): Promise<DevServerTarget | null> {
    const envValue = process.env.SECURECODE_DEV_SERVER_PORT;
    if (envValue) {
        const port = Number.parseInt(envValue.trim(), 10);
        if (Number.isInteger(port) && port >= 1 && port <= 65535) {
            return { host: '127.0.0.1', port, source: 'env' };
        }
    }
    try {
        const cfgPath = path.join(workspaceRoot, '.securecode', 'runtime-probe.json');
        if (fs.existsSync(cfgPath)) {
            const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8')) as { host?: unknown; port?: unknown };
            const port = typeof cfg.port === 'number' ? cfg.port : Number.parseInt(String(cfg.port ?? ''), 10);
            const host = typeof cfg.host === 'string' && cfg.host.length > 0 ? cfg.host : '127.0.0.1';
            if (Number.isInteger(port) && port >= 1 && port <= 65535 && isLocalhostHost(host)) {
                return { host, port, source: 'config' };
            }
        }
    } catch {
        // fall through to autodetect
    }
    const candidates = opts?.candidatePorts ?? AUTODETECT_PORTS;
    for (const port of candidates) {
        if (await isPortOpen('127.0.0.1', port, 400)) {
            return { host: '127.0.0.1', port, source: 'autodetect' };
        }
    }
    return null;
}

interface ProbeSnapshot {
    role: 'baseline' | 'attack';
    statusCode: number;
    headers: Record<string, string>;
    body: string;
    latencyMs: number;
    error?: string;
}

function snapshotToRuleResponse(snapshot: ProbeSnapshot): ProbeRuleResponse {
    return {
        statusCode: snapshot.statusCode,
        headers: snapshot.headers,
        body: snapshot.body,
        latencyMs: snapshot.latencyMs,
    };
}

function buildEvidence(
    ruleResult: ProbeRuleResult,
    baseline: ProbeSnapshot | null,
    attack: ProbeSnapshot,
): string {
    const parts = [
        `Rule '${ruleResult.rule}' → ${ruleResult.verdict}: ${ruleResult.reason}`,
        `Decisive statuses: baseline ${baseline ? baseline.statusCode : 'none'} → attack ${attack.statusCode}.`,
    ];
    const snippet = attack.body.slice(0, 300);
    if (snippet.length > 0) {
        parts.push(`Attack body (first ${snippet.length} of ${attack.body.length} chars, redacted): ${snippet}`);
    }
    return redactText(parts.join(' ')).slice(0, 2000);
}

export async function executeProbePlan(
    plan: ProbePlan,
    opts: { signal?: AbortSignal } = {},
): Promise<ProbeResult> {
    const observed: ProbeRequestObservation[] = [];

    const inconclusive = (reason: string): ProbeResult => ({
        verdict: 'INCONCLUSIVE',
        reason,
        evidence: redactText(reason).slice(0, 2000),
        requests: observed,
    });

    if (plan.requests.length === 0) {
        return inconclusive('Probe plan contains no requests.');
    }
    if (plan.requests.length > PROBE_BUDGET.maxRequests) {
        return inconclusive(
            `Probe plan has ${plan.requests.length} requests, exceeding the budget cap of ${PROBE_BUDGET.maxRequests}.`,
        );
    }

    const snapshots: ProbeSnapshot[] = [];

    for (const req of plan.requests) {
        if (opts.signal?.aborted) {
            return inconclusive('cancelled');
        }
        let safePath: string;
        try {
            validateTarget({ host: plan.host, port: plan.port, path: req.path });
            safePath = encodeProbePath(req.path);
        } catch (err) {
            const message = err instanceof PolicyError ? err.message : String(err);
            return inconclusive(`Policy validation failed for ${req.role} ${req.method} ${req.path}: ${message}`);
        }
        const resp = await executeHttpRequest(
            {
                method: req.method,
                path: safePath,
                host: plan.host,
                port: plan.port,
                headers: req.headers,
                body: req.body,
            },
            PROBE_BUDGET,
            opts.signal,
        );
        observed.push({
            role: req.role,
            method: req.method,
            path: req.path,
            statusCode: resp.statusCode,
            latencyMs: resp.latencyMs,
        });
        snapshots.push({
            role: req.role,
            statusCode: resp.statusCode,
            headers: redactResponseHeaders(resp.headers),
            body: redactText(resp.body),
            latencyMs: resp.latencyMs,
            error: resp.error,
        });
    }

    if (opts.signal?.aborted) {
        return inconclusive('cancelled');
    }

    let baseline: ProbeSnapshot | null = null;
    let attack: ProbeSnapshot | null = null;
    let attackRequest: ProbeRequest | null = null;
    for (let i = 0; i < plan.requests.length; i++) {
        if (plan.requests[i].role === 'baseline') {
            baseline = snapshots[i];
        } else {
            attack = snapshots[i];
            attackRequest = plan.requests[i];
        }
    }

    if (!attackRequest || !attack) {
        return inconclusive('Probe plan contains no attack request.');
    }

    const ruleResult = applyProbeRules(
        {
            method: attackRequest.method,
            path: attackRequest.path,
            headers: attackRequest.headers,
            body: attackRequest.body,
            ...(attackRequest.expect ?? {}),
        },
        attack.statusCode === 0 ? null : snapshotToRuleResponse(attack),
        null,
        baseline && baseline.statusCode !== 0 ? snapshotToRuleResponse(baseline) : null,
    );

    const verdict = ruleResult.verdict === 'confirmed-bypass'
        ? 'PROVEN'
        : ruleResult.verdict === 'refuted'
            ? 'UNPROVEN'
            : 'INCONCLUSIVE';

    return {
        verdict,
        rule: ruleResult.rule,
        reason: redactText(ruleResult.reason),
        baselineStatus: baseline ? baseline.statusCode : undefined,
        attackStatus: attack.statusCode,
        evidence: buildEvidence(ruleResult, baseline, attack),
        requests: observed,
    };
}

export interface ProbeEndpointCandidate {
    method: string;
    path: string;
    line: number;
    [key: string]: unknown;
}

export function matchEndpointForFinding(
    finding: { type: string; line: number; lineEnd?: number },
    endpointContext: unknown[] | undefined,
): ProbeEndpointCandidate | null {
    if (!Array.isArray(endpointContext)) return null;
    for (const entry of endpointContext) {
        if (!entry || typeof entry !== 'object') continue;
        const candidate = entry as ProbeEndpointCandidate;
        if (typeof candidate.method !== 'string' || candidate.method.length === 0) continue;
        if (typeof candidate.path !== 'string' || candidate.path.length === 0) continue;
        if (typeof candidate.line !== 'number') continue;
        const nearLine = Math.abs(candidate.line - finding.line) <= 25;
        const coversLine = candidate.line <= finding.line && finding.line <= candidate.line + 200;
        if (nearLine || coversLine) return candidate;
    }
    return null;
}

export function isProbeEligible(
    finding: { type: string; line: number; lineEnd?: number },
    verifyReason: string,
    endpointContext: unknown[] | undefined,
): boolean {
    if (!PROBE_ELIGIBLE_TYPES.has(finding.type)) return false;
    if (!PROBE_VERIFY_REASON_RE.test(verifyReason ?? '')) return false;
    return matchEndpointForFinding(finding, endpointContext) !== null;
}

export function isProbeEligibleType(findingType: string): boolean {
    return PROBE_ELIGIBLE_TYPES.has(findingType);
}

export function hasProbeEligibleReason(verifyReason: string): boolean {
    return PROBE_VERIFY_REASON_RE.test(verifyReason ?? '');
}

/**
 * Derive an endpoint candidate when the deterministic project map has no
 * endpoints for the finding's file — frameworks like Effect-TS, NestJS,
 * Hono, or Koa that the map does not extract, or scans whose map lookup
 * predates a map refresh.
 *
 * Pass 1 scans the target file's code within the same ±25 / +200 line
 * window matchEndpointForFinding uses, so the derived candidate is always
 * the route registration nearest the finding.
 * Pass 2 mines the finding's own evidence/why text for explicit
 * "METHOD '/path'" strings.
 *
 * Returns a ProbeEndpointCandidate with derived:true, or null.
 */
export function deriveEndpointFallback(
    finding: {
        line: number;
        lineEnd?: number;
        evidence?: string;
        why?: string;
        evidenceChain?: {
            source?: { description?: string };
            sink?: { description?: string };
        };
    },
    code: string,
): ProbeEndpointCandidate | null {
    // Pass 1: route-registration scan in the code window around the finding.
    const lines = code.split(/\r?\n/);
    const windowStart = Math.max(0, finding.line - 26);
    const windowEnd = Math.min(lines.length, finding.line + 200);
    for (let i = windowStart; i < windowEnd; i++) {
        const lineText = lines[i];
        if (!lineText) continue;
        for (const pat of FALLBACK_ROUTE_PATTERNS) {
            const m = lineText.match(pat.re);
            if (!m) continue;
            const rawPath = m[pat.pathGroup] || '';
            if (!rawPath) continue;
            const normalizedPath = rawPath.startsWith('/') ? `/${rawPath.slice(1)}` : `/${rawPath}`;
            return {
                method: pat.methodFrom(m),
                path: normalizedPath,
                line: i + 1,
                derived: true,
            };
        }
    }

    // Pass 2: mine the finding's own text for "METHOD '/path'" mentions —
    // the agent has read the route definition, and often says so verbatim.
    const texts = [
        finding.evidence,
        finding.why,
        finding.evidenceChain?.source?.description,
        finding.evidenceChain?.sink?.description,
    ].filter((t): t is string => typeof t === 'string' && t.length > 0);
    for (const text of texts) {
        const m = text.match(FALLBACK_EVIDENCE_ROUTE_RE);
        if (m) {
            return {
                method: m[1].toUpperCase(),
                path: m[2],
                line: finding.line,
                derived: true,
            };
        }
    }

    return null;
}

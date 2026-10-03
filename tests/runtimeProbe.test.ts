// Unit tests for the runtime probe engine — policy enforcement, URL encoding,
// redaction, baseline/attack pairing, abort handling, dev-server detection,
// and probe eligibility.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as net from 'net';
import * as os from 'os';
import * as path from 'path';

vi.mock('../src/attack/executor', () => ({
    executeHttpRequest: vi.fn(),
}));

import { executeHttpRequest, type ExecResponse } from '../src/attack/executor';
import {
    detectDevServer,
    encodeProbePath,
    executeProbePlan,
    isProbeEligible,
    matchEndpointForFinding,
    type ProbePlan,
    type ProbeRequest,
} from '../src/attack/runtimeProbe';

const PROBE_BUDGET = {
    maxSteps: 8,
    maxRequests: 8,
    wallClockMs: 60_000,
    maxResponseBytes: 200_000,
    requestTimeoutMs: 10_000,
    costCapUsd: 0,
};

function makeResponse(statusCode: number, body = ''): ExecResponse {
    return { statusCode, headers: {}, body, latencyMs: 5 };
}

function attackReq(overrides?: Partial<ProbeRequest>): ProbeRequest {
    return { role: 'attack', method: 'GET', path: '/api/users', ...overrides };
}

function baselineReq(overrides?: Partial<ProbeRequest>): ProbeRequest {
    return { role: 'baseline', method: 'GET', path: '/api/users', ...overrides };
}

async function startListener(): Promise<{ server: net.Server; port: number }> {
    const server = net.createServer(() => {});
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    const addr = server.address();
    if (!addr || typeof addr !== 'object') throw new Error('no address');
    return { server, port: addr.port };
}

async function acquireFreePort(): Promise<number> {
    const { server, port } = await startListener();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    return port;
}

describe('executeProbePlan — policy enforcement', () => {
    beforeEach(() => {
        vi.mocked(executeHttpRequest).mockReset();
    });

    it('returns INCONCLUSIVE for a non-localhost host', async () => {
        const plan: ProbePlan = {
            host: 'example.com',
            port: 80,
            requests: [attackReq()],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('Policy validation failed');
        expect(result.reason).toContain('not allowed');
        expect(vi.mocked(executeHttpRequest)).not.toHaveBeenCalled();
    });

    it('uses caller-provided host/port when the plan omits them (API plan shape)', async () => {
        vi.mocked(executeHttpRequest).mockResolvedValue(makeResponse(200, 'ok'));
        const plan: ProbePlan = { requests: [attackReq()] };
        await executeProbePlan(plan, { host: '127.0.0.1', port: 3773 });
        const call = vi.mocked(executeHttpRequest).mock.calls[0];
        expect(call[0]).toEqual(expect.objectContaining({ host: '127.0.0.1', port: 3773 }));
    });

    it('returns INCONCLUSIVE when neither the plan nor the caller provides host/port', async () => {
        const plan: ProbePlan = { requests: [attackReq()] };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('no target host/port');
        expect(vi.mocked(executeHttpRequest)).not.toHaveBeenCalled();
    });

    it('rejects path traversal in the probe path', async () => {
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [attackReq({ path: '/../etc/passwd' })],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('traversal');
        expect(vi.mocked(executeHttpRequest)).not.toHaveBeenCalled();
    });

    it('rejects an absolute URL as the probe path', async () => {
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [attackReq({ path: 'http://evil.com/x' })],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('must start with');
        expect(vi.mocked(executeHttpRequest)).not.toHaveBeenCalled();
    });

    it('rejects a plan larger than the request budget', async () => {
        const requests = Array.from({ length: 9 }, () => baselineReq());
        const result = await executeProbePlan({ host: '127.0.0.1', port: 3000, requests });
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('exceeding the budget cap');
        expect(vi.mocked(executeHttpRequest)).not.toHaveBeenCalled();
    });
});

describe('executeProbePlan — URL encoding', () => {
    beforeEach(() => {
        vi.mocked(executeHttpRequest).mockReset();
    });

    it('encodes a SQLi payload with spaces and quotes in the query', async () => {
        vi.mocked(executeHttpRequest).mockResolvedValue(makeResponse(200, '{"ok":true}'));
        const payload = "/api/users?id=1' OR '1'='1 --";
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [attackReq({
                path: payload,
                expect: { successStatus: [200], successBodyPattern: '"ok":\\s*true' },
            })],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('PROVEN');

        const calls = vi.mocked(executeHttpRequest).mock.calls;
        expect(calls.length).toBe(1);
        const sentPath = calls[0][0].path;
        expect(sentPath).not.toContain(' ');
        expect(sentPath).toContain('%20');
        expect(sentPath.startsWith('/api/users?')).toBe(true);
        const query = sentPath.slice(sentPath.indexOf('?') + 1);
        expect(decodeURIComponent(query)).toBe("id=1' OR '1'='1 --");
    });

    it('passes the probe budget and abort signal to the executor', async () => {
        vi.mocked(executeHttpRequest).mockResolvedValue(makeResponse(200, 'ok'));
        const controller = new AbortController();
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [attackReq()],
        };
        await executeProbePlan(plan, { signal: controller.signal });
        const call = vi.mocked(executeHttpRequest).mock.calls[0];
        expect(call[1]).toEqual(PROBE_BUDGET);
        expect(call[2]).toBe(controller.signal);
    });
});

describe('executeProbePlan — redaction', () => {
    beforeEach(() => {
        vi.mocked(executeHttpRequest).mockReset();
    });

    it('never leaks a JWT from the response body into evidence', async () => {
        const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        vi.mocked(executeHttpRequest)
            .mockResolvedValueOnce(makeResponse(401, 'unauthorized'))
            .mockResolvedValueOnce(makeResponse(200, `{"token":"${jwt}","user":"admin"}`));
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [baselineReq(), attackReq()],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('PROVEN');
        expect(result.evidence).toContain('[JWT_REDACTED]');
        expect(result.evidence).not.toContain('eyJhbGciOiJIUzI1NiJ9');
        expect(result.reason).not.toContain('eyJhbGciOiJIUzI1NiJ9');
        expect(result.requests.every((r) => !('body' in r))).toBe(true);
    });
});

describe('executeProbePlan — baseline/attack pairing', () => {
    beforeEach(() => {
        vi.mocked(executeHttpRequest).mockReset();
    });

    it('evaluates the LAST baseline/attack pair when the plan has multiple pairs', async () => {
        vi.mocked(executeHttpRequest)
            .mockResolvedValueOnce(makeResponse(200, 'list'))
            .mockResolvedValueOnce(makeResponse(403, 'blocked'))
            .mockResolvedValueOnce(makeResponse(401, ''))
            .mockResolvedValueOnce(makeResponse(200, 'admin user data'));
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [baselineReq(), attackReq(), baselineReq(), attackReq()],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('PROVEN');
        expect(result.rule).toBe('auth-bypass');
        expect(result.baselineStatus).toBe(401);
        expect(result.attackStatus).toBe(200);
        expect(result.requests.length).toBe(4);
        expect(result.requests.map((r) => r.statusCode)).toEqual([200, 403, 401, 200]);
    });

    it('maps a refuted rule to UNPROVEN', async () => {
        vi.mocked(executeHttpRequest).mockResolvedValue(makeResponse(403, 'forbidden'));
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [attackReq({ expect: { expectedStatus: [403] } })],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('UNPROVEN');
        expect(result.rule).toBe('blocked');
    });

    it('maps an errored attack transport (statusCode 0) to INCONCLUSIVE', async () => {
        vi.mocked(executeHttpRequest).mockResolvedValue({
            statusCode: 0,
            headers: {},
            body: '',
            latencyMs: 3,
            error: 'connect ECONNREFUSED',
        });
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [attackReq()],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('no response');
    });

    it('is INCONCLUSIVE when the plan has no attack request', async () => {
        vi.mocked(executeHttpRequest).mockResolvedValue(makeResponse(200, 'ok'));
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [baselineReq()],
        };
        const result = await executeProbePlan(plan);
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toContain('no attack request');
    });
});

describe('executeProbePlan — abort handling', () => {
    beforeEach(() => {
        vi.mocked(executeHttpRequest).mockReset();
    });

    it('returns INCONCLUSIVE "cancelled" when the signal fires between requests', async () => {
        const controller = new AbortController();
        vi.mocked(executeHttpRequest).mockImplementationOnce(async () => {
            controller.abort();
            return makeResponse(200, 'ok');
        });
        vi.mocked(executeHttpRequest).mockResolvedValue(makeResponse(200, 'ok'));
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [baselineReq(), attackReq()],
        };
        const result = await executeProbePlan(plan, { signal: controller.signal });
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toBe('cancelled');
        expect(result.requests.length).toBe(1);
        expect(vi.mocked(executeHttpRequest)).toHaveBeenCalledTimes(1);
    });

    it('returns INCONCLUSIVE "cancelled" when the signal is already aborted', async () => {
        const controller = new AbortController();
        controller.abort();
        vi.mocked(executeHttpRequest).mockResolvedValue(makeResponse(200, 'ok'));
        const plan: ProbePlan = {
            host: '127.0.0.1',
            port: 3000,
            requests: [baselineReq(), attackReq()],
        };
        const result = await executeProbePlan(plan, { signal: controller.signal });
        expect(result.verdict).toBe('INCONCLUSIVE');
        expect(result.reason).toBe('cancelled');
        expect(result.requests.length).toBe(0);
        expect(vi.mocked(executeHttpRequest)).not.toHaveBeenCalled();
    });
});

describe('encodeProbePath', () => {
    it('encodes spaces and quotes in the query and preserves structure', () => {
        expect(encodeProbePath("/api/users?id=1' OR '1'='1 --"))
            .toBe("/api/users?id=1%27%20OR%20%271%27=%271%20--");
        expect(encodeProbePath('/a b')).toBe('/a%20b');
        expect(encodeProbePath('/api/users')).toBe('/api/users');
    });
});

describe('detectDevServer', () => {
    let listenerA: { server: net.Server; port: number };
    let listenerB: { server: net.Server; port: number };
    let workspace: string;
    let freePort: number;

    beforeEach(async () => {
        listenerA = await startListener();
        listenerB = await startListener();
        freePort = await acquireFreePort();
        workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'securecode-probe-'));
        delete process.env.SECURECODE_DEV_SERVER_PORT;
    });

    afterEach(async () => {
        delete process.env.SECURECODE_DEV_SERVER_PORT;
        fs.rmSync(workspace, { recursive: true, force: true });
        await Promise.all([
            new Promise<void>((resolve) => listenerA.server.close(() => resolve())),
            new Promise<void>((resolve) => listenerB.server.close(() => resolve())),
        ]);
    });

    function writeConfig(cfg: unknown): void {
        fs.mkdirSync(path.join(workspace, '.securecode'), { recursive: true });
        fs.writeFileSync(
            path.join(workspace, '.securecode', 'runtime-probe.json'),
            JSON.stringify(cfg),
        );
    }

    it('prefers the SECURECODE_DEV_SERVER_PORT env var over the config file', async () => {
        writeConfig({ port: listenerA.port });
        process.env.SECURECODE_DEV_SERVER_PORT = String(listenerB.port);
        const target = await detectDevServer(workspace);
        expect(target).toEqual({ host: '127.0.0.1', port: listenerB.port, source: 'env' });
    });

    it('falls back to the config file when the env value is not a port', async () => {
        writeConfig({ port: listenerA.port });
        process.env.SECURECODE_DEV_SERVER_PORT = 'not-a-port';
        const target = await detectDevServer(workspace);
        expect(target).toEqual({ host: '127.0.0.1', port: listenerA.port, source: 'config' });
    });

    it('reads host and port from .securecode/runtime-probe.json', async () => {
        writeConfig({ host: 'localhost', port: listenerA.port });
        const target = await detectDevServer(workspace);
        expect(target).toEqual({ host: 'localhost', port: listenerA.port, source: 'config' });
    });

    it('ignores a config pointing at a non-localhost host', async () => {
        writeConfig({ host: 'example.com', port: listenerA.port });
        const target = await detectDevServer(workspace, { candidatePorts: [freePort, listenerB.port] });
        expect(target).toEqual({ host: '127.0.0.1', port: listenerB.port, source: 'autodetect' });
    });

    it('survives a malformed config file and falls through to autodetect', async () => {
        fs.mkdirSync(path.join(workspace, '.securecode'), { recursive: true });
        fs.writeFileSync(path.join(workspace, '.securecode', 'runtime-probe.json'), '{not json');
        const target = await detectDevServer(workspace, { candidatePorts: [listenerA.port] });
        expect(target).toEqual({ host: '127.0.0.1', port: listenerA.port, source: 'autodetect' });
    });

    it('autodetects the first open candidate port', async () => {
        const target = await detectDevServer(workspace, {
            candidatePorts: [freePort, listenerA.port, listenerB.port],
        });
        expect(target).toEqual({ host: '127.0.0.1', port: listenerA.port, source: 'autodetect' });
    });

    it('returns null when nothing listens', async () => {
        const target = await detectDevServer(workspace, {
            candidatePorts: [freePort, await acquireFreePort()],
        });
        expect(target).toBeNull();
    });
});

describe('isProbeEligible / matchEndpointForFinding', () => {
    const timeoutReason = 'Test timed out after 12 rounds — Effect-TS module requires full runtime';
    const endpoints = [
        { method: 'GET', path: '/api/users', line: 42, handlerName: 'listUsers' },
    ];

    it('matches an endpoint within 25 lines of the finding', () => {
        const finding = { type: 'sql_injection', line: 50 };
        expect(isProbeEligible(finding, timeoutReason, endpoints)).toBe(true);
        expect(matchEndpointForFinding(finding, endpoints)).toEqual(endpoints[0]);
    });

    it('matches an endpoint whose handler covers the finding line (line..line+200)', () => {
        const endpointsDeep = [{ method: 'POST', path: '/api/users', line: 10 }];
        const finding = { type: 'broken_access_control', line: 150 };
        expect(isProbeEligible(finding, timeoutReason, endpointsDeep)).toBe(true);
    });

    it('rejects findings with no nearby endpoint', () => {
        const farEndpoints = [{ method: 'GET', path: '/api/users', line: 400 }];
        const finding = { type: 'sql_injection', line: 50 };
        expect(matchEndpointForFinding(finding, farEndpoints)).toBeNull();
        expect(isProbeEligible(finding, timeoutReason, farEndpoints)).toBe(false);
    });

    it('skips endpoints without a method or path', () => {
        const partial = [{ method: 'GET', line: 42 }, { path: '/x', line: 42 }];
        const finding = { type: 'ssrf', line: 42 };
        expect(matchEndpointForFinding(finding, partial)).toBeNull();
    });

    it('requires an HTTP-routable vulnerability type', () => {
        const finding = { type: 'command_injection', line: 50 };
        expect(isProbeEligible(finding, timeoutReason, endpoints)).toBe(false);
        expect(isProbeEligible({ type: 'xss', line: 50 }, timeoutReason, endpoints)).toBe(true);
    });

    it('requires a sandbox-failure verify reason', () => {
        const finding = { type: 'sql_injection', line: 50 };
        expect(isProbeEligible(finding, 'test passed in sandbox, all green', endpoints)).toBe(false);
        expect(isProbeEligible(finding, 'DOM/jsdom cannot render this', endpoints)).toBe(true);
        expect(isProbeEligible(finding, 'cannot test in sandbox without a database', endpoints)).toBe(true);
    });

    it('returns null for undefined endpoint context', () => {
        expect(matchEndpointForFinding({ type: 'ssrf', line: 1 }, undefined)).toBeNull();
        expect(isProbeEligible({ type: 'ssrf', line: 1 }, timeoutReason, undefined)).toBe(false);
    });
});

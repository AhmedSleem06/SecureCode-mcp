import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import {
    isLocalhostHost,
    validateTarget,
    isRedirectToNonLocal,
    checkBudget,
    DEFAULT_BUDGET,
    PolicyError,
} from '../src/attack/policy';
import { executeHttpRequest } from '../src/attack/executor';
import { redactText, buildReport } from '../src/attack/report';

describe('Policy — localhost validation', () => {
    it('accepts 127.0.0.1', () => {
        expect(isLocalhostHost('127.0.0.1')).toBe(true);
    });

    it('accepts localhost', () => {
        expect(isLocalhostHost('localhost')).toBe(true);
    });

    it('accepts ::1', () => {
        expect(isLocalhostHost('::1')).toBe(true);
    });

    it('rejects external hosts', () => {
        expect(isLocalhostHost('example.com')).toBe(false);
        expect(isLocalhostHost('10.0.0.1')).toBe(false);
        expect(isLocalhostHost('192.168.1.1')).toBe(false);
    });
});

describe('Policy — target validation', () => {
    it('accepts valid localhost target', () => {
        expect(() => validateTarget({ host: '127.0.0.1', port: 3000, path: '/api/users' })).not.toThrow();
    });

    it('rejects external host', () => {
        expect(() => validateTarget({ host: 'example.com', port: 80, path: '/' })).toThrow(PolicyError);
    });

    it('rejects invalid port', () => {
        expect(() => validateTarget({ host: '127.0.0.1', port: 0, path: '/' })).toThrow(PolicyError);
        expect(() => validateTarget({ host: '127.0.0.1', port: 70000, path: '/' })).toThrow(PolicyError);
    });

    it('rejects path traversal', () => {
        expect(() => validateTarget({ host: '127.0.0.1', port: 3000, path: '/../etc/passwd' })).toThrow(PolicyError);
    });

    it('rejects path without leading slash', () => {
        expect(() => validateTarget({ host: '127.0.0.1', port: 3000, path: 'api' })).toThrow(PolicyError);
    });
});

describe('Policy — redirect blocking', () => {
    it('blocks redirect to external host', () => {
        expect(isRedirectToNonLocal(302, 'https://evil.com/steal')).toBe(true);
    });

    it('allows redirect to localhost', () => {
        expect(isRedirectToNonLocal(302, 'http://127.0.0.1:3000/login')).toBe(false);
    });

    it('ignores non-redirect status codes', () => {
        expect(isRedirectToNonLocal(200, 'https://evil.com')).toBe(false);
    });

    it('blocks protocol-relative redirect to external', () => {
        expect(isRedirectToNonLocal(301, '//evil.com/x')).toBe(true);
    });
});

describe('Policy — budget enforcement', () => {
    it('allows when within budget', () => {
        const state = { stepsTaken: 5, requestsMade: 10, startTime: Date.now() };
        expect(checkBudget(DEFAULT_BUDGET, state).exhausted).toBe(false);
    });

    it('exhausts on max steps', () => {
        const state = { stepsTaken: 12, requestsMade: 5, startTime: Date.now() };
        const result = checkBudget(DEFAULT_BUDGET, state);
        expect(result.exhausted).toBe(true);
        expect(result.reason).toContain('steps');
    });

    it('exhausts on max requests', () => {
        const state = { stepsTaken: 1, requestsMade: 50, startTime: Date.now() };
        const result = checkBudget(DEFAULT_BUDGET, state);
        expect(result.exhausted).toBe(true);
        expect(result.reason).toContain('requests');
    });

    it('exhausts on wall clock', () => {
        const state = { stepsTaken: 1, requestsMade: 5, startTime: Date.now() - 100_000 };
        const result = checkBudget(DEFAULT_BUDGET, state);
        expect(result.exhausted).toBe(true);
        expect(result.reason).toMatch(/wall clock/i);
    });
});

describe('Executor — HTTP requests against localhost', () => {
    let server: http.Server;
    let port: number;

    beforeAll(async () => {
        server = http.createServer((req, res) => {
            if (req.url === '/ok') {
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ status: 'ok' }));
            } else if (req.url === '/large') {
                res.writeHead(200);
                res.end(Buffer.alloc(2_000_000, 0x41));
            } else if (req.url === '/redirect') {
                res.writeHead(302, { Location: 'https://evil.com/steal' });
                res.end();
            } else if (req.url === '/redirect-local') {
                res.writeHead(302, { Location: 'http://127.0.0.1:' + port + '/ok' });
                res.end();
            } else if (req.url === '/slow') {
                setTimeout(() => { res.writeHead(200); res.end('late'); }, 15_000);
            } else {
                res.writeHead(404);
                res.end('Not found');
            }
        });
        await new Promise<void>((resolve) => {
            server.listen(0, '127.0.0.1', () => {
                port = (server.address() as any).port;
                resolve();
            });
        });
    });

    afterAll(async () => {
        await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('sends a GET request and receives the response', async () => {
        const resp = await executeHttpRequest(
            { method: 'GET', path: '/ok', host: '127.0.0.1', port },
            DEFAULT_BUDGET,
        );
        expect(resp.statusCode).toBe(200);
        expect(resp.body).toContain('ok');
    });

    it('truncates response exceeding maxResponseBytes', async () => {
        const resp = await executeHttpRequest(
            { method: 'GET', path: '/large', host: '127.0.0.1', port },
            DEFAULT_BUDGET,
        );
        expect(resp.error).toContain('exceeded');
        expect(resp.body.length).toBeLessThanOrEqual(DEFAULT_BUDGET.maxResponseBytes);
    });

    it('blocks redirect to non-localhost', async () => {
        const resp = await executeHttpRequest(
            { method: 'GET', path: '/redirect', host: '127.0.0.1', port },
            DEFAULT_BUDGET,
        );
        expect(resp.error).toContain('Redirect to non-localhost blocked');
    });

    it('handles connection refused', async () => {
        const resp = await executeHttpRequest(
            { method: 'GET', path: '/', host: '127.0.0.1', port: 1 },
            DEFAULT_BUDGET,
        );
        expect(resp.statusCode).toBe(0);
        expect(resp.error).toBeDefined();
    });

    it('handles 404 gracefully', async () => {
        const resp = await executeHttpRequest(
            { method: 'GET', path: '/nonexistent', host: '127.0.0.1', port },
            DEFAULT_BUDGET,
        );
        expect(resp.statusCode).toBe(404);
    });
});

describe('Report — redaction', () => {
    it('redacts JWTs', () => {
        const text = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        const redacted = redactText(text);
        expect(redacted).toContain('[JWT_REDACTED]');
        expect(redacted).not.toContain('eyJhbGciOiJIUzI1NiJ9');
    });

    it('redacts emails', () => {
        const text = 'User email: admin@example.com contacted';
        const redacted = redactText(text);
        expect(redacted).toContain('[EMAIL_REDACTED]');
        expect(redacted).not.toContain('admin@example.com');
    });

    it('redacts Bearer tokens', () => {
        const text = 'Authorization: Bearer abc123def456';
        const redacted = redactText(text);
        expect(redacted).toContain('[REDACTED]');
    });

    it('redacts 32-char API keys', () => {
        const text = 'Authorization: Bearer AKIAIOSFODNN7EXAMPLE1234567890AB';
        const redacted = redactText(text);
        expect(redacted).toContain('[REDACTED]');
    });
});

describe('Report — buildReport', () => {
    it('builds a report with findings and redacted transcript', () => {
        const transcript = [
            {
                action: {
                    type: 'http_request' as const,
                    method: 'GET' as const,
                    path: '/api/users',
                    headers: { Authorization: 'Bearer secret123' },
                    rationale: 'test',
                },
                observation: {
                    statusCode: 200,
                    headers: { 'Set-Cookie': 'session=abc123' },
                    body: '{"email":"admin@test.com"}',
                    latencyMs: 50,
                },
            },
        ];
        const report = buildReport('completed', [], transcript, 1, 0.01, 'done');
        expect(report.status).toBe('completed');
        expect(report.stepsUsed).toBe(1);
        expect(report.transcript[0].action.headers.Authorization).toBe('[REDACTED]');
        expect(report.transcript[0].observation.headers['Set-Cookie']).toBe('[REDACTED]');
        expect(report.transcript[0].observation.body).toContain('[EMAIL_REDACTED]');
    });
});

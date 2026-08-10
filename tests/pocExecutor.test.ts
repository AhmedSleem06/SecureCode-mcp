import { describe, it, expect, vi, beforeEach } from 'vitest';
import { routePoc } from '../src/poc/pocRouter';
import { generatePandaScript, isLightpandaAvailable, _resetAvailabilityCache } from '../src/poc/lightpandaExecutor';
import { executePoc } from '../src/poc/pocExecutor';
import { executeWithHttp } from '../src/poc/httpPocExecutor';
import type { PocRequest } from '../src/poc/pocTypes';

// ── Router tests ────────────────────────────────────────────────────────────

describe('POC Router', () => {
    it('routes XSS to Lightpanda', () => {
        expect(routePoc('xss')).toBe('lightpanda');
    });

    it('routes SQL injection to HTTP', () => {
        expect(routePoc('sql_injection')).toBe('http');
    });

    it('routes NoSQL injection to HTTP', () => {
        expect(routePoc('nosql_injection')).toBe('http');
    });

    it('routes SSRF to HTTP', () => {
        expect(routePoc('ssrf')).toBe('http');
    });

    it('routes open redirect to HTTP', () => {
        expect(routePoc('open_redirect')).toBe('http');
    });

    it('routes broken access control to HTTP', () => {
        expect(routePoc('broken_access_control')).toBe('http');
    });

    it('routes command injection to none (taint tracker covers it)', () => {
        expect(routePoc('command_injection')).toBe('none');
    });

    it('routes prototype pollution to none', () => {
        expect(routePoc('prototype_pollution')).toBe('none');
    });

    it('routes insecure crypto to none', () => {
        expect(routePoc('insecure_crypto')).toBe('none');
    });

    it('routes path traversal to none', () => {
        expect(routePoc('path_traversal')).toBe('none');
    });

    it('routes unknown types to none', () => {
        expect(routePoc('unknown_vuln')).toBe('none');
    });
});

// ── PandaScript generation tests ────────────────────────────────────────────

describe('PandaScript generation', () => {
    const baseReq: PocRequest = {
        vulnType: 'xss',
        poc: 'Inject <script>alert(1)</script> into the search query',
        endpoint: { method: 'GET', path: '/search', baseUrl: 'http://127.0.0.1:3000' },
        payload: '<script>alert(1)</script>',
        injectionPoint: 'query',
        paramName: 'q',
    };

    it('generates a query-injection PandaScript for XSS', () => {
        const script = generatePandaScript(baseReq);
        expect(script).toContain('new Page()');
        expect(script).toContain('page.goto');
        expect(script).toContain('/search?q=');
        expect(script).toContain('page.extract');
        expect(script).toContain('exploited');
        expect(script).toContain('<script>alert(1)</script>');
    });

    it('generates a body-injection PandaScript for XSS', () => {
        const script = generatePandaScript({
            ...baseReq,
            injectionPoint: 'body',
            paramName: 'comment',
        });
        expect(script).toContain('page.fill');
        expect(script).toContain('page.click');
        expect(script).toContain('comment');
    });

    it('generates a redirect PandaScript for open_redirect', () => {
        const script = generatePandaScript({
            ...baseReq,
            vulnType: 'open_redirect',
            payload: 'https://evil.com',
            paramName: 'url',
        });
        expect(script).toContain('page.getUrl');
        expect(script).toContain('evil.com');
    });

    it('generates a generic fallback script for unknown vuln types', () => {
        const script = generatePandaScript({
            ...baseReq,
            vulnType: 'unknown_type',
        });
        expect(script).toContain('Generic POC');
        expect(script).toContain('page.goto');
    });
});

// ── Lightpanda availability ──────────────────────────────────────────────────

describe('Lightpanda availability', () => {
    beforeEach(() => {
        _resetAvailabilityCache();
    });

    it('returns false when lightpanda is not installed', () => {
        // In the test environment, lightpanda is not installed
        expect(isLightpandaAvailable()).toBe(false);
    });
});

// ── Main executor integration ────────────────────────────────────────────────

describe('executePoc (main entry point)', () => {
    it('returns none backend for command_injection', async () => {
        const result = await executePoc({
            vulnType: 'command_injection',
            poc: 'exec(userInput)',
            endpoint: { method: 'GET', path: '/' },
        });
        expect(result.backend).toBe('none');
        expect(result.evidence).toContain('deterministic analysis');
    });

    it('returns none backend for prototype_pollution', async () => {
        const result = await executePoc({
            vulnType: 'prototype_pollution',
            poc: 'merge({}, req.body)',
            endpoint: { method: 'GET', path: '/' },
        });
        expect(result.backend).toBe('none');
    });

    it('returns lightpanda backend (not available) for XSS', async () => {
        _resetAvailabilityCache();
        const result = await executePoc({
            vulnType: 'xss',
            poc: 'XSS via query param',
            endpoint: { method: 'GET', path: '/search', baseUrl: 'http://127.0.0.1:3000' },
            payload: '<script>alert(1)</script>',
            injectionPoint: 'query',
            paramName: 'q',
        });
        // Lightpanda not installed in test env → returns 'none' backend
        expect(result.backend).toBe('none');
        expect(result.evidence).toContain('not found');
    });
});

// ── HTTP executor tests (mocked fetch) ───────────────────────────────────────

describe('HTTP POC executor', () => {
    it('detects SQL error in response', async () => {
        const mockResponse = {
            status: 500,
            headers: { forEach: (cb: (v: string, k: string) => void) => { cb('text/html', 'content-type'); } },
            text: async () => 'SQL syntax error near line 1: SELECT * FROM users WHERE id = 1\' OR 1=1--',
        };
        global.fetch = vi.fn().mockResolvedValue(mockResponse as any);

        const result = await executePoc({
            vulnType: 'sql_injection',
            poc: 'Inject 1\' OR 1=1--',
            endpoint: { method: 'GET', path: '/users', baseUrl: 'http://127.0.0.1:3000' },
            payload: "1' OR 1=1--",
            injectionPoint: 'query',
            paramName: 'id',
        });
        expect(result.backend).toBe('http');
        expect(result.exploitable).toBe(true);
        expect(result.evidence).toContain('SQL error');
    });

    it('detects XSS reflection in response (via HTTP executor directly)', async () => {
        const mockResponse = {
            status: 200,
            headers: { forEach: () => {} },
            text: async () => '<div>Results for: <script>alert(1)</script></div>',
        };
        global.fetch = vi.fn().mockResolvedValue(mockResponse as any);

        // XSS routes to Lightpanda, but the HTTP executor can also detect
        // reflected XSS. Test it directly.
        const result = await executeWithHttp({
            vulnType: 'xss',
            poc: 'Reflected XSS',
            endpoint: { method: 'GET', path: '/search', baseUrl: 'http://127.0.0.1:3000' },
            payload: '<script>alert(1)</script>',
            injectionPoint: 'query',
            paramName: 'q',
        });
        expect(result.exploitable).toBe(true);
        expect(result.evidence).toContain('reflected');
    });

    it('detects open redirect via Location header', async () => {
        const mockResponse = {
            status: 302,
            headers: { forEach: (cb: (v: string, k: string) => void) => {
                cb('https://evil.com', 'location');
            } },
            text: async () => '',
        };
        global.fetch = vi.fn().mockResolvedValue(mockResponse as any);

        const result = await executePoc({
            vulnType: 'open_redirect',
            poc: 'Redirect to evil.com',
            endpoint: { method: 'GET', path: '/redirect', baseUrl: 'http://127.0.0.1:3000' },
            payload: 'https://evil.com',
            injectionPoint: 'query',
            paramName: 'url',
        });
        expect(result.exploitable).toBe(true);
        expect(result.evidence).toContain('Redirected');
    });

    it('detects access control bypass (200 when 401 expected)', async () => {
        const mockResponse = {
            status: 200,
            headers: { forEach: () => {} },
            text: async () => '{"data": "sensitive"}',
        };
        global.fetch = vi.fn().mockResolvedValue(mockResponse as any);

        const result = await executePoc({
            vulnType: 'broken_access_control',
            poc: 'Access admin endpoint without auth',
            endpoint: { method: 'GET', path: '/admin/users', baseUrl: 'http://127.0.0.1:3000' },
        });
        expect(result.exploitable).toBe(true);
        expect(result.evidence).toContain('Access control bypass');
    });

    it('returns not exploitable when SQL injection does not error', async () => {
        const mockResponse = {
            status: 200,
            headers: { forEach: () => {} },
            text: async () => '{"users": []}',
        };
        global.fetch = vi.fn().mockResolvedValue(mockResponse as any);

        const result = await executePoc({
            vulnType: 'sql_injection',
            poc: 'Inject normal value',
            endpoint: { method: 'GET', path: '/users', baseUrl: 'http://127.0.0.1:3000' },
            payload: '42',
            injectionPoint: 'query',
            paramName: 'id',
        });
        expect(result.exploitable).toBe(false);
    });

    it('handles fetch errors gracefully', async () => {
        global.fetch = vi.fn().mockRejectedValue(new Error('Connection refused'));

        const result = await executePoc({
            vulnType: 'sql_injection',
            poc: 'SQLi test',
            endpoint: { method: 'GET', path: '/users', baseUrl: 'http://127.0.0.1:3000' },
            payload: "1' OR 1=1--",
            injectionPoint: 'query',
            paramName: 'id',
        });
        expect(result.exploitable).toBe(false);
        expect(result.error).toContain('Connection refused');
        expect(result.backend).toBe('http');
    });

    it('handles timeout gracefully', async () => {
        global.fetch = vi.fn().mockRejectedValue(
            Object.assign(new Error('The operation was aborted'), { name: 'TimeoutError' })
        );

        const result = await executePoc({
            vulnType: 'sql_injection',
            poc: 'SQLi test',
            endpoint: { method: 'GET', path: '/users', baseUrl: 'http://127.0.0.1:3000' },
            payload: "1' OR 1=1--",
            injectionPoint: 'query',
            paramName: 'id',
        });
        expect(result.exploitable).toBe(false);
        expect(result.timedOut).toBe(true);
        expect(result.evidence).toContain('timed out');
    });
});

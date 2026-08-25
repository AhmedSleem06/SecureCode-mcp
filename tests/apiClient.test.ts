import { describe, it, expect, afterEach } from 'vitest';
import * as http from 'http';
import { ApiClient, ApiClientError } from '../src/api/client';
import type { CreditBalanceResponse } from '../src/api/types';

let server: http.Server;

function startServer(handler: (req: http.IncomingMessage, res: http.ServerResponse) => void): Promise<string> {
    return new Promise(resolve => {
        server = http.createServer(handler);
        server.listen(0, '127.0.0.1', () => {
            const addr = server.address();
            resolve(`http://127.0.0.1:${(addr as any).port}`);
        });
    });
}

afterEach(() => {
    if (server) server.close();
});

describe('ApiClientError', () => {
    it('preserves credit details from constructor', () => {
        const err = new ApiClientError(402, 'INSUFFICIENT_CREDITS', 'Not enough credits', 3, {
            creditType: 'scan',
            requested: 10,
            balance: 3,
            required: 10,
            available: 3,
        });
        expect(err.status).toBe(402);
        expect(err.apiCode).toBe('INSUFFICIENT_CREDITS');
        expect(err.remaining).toBe(3);
        expect(err.creditType).toBe('scan');
        expect(err.requested).toBe(10);
        expect(err.balance).toBe(3);
        expect(err.required).toBe(10);
        expect(err.available).toBe(3);
    });

    it('preserves backward-compatible remaining field', () => {
        const err = new ApiClientError(402, undefined, 'msg', 5);
        expect(err.remaining).toBe(5);
        expect(err.creditType).toBeUndefined();
    });

    it('isInsufficientCredits detects 402', () => {
        const err = new ApiClientError(402, 'INSUFFICIENT_CREDITS', 'msg', 0);
        expect(ApiClientError.isInsufficientCredits(err)).toBe(true);
    });

    it('isInsufficientCredits rejects non-402', () => {
        const err = new ApiClientError(500, undefined, 'msg', undefined);
        expect(ApiClientError.isInsufficientCredits(err)).toBe(false);
    });

    it('isAgentScanConflict detects 409', () => {
        const err = new ApiClientError(409, 'AGENT_SCAN_ALREADY_RUNNING', 'msg', undefined);
        expect(ApiClientError.isAgentScanConflict(err)).toBe(true);
    });

    it('isAgentScanConflict detects code without 409', () => {
        const err = new ApiClientError(500, 'AGENT_SCAN_ALREADY_RUNNING', 'msg', undefined);
        expect(ApiClientError.isAgentScanConflict(err)).toBe(true);
    });

    it('isCreditLockTimeout detects code', () => {
        const err = new ApiClientError(503, 'CREDIT_LOCK_TIMEOUT', 'msg', undefined, { retryable: true });
        expect(ApiClientError.isCreditLockTimeout(err)).toBe(true);
        expect(err.retryable).toBe(true);
    });

    it('isCreditLockTimeout rejects other 503s', () => {
        const err = new ApiClientError(503, 'OTHER_ERROR', 'msg', undefined);
        expect(ApiClientError.isCreditLockTimeout(err)).toBe(false);
    });
});

describe('ApiClient.getJson', () => {
    it('makes an authenticated GET request', async () => {
        const baseUrl = await startServer((req, res) => {
            expect(req.method).toBe('GET');
            expect(req.headers.authorization).toBe('Bearer test-token');
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ scanCredits: 100, attackerCredits: 50 }));
        });

        const client = new ApiClient({ baseUrl, token: 'test-token' });
        const result = await client.getJson<CreditBalanceResponse>('/credits/balance');
        expect(result.scanCredits).toBe(100);
        expect(result.attackerCredits).toBe(50);
    });

    it('parses /credits/balance response', async () => {
        const baseUrl = await startServer((req, res) => {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                scanCredits: 95,
                attackerCredits: 30,
                scanCreditsExpiringSoon: 10,
            }));
        });

        const client = new ApiClient({ baseUrl, token: 'test' });
        const result = await client.getJson<CreditBalanceResponse>('/credits/balance');
        expect(result.scanCredits).toBe(95);
        expect(result.attackerCredits).toBe(30);
        expect(result.scanCreditsExpiringSoon).toBe(10);
    });

    it('preserves credit error details on 402', async () => {
        const baseUrl = await startServer((req, res) => {
            res.statusCode = 402;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                error: 'Insufficient scan credits',
                code: 'INSUFFICIENT_CREDITS',
                creditType: 'scan',
                requested: 10,
                balance: 3,
            }));
        });

        const client = new ApiClient({ baseUrl, token: 'test' });
        try {
            await client.getJson('/credits/balance');
            expect.fail('should have thrown');
        } catch (err: any) {
            expect(err).toBeInstanceOf(ApiClientError);
            expect(err.status).toBe(402);
            expect(err.apiCode).toBe('INSUFFICIENT_CREDITS');
            expect(err.creditType).toBe('scan');
            expect(err.requested).toBe(10);
            expect(err.balance).toBe(3);
        }
    });

    it('preserves retryable flag on 503', async () => {
        const baseUrl = await startServer((req, res) => {
            res.statusCode = 503;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                error: 'Credit lock timeout',
                code: 'CREDIT_LOCK_TIMEOUT',
                retryable: true,
            }));
        });

        const client = new ApiClient({ baseUrl, token: 'test' });
        try {
            await client.getJson('/agent/scan/start');
            expect.fail('should have thrown');
        } catch (err: any) {
            expect(err).toBeInstanceOf(ApiClientError);
            expect(err.status).toBe(503);
            expect(err.apiCode).toBe('CREDIT_LOCK_TIMEOUT');
            expect(err.retryable).toBe(true);
        }
    });
});

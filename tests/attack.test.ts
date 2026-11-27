import { describe, it, expect } from 'vitest';
import { redactText, buildReport } from '../src/attack/report';

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

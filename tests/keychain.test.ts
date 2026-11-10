import { describe, it, expect } from 'vitest';
import { sanitizeKeychainError } from '../src/auth/keychain';

describe('sanitizeKeychainError', () => {
    const token = 'eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IngifQ.c2lnbmF0dXJl';

    it('never includes the token, even when the command output echoes it', () => {
        const err = { status: 1, message: `Command failed: powershell ... "${token}"`, stderr: `Parse error near "${token}"\nmore` };
        const msg = sanitizeKeychainError(err, token);
        expect(msg).not.toContain(token);
        expect(msg).toContain('keychain write failed (exit 1)');
    });

    it('ignores err.message (which carries the full command line) and masks any JWT-shaped text', () => {
        const err = { status: 2, message: `Command failed with ${token}`, stderr: 'boom eyJa.eyJb.sig' };
        const msg = sanitizeKeychainError(err, 'other');
        expect(msg).not.toContain(token);
        expect(msg).not.toContain('eyJa.eyJb.sig');
        expect(msg).toContain('***');
    });

    it('works without stderr', () => {
        expect(sanitizeKeychainError({ code: 'ENOENT' }, token)).toBe('keychain write failed (ENOENT)');
    });
});

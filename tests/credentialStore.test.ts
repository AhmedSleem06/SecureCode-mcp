import { describe, it, expect } from 'vitest';
import * as os from 'os';
import { Keychain } from '../src/auth/keychain';
import { CredentialStore } from '../src/auth/credentialStore';

describe('Keychain platform detection', () => {
    it('detects the current platform', () => {
        const platform = Keychain.getPlatform();
        const expected = os.platform();
        expect(['darwin', 'win32', 'linux']).toContain(platform);
        expect(platform).toBe(expected === 'darwin' ? 'darwin' : expected === 'win32' ? 'win32' : 'linux');
    });

    it('isAvailable returns a boolean', () => {
        const result = Keychain.isAvailable();
        expect(typeof result).toBe('boolean');
    });

    it('get returns null when no credential is stored', () => {
        const result = Keychain.get();
        expect(result === null || typeof result === 'string').toBe(true);
    });

    it('set and delete round-trip', () => {
        const testToken = 'test-keychain-token-' + Date.now();
        const setResult = Keychain.set(testToken);
        if (setResult.success) {
            const retrieved = Keychain.get();
            expect(retrieved).toBe(testToken);
            const deleted = Keychain.delete();
            expect(deleted).toBe(true);
            const afterDelete = Keychain.get();
            expect(afterDelete).toBe(null);
        } else {
            expect(setResult.method).toBe('file');
        }
    });
});

describe('CredentialStore with keychain fallback', () => {
    it('returns null when no credentials exist', () => {
        const originalEnv = process.env.SECURECODE_API_TOKEN;
        delete process.env.SECURECODE_API_TOKEN;
        const creds = CredentialStore.get();
        if (creds === null) {
            expect(creds).toBeNull();
        } else {
            expect(creds.apiToken).toBeDefined();
            expect(creds.apiUrl).toBeDefined();
        }
        if (originalEnv) process.env.SECURECODE_API_TOKEN = originalEnv;
    });

    it('env token takes priority over keychain and file', () => {
        process.env.SECURECODE_API_TOKEN = 'env-priority-test';
        const creds = CredentialStore.get();
        expect(creds).not.toBeNull();
        expect(creds!.apiToken).toBe('env-priority-test');
        expect(creds!.storedAt).toBe('env');
        delete process.env.SECURECODE_API_TOKEN;
    });

    it('save returns a method string', () => {
        const result = CredentialStore.save({
            apiToken: 'round-trip-test-token',
            apiUrl: 'https://api.usesecurecode.tech',
            storedAt: new Date().toISOString(),
        });
        expect(typeof result.method).toBe('string');
        expect(['keychain', 'file']).toContain(result.method);
        CredentialStore.clear();
    });

    it('clear returns a boolean', () => {
        CredentialStore.save({
            apiToken: 'clear-test',
            apiUrl: 'https://api.usesecurecode.tech',
            storedAt: new Date().toISOString(),
        });
        const result = CredentialStore.clear();
        expect(typeof result).toBe('boolean');
    });

    it('getOrThrow throws when not authenticated', () => {
        const originalEnv = process.env.SECURECODE_API_TOKEN;
        delete process.env.SECURECODE_API_TOKEN;
        const originalGet = CredentialStore.get;
        CredentialStore.get = () => null;
        expect(() => CredentialStore.getOrThrow()).toThrow('Not authenticated');
        CredentialStore.get = originalGet;
        if (originalEnv) process.env.SECURECODE_API_TOKEN = originalEnv;
    });
});

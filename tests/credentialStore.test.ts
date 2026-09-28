import { describe, it, expect, beforeAll } from 'vitest';
import * as os from 'os';
import * as fs from 'fs';
import * as path from 'path';

// Set BEFORE the modules under test are imported so they resolve their
// credential dir and keychain service against a throwaway sandbox. Without
// this, these tests round-tripped the developer's REAL keychain entry and
// credentials.json — clear() wiped real production tokens.
const credSandbox = path.join(os.tmpdir(), 'securecode-credstore-test-sandbox');
fs.rmSync(credSandbox, { recursive: true, force: true });
fs.mkdirSync(credSandbox, { recursive: true });
process.env.SECURECODE_CRED_DIR = credSandbox;
process.env.SECURECODE_KEYCHAIN_SERVICE = 'SecureCode-MCP-Test-Only';

let Keychain: typeof import('../src/auth/keychain').Keychain;
let CredentialStore: typeof import('../src/auth/credentialStore').CredentialStore;

beforeAll(async () => {
    ({ Keychain } = await import('../src/auth/keychain'));
    ({ CredentialStore } = await import('../src/auth/credentialStore'));
});

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
        expect(result === null || typeof result).toBe(true as any);
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
    it('writes the fallback file inside the sandbox dir', () => {
        const result = CredentialStore.save({
            apiToken: 'round-trip-test-token',
            apiUrl: 'https://api.usesecurecode.tech',
            storedAt: new Date().toISOString(),
        });
        expect(typeof result.method).toBe('string');
        expect(['keychain', 'file']).toContain(result.method);
        const expectedFile = path.join(credSandbox, 'credentials.json');
        expect(fs.existsSync(expectedFile)).toBe(true);
        CredentialStore.clear();
        expect(fs.existsSync(expectedFile)).toBe(false);
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

    it('env token takes priority over keychain and file', () => {
        process.env.SECURECODE_API_TOKEN = 'env-priority-test';
        const creds = CredentialStore.get();
        expect(creds).not.toBeNull();
        expect(creds!.apiToken).toBe('env-priority-test');
        expect(creds!.storedAt).toBe('env');
        delete process.env.SECURECODE_API_TOKEN;
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

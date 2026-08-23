import { describe, it, expect } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { looksLikeContractOnly, formatImplementationResolution } from '../src/project-map/implementationResolver';

describe('Implementation Resolver', () => {
    describe('looksLikeContractOnly', () => {
        it('returns true for an interface-only file', () => {
            const content = `
export interface ServerAuthShape {
    authenticate: (req: Request) => Effect<void, AuthError>;
    revokeSession: (sessionId: string) => Effect<void, AuthError>;
}
export type AuthError = { status: 401 | 403 | 500 };
`;
            expect(looksLikeContractOnly(content)).toBe(true);
        });

        it('returns true for a type-only file', () => {
            const content = `
export type Session = { id: string; userId: string };
export type Credential = { token: string; expiresAt: number };
export interface SessionManager { verify: (token: string) => Effect<Session, Error> };
`;
            expect(looksLikeContractOnly(content)).toBe(true);
        });

        it('returns true for an Effect service declaration without implementation', () => {
            const content = `
export class ServerAuth extends Service.Service<ServerAuth>()("synara/auth/ServerAuth", {
    accessors: {},
    succeed: {} as ServerAuthShape,
}) {}
`;
            expect(looksLikeContractOnly(content)).toBe(true);
        });

        it('returns false for a file with runtime implementations', () => {
            const content = `
export const makeServerAuth = Effect.gen(function* () {
    const session = yield* SessionCredentialService;
    return { authenticate: (req) => Effect.gen(function* () { ... }) };
});
export const ServerAuthLive = Layer.effect(ServerAuth, makeServerAuth);
`;
            expect(looksLikeContractOnly(content)).toBe(false);
        });

        it('returns false for a file with functions', () => {
            const content = `
export function handler(req, res) { res.json({ ok: true }); }
export async function authenticate(token) { return true; }
`;
            expect(looksLikeContractOnly(content)).toBe(false);
        });

        it('returns false for an empty file', () => {
            expect(looksLikeContractOnly('')).toBe(false);
        });

        it('returns false for a file with mixed types and functions', () => {
            const content = `
export interface Config { port: number }
export function loadConfig(): Config { return { port: 3000 }; }
`;
            expect(looksLikeContractOnly(content)).toBe(false);
        });
    });

    describe('formatImplementationResolution', () => {
        it('formats unresolved resolution', () => {
            const result = formatImplementationResolution({
                contractLocations: [],
                implementationLocations: [],
                callSites: [],
                unresolved: true,
                description: 'No implementations found',
            });
            expect(result).toContain('No implementations found');
            expect(result).toContain('Consider:');
        });

        it('formats resolved implementation', () => {
            const result = formatImplementationResolution({
                contractLocations: [{ filePath: 'src/auth.ts', line: 10, symbol: 'ServerAuth' }],
                implementationLocations: [{ filePath: 'src/auth/Layers/ServerAuth.ts', line: 54, symbol: 'makeServerAuth' }],
                callSites: [{ filePath: 'src/http.ts', line: 30 }],
                unresolved: false,
                description: 'Found 1 implementation',
            });
            expect(result).toContain('Implementation resolution');
            expect(result).toContain('src/auth/Layers/ServerAuth.ts:54');
            expect(result).toContain('Call sites');
            expect(result).toContain('src/http.ts:30');
        });

        it('truncates call sites to 10', () => {
            const callSites = Array.from({ length: 15 }, (_, i) => ({ filePath: `f${i}.ts`, line: i + 1 }));
            const result = formatImplementationResolution({
                contractLocations: [],
                implementationLocations: [{ filePath: 'impl.ts', line: 1 }],
                callSites,
                unresolved: false,
                description: '',
            });
            expect(result).toContain('... and 5 more');
        });
    });
});

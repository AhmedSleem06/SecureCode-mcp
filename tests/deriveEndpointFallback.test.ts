// Unit tests for deriveEndpointFallback — the framework fallback that
// derives probe endpoint candidates when the deterministic project map
// has no endpoints for the finding's file (Effect-TS, NestJS, Hono, Koa).

import { describe, it, expect } from 'vitest';
import {
    deriveEndpointFallback,
    isProbeEligibleType,
    hasProbeEligibleReason,
} from '../src/attack/runtimeProbe';

describe('deriveEndpointFallback', () => {
    it('derives an Effect-TS HttpApiEndpoint candidate from the code window', () => {
        const code = [
            "import { HttpApiEndpoint } from '@effect/platform';",
            '',
            "export const bootstrapApi = HttpApiEndpoint.post('bootstrap', () => {",
            '  // token exchange logic',
            '});',
            '',
            '// finding is on this line',
        ].join('\n');
        const candidate = deriveEndpointFallback(
            { line: 6, type: 'broken_access_control' } as any,
            code,
        );
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('POST');
        expect(candidate!.path).toBe('/bootstrap');
        expect(candidate!.line).toBe(3);
        expect((candidate as any).derived).toBe(true);
    });

    it('derives an Effect HttpRouter candidate with a leading slash preserved', () => {
        const code = [
            "// header comment",
            "export const router = HttpRouter.get('/health', handler)",
            'const vulnerable = req.body.id; // finding here',
        ].join('\n');
        const candidate = deriveEndpointFallback({ line: 3 } as any, code);
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('GET');
        expect(candidate!.path).toBe('/health');
    });

    it('derives a NestJS decorator candidate', () => {
        const code = [
            "@Controller('users')",
            'export class UsersController {',
            "  @Put(':id/admin')",
            '  promote(@Param() params) { /* finding line */ }',
            '}',
        ].join('\n');
        const candidate = deriveEndpointFallback({ line: 4 } as any, code);
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('PUT');
        expect(candidate!.path).toBe('/:id/admin');
    });

    it('derives an Express/Hono candidate as a safety net', () => {
        const code = [
            'const app = new Hono()',
            "app.post('/api/tokens', exchange)",
            'const session = authorize(token) // finding',
        ].join('\n');
        const candidate = deriveEndpointFallback({ line: 3 } as any, code);
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('POST');
        expect(candidate!.path).toBe('/api/tokens');
    });

    it('prefers the route nearest the finding within the ±25/+200 window', () => {
        const lines: string[] = [];
        lines[0] = "app.get('/far-away', handler)";
        for (let i = 1; i < 40; i++) lines[i] = `const filler${i} = ${i};`;
        lines[20] = "router.post('/near', handler)";
        const code = lines.join('\n');
        const candidate = deriveEndpointFallback({ line: 30 } as any, code);
        // far-away route is > 25 lines before the finding and its +200 window
        // does not reach backward — only the near route qualifies
        expect(candidate).not.toBeNull();
        expect(candidate!.path).toBe('/near');
    });

    it('falls back to evidence mining when the code has no route pattern', () => {
        const candidate = deriveEndpointFallback({
            line: 10,
            evidence: 'The POST /mcp/bootstrap endpoint exchanges a bootstrap token with no ownership check',
        } as any, 'no routes here');
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('POST');
        expect(candidate!.path).toBe('/mcp/bootstrap');
        expect(candidate!.line).toBe(10);
    });

    it('returns null when neither the code window nor evidence has a route', () => {
        const candidate = deriveEndpointFallback(
            { line: 1, evidence: 'some vague evidence' } as any,
            'const x = 1;',
        );
        expect(candidate).toBeNull();
    });

    it('normalizes segment paths to a leading slash', () => {
        const code = [
            "export const api = HttpApiEndpoint.get('users', handler)",
        ].join('\n');
        const candidate = deriveEndpointFallback({ line: 1 } as any, code);
        expect(candidate!.path).toBe('/users');
    });

    it('derives a multi-line HttpRouter.add registration below the finding', () => {
        const lines: string[] = [];
        for (let i = 1; i <= 120; i++) lines[i] = `const filler${i} = ${i};`;
        lines[30] = 'function isLegacyTokenAuthorized(config) { return !config.authToken; }';
        lines[100] = 'export const threadExportEffectRouteLayer = HttpRouter.add(';
        lines[101] = '  "GET",';
        lines[102] = '  "/api/thread-export",';
        lines[103] = '  Effect.gen(function* () {';
        const code = lines.map((l, i) => l ?? '').join('\n');
        const candidate = deriveEndpointFallback({ line: 30 } as any, code);
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('GET');
        expect(candidate!.path).toBe('/api/thread-export');
    });

    it('prefers the concrete registration over a nearer wildcard auth layer', () => {
        const lines: string[] = [];
        for (let i = 1; i <= 400; i++) lines[i] = `const filler${i} = ${i};`;
        lines[30] = 'function isLegacyTokenAuthorized(config) { return !config.authToken; }';
        lines[97] = 'export const authEffectRouteLayer = HttpRouter.add(';
        lines[98] = '  "*",';
        lines[99] = '  "/api/auth/*",';
        lines[100] = '  Effect.gen(function* () {';
        lines[270] = 'const threadExportEffectRouteLayer = HttpRouter.add(';
        lines[271] = '  "GET",';
        lines[272] = '  "/api/thread-export",';
        lines[273] = '  Effect.gen(function* () {';
        const code = lines.map((l, i) => l ?? '').join('\n');
        const candidate = deriveEndpointFallback({ line: 30 } as any, code);
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('GET');
        expect(candidate!.path).toBe('/api/thread-export');
    });

    it('boosts the registration the finding evidence names over nearer concrete routes', () => {
        const lines: string[] = [];
        for (let i = 1; i <= 400; i++) lines[i] = `const filler${i} = ${i};`;
        lines[30] = 'function isLegacyTokenAuthorized(config) { return !config.authToken; }';
        lines[200] = 'const projectFaviconEffectRouteLayer = HttpRouter.add(';
        lines[201] = '  "GET",';
        lines[202] = '  "/api/project-favicon",';
        lines[203] = '  Effect.gen(function* () {';
        lines[370] = 'const threadExportEffectRouteLayer = HttpRouter.add(';
        lines[371] = '  "GET",';
        lines[372] = '  "/api/thread-export",';
        lines[373] = '  Effect.gen(function* () {';
        const code = lines.map((l, i) => l ?? '').join('\n');
        const candidate = deriveEndpointFallback({
            line: 30,
            evidence: 'The bypass exposes GET /api/thread-export to unauthenticated loopback requests',
        } as any, code);
        expect(candidate).not.toBeNull();
        expect(candidate!.path).toBe('/api/thread-export');
    });

    it('prefers the auth-protected route over a nearer unprotected route', () => {
        const lines: string[] = [];
        for (let i = 1; i <= 400; i++) lines[i] = `const filler${i} = ${i};`;
        lines[30] = 'function isLegacyTokenAuthorized(config) { return !config.authToken; }';
        lines[100] = 'const projectFaviconEffectRouteLayer = HttpRouter.add(';
        lines[101] = '  "GET",';
        lines[102] = '  "/api/project-favicon",';
        lines[103] = '  Effect.gen(function* () {';
        lines[104] = '    yield* Effect.succeed(faviconBytes);';
        lines[105] = '  })';
        lines[270] = 'const threadExportEffectRouteLayer = HttpRouter.add(';
        lines[271] = '  "GET",';
        lines[272] = '  "/api/thread-export",';
        lines[273] = '  Effect.gen(function* () {';
        lines[274] = '    const session = yield* requireAuthenticated;';
        lines[275] = '    if (!isLegacyTokenAuthorized(config)) {';
        lines[276] = '      yield* Effect.fail(new AccessDeniedError());';
        lines[277] = '    }';
        lines[278] = '  })';
        const code = lines.map((l, i) => l ?? '').join('\n');
        const candidate = deriveEndpointFallback({ line: 30 } as any, code);
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('GET');
        expect(candidate!.path).toBe('/api/thread-export');
        expect(candidate!.line).toBe(271);
    });

    it('falls back to a wildcard registration with GET method when nothing concrete exists', () => {
        const code = [
            'function isLegacyTokenAuthorized(config) { return !config.authToken; }',
            '',
            'export const authEffectRouteLayer = HttpRouter.add(',
            '  "*",',
            '  "/api/auth/*",',
            '  Effect.gen(function* () {',
        ].join('\n');
        const candidate = deriveEndpointFallback({ line: 1 } as any, code);
        expect(candidate).not.toBeNull();
        expect(candidate!.method).toBe('GET');
        expect(candidate!.path).toBe('/api/auth/*');
    });
});

describe('probe eligibility helpers', () => {
    it('isProbeEligibleType matches the HTTP-routable types only', () => {
        expect(isProbeEligibleType('broken_access_control')).toBe(true);
        expect(isProbeEligibleType('sql_injection')).toBe(true);
        expect(isProbeEligibleType('missing_rate_limiting')).toBe(false);
        expect(isProbeEligibleType('hardcoded_secret')).toBe(false);
    });

    it('hasProbeEligibleReason matches runtime-shaped verify reasons', () => {
        expect(hasProbeEligibleReason('Effect-TS module with full runtime dependencies cannot be imported in sandbox — 10 timeouts confirm')).toBe(true);
        expect(hasProbeEligibleReason('Test timed out after 12 rounds')).toBe(true);
        expect(hasProbeEligibleReason('Guard checks out; input sanitized')).toBe(false);
    });

    it('hasProbeEligibleReason matches baseline-failed proof-gate shapes', () => {
        expect(hasProbeEligibleReason('Proof gate rejected: baseline-failed. Baseline secure case did not pass — cannot distinguish exploit from normal behavior')).toBe(true);
        expect(hasProbeEligibleReason('baseline failed: the secure request also succeeded, cannot distinguish')).toBe(true);
        expect(hasProbeEligibleReason('INCONCLUSIVE: cannot distinguish exploit from normal behavior')).toBe(true);
        expect(hasProbeEligibleReason('Guard checks out; input sanitized')).toBe(false);
    });
});

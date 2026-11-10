import { describe, it, expect } from 'vitest';
import {
    selectInvestigationProfile,
    HTTP_ROUTE_PROFILE,
    WEBSOCKET_RPC_PROFILE,
    AUTH_SERVICE_PROFILE,
    GENERIC_UTILITY_PROFILE,
    DECLARATION_PROFILE,
    extractRoleFromArchitectureContext,
} from '../src/attack/investigationProfiles';

describe('selectInvestigationProfile', () => {
    it('selects WebSocket RPC profile for wsRpc.ts', () => {
        const profile = selectInvestigationProfile({ filePath: 'apps/server/src/wsRpc.ts' });
        expect(profile.name).toBe('websocket-rpc');
        expect(profile.requiredSteps).toContain('initial-read');
        expect(profile.requiredSteps).toContain('ownership-analysis');
    });

    it('selects WebSocket RPC profile for socket.io handler', () => {
        const profile = selectInvestigationProfile({
            filePath: 'src/handler.ts',
            architectureContext: 'src/handler.ts uses WebSocket and socket.io for real-time communication',
        });
        expect(profile.name).toBe('websocket-rpc');
    });

    it('ignores project-wide architecture text that does not mention the target', () => {
        const profile = selectInvestigationProfile({
            filePath: 'src/billing/invoice.ts',
            architectureContext: 'Project uses WebSocket and socket.io for real-time communication\nsrc/ws/server.ts — RPC methods',
        });
        expect(profile.name).not.toBe('websocket-rpc');
    });

    it('selects Auth Service profile for auth file', () => {
        const profile = selectInvestigationProfile({ filePath: 'src/auth/ServerAuth.ts' });
        expect(profile.name).toBe('auth-service');
        expect(profile.requiredSteps).toContain('tests-found');
    });

    it('selects Auth Service profile for token file', () => {
        const profile = selectInvestigationProfile({ filePath: 'src/tokenManager.ts' });
        expect(profile.name).toBe('auth-service');
    });

    it('selects HTTP Route profile for route handler', () => {
        const profile = selectInvestigationProfile({
            filePath: 'apps/server/src/http.ts',
            architectureContext: 'Express routes defined in http.ts',
        });
        expect(profile.name).toBe('http-route');
        expect(profile.requiredSteps).toContain('route-discovery');
        expect(profile.requiredSteps).toContain('policy-check');
    });

    it('selects HTTP Route profile for controller file', () => {
        const profile = selectInvestigationProfile({ filePath: 'src/controllers/userController.ts' });
        expect(profile.name).toBe('http-route');
    });

    it('selects HTTP Route profile when endpoint context references the file', () => {
        const profile = selectInvestigationProfile({
            filePath: 'src/handler.ts',
            endpointContext: 'GET /api/users → src/handler.ts:42',
        });
        expect(profile.name).toBe('http-route');
    });

    it('selects HTTP Route profile when endpoint context is an ARRAY (the real wire shape)', () => {
        // Regression: agentScanLoop passes target.endpointContext as
        // EndpointContext[]; the old string-only handling silently
        // discarded it and never matched the file.
        const profile = selectInvestigationProfile({
            filePath: 'src/handler.ts',
            endpointContext: [
                {
                    method: 'GET',
                    path: '/api/users',
                    handlerName: 'getUsers',
                    sourceFile: 'src/handler.ts',
                    line: 42,
                },
                {
                    method: 'POST',
                    path: '/api/orders',
                    handlerName: 'createOrder',
                    sourceFile: 'src/orders.ts',
                    line: 10,
                },
            ] as any,
        });
        expect(profile.name).toBe('http-route');
    });

    it('does not select HTTP Route profile when the array does not reference the file', () => {
        const profile = selectInvestigationProfile({
            filePath: 'src/lib/formatDate.ts',
            endpointContext: [
                { method: 'GET', path: '/api/users', handlerName: 'getUsers', sourceFile: 'src/handler.ts', line: 42 },
            ] as any,
        });
        expect(profile.name).toBe('generic-utility');
    });

    it('selects Generic Utility profile for unrelated file', () => {
        const profile = selectInvestigationProfile({ filePath: 'src/utils/formatDate.ts' });
        expect(profile.name).toBe('generic-utility');
        expect(profile.requiredSteps).toContain('initial-read');
        expect(profile.requiredSteps).not.toContain('route-discovery');
    });

    it('does not require route-discovery for generic utility', () => {
        const profile = selectInvestigationProfile({ filePath: 'src/lib/helper.ts' });
        expect(profile.requiredSteps).not.toContain('route-discovery');
        expect(profile.requiredSteps).not.toContain('policy-check');
    });

    it('all profiles include candidates-verified', () => {
        expect(HTTP_ROUTE_PROFILE.requiredSteps).toContain('candidates-verified');
        expect(WEBSOCKET_RPC_PROFILE.requiredSteps).toContain('candidates-verified');
        expect(AUTH_SERVICE_PROFILE.requiredSteps).toContain('candidates-verified');
        expect(GENERIC_UTILITY_PROFILE.requiredSteps).toContain('candidates-verified');
    });

    it('all profiles include initial-read', () => {
        expect(HTTP_ROUTE_PROFILE.requiredSteps).toContain('initial-read');
        expect(WEBSOCKET_RPC_PROFILE.requiredSteps).toContain('initial-read');
        expect(AUTH_SERVICE_PROFILE.requiredSteps).toContain('initial-read');
        expect(GENERIC_UTILITY_PROFILE.requiredSteps).toContain('initial-read');
    });

    it('all profiles define evidence requirements', () => {
        expect(HTTP_ROUTE_PROFILE.requirements.length).toBeGreaterThan(0);
        expect(WEBSOCKET_RPC_PROFILE.requirements.length).toBeGreaterThan(0);
        expect(AUTH_SERVICE_PROFILE.requirements.length).toBeGreaterThan(0);
        expect(GENERIC_UTILITY_PROFILE.requirements.length).toBeGreaterThan(0);
    });

    it('each profile has a source-range initial-read requirement', () => {
        const allProfiles = [HTTP_ROUTE_PROFILE, WEBSOCKET_RPC_PROFILE, AUTH_SERVICE_PROFILE, GENERIC_UTILITY_PROFILE];
        for (const profile of allProfiles) {
            const hasInitialRead = profile.requirements.some(r => r.acceptedKinds.includes('source-range'));
            expect(hasInitialRead).toBe(true);
        }
    });

    it('http route profile requires route discovery and policy check evidence', () => {
        const hasRouteDiscovery = HTTP_ROUTE_PROFILE.requirements.some(r => r.acceptedKinds.includes('handler-inventory'));
        const hasPolicyCheck = HTTP_ROUTE_PROFILE.requirements.some(r => r.acceptedKinds.includes('policy-result'));
        expect(hasRouteDiscovery).toBe(true);
        expect(hasPolicyCheck).toBe(true);
    });

    it('generic utility does not require route discovery or policy check', () => {
        const hasRouteDiscovery = GENERIC_UTILITY_PROFILE.requirements.some(r => r.acceptedKinds.includes('handler-inventory'));
        const hasPolicyCheck = GENERIC_UTILITY_PROFILE.requirements.some(r => r.acceptedKinds.includes('policy-result'));
        expect(hasRouteDiscovery).toBe(false);
        expect(hasPolicyCheck).toBe(false);
    });
});

describe('selectInvestigationProfile — file shape, role and word boundaries', () => {
    const typesOnly = `import { ServiceMap } from "effect";
export interface ServerAuthShape { readonly authenticate: (token: string) => boolean }
export class ServerAuth extends ServiceMap.Service<ServerAuth, ServerAuthShape>()("t3/auth/Services/ServerAuth") {}
`;

    it('selects the declaration profile for a types-only file before any path heuristic', () => {
        const profile = selectInvestigationProfile({
            filePath: 'apps/server/src/auth/Services/ServerAuth.ts',
            fileContent: typesOnly,
            role: 'authentication Issues session tokens',
        });
        expect(profile.name).toBe('declaration');
        expect(profile).toBe(DECLARATION_PROFILE);
    });

    it('declaration profile requires only an initial read and an implementation search', () => {
        expect(DECLARATION_PROFILE.requirements.map(r => r.id)).toEqual(['decl-initial-read', 'decl-find-implementation']);
        const find = DECLARATION_PROFILE.requirements[1];
        expect(find.requiredTools).toEqual(['search_code', 'find_references']);
        expect(find.acceptsNegative).toBe(true);
    });

    it('does not pick the declaration profile for a file with implementation', () => {
        const profile = selectInvestigationProfile({
            filePath: 'src/utils/format.ts',
            fileContent: 'export function format(x: string) { return x.trim(); }',
        });
        expect(profile.name).toBe('generic-utility');
    });

    it('role keywords win over path heuristics', () => {
        expect(selectInvestigationProfile({ filePath: 'src/wsRpc.ts', role: 'route_handler REST endpoints' }).name).toBe('http-route');
        expect(selectInvestigationProfile({ filePath: 'src/lib/thing.ts', role: 'middleware' }).name).toBe('http-route');
        expect(selectInvestigationProfile({ filePath: 'src/lib/thing.ts', role: 'service Handles WebSocket RPC calls' }).name).toBe('websocket-rpc');
        expect(selectInvestigationProfile({ filePath: 'src/lib/thing.ts', role: 'service auth service for session tokens' }).name).toBe('auth-service');
        expect(selectInvestigationProfile({ filePath: 'src/lib/thing.ts', role: 'service token issuance' }).name).toBe('auth-service');
        expect(selectInvestigationProfile({ filePath: 'src/lib/thing.ts', role: 'model shared types and interfaces' }).name).toBe('declaration');
    });

    it('a role that matches nothing falls through to path heuristics', () => {
        expect(selectInvestigationProfile({ filePath: 'src/wsRpc.ts', role: 'shared_helper formatting' }).name).toBe('websocket-rpc');
    });

    it('extracts the role from the formatted architecture context', () => {
        const arch = [
            'Important files (2, ranked by security importance):',
            '  [95] apps/server/src/auth/Layers/ServerAuth.ts (authentication) — Issues session tokens; validates bearer',
            '  [80] apps/server/src/http.ts (route_handler) — HTTP routes',
        ].join('\n');
        expect(extractRoleFromArchitectureContext(arch, 'apps/server/src/http.ts')).toBe('route_handler HTTP routes');
        expect(extractRoleFromArchitectureContext(arch, 'apps/server/src/auth/Layers/ServerAuth.ts')).toBe('authentication Issues session tokens; validates bearer');
        expect(extractRoleFromArchitectureContext(arch, 'apps/server/src/other.ts')).toBeUndefined();
    });

    it('uses word boundaries for websocket path tokens (views.ts / news.ts are not websocket)', () => {
        expect(selectInvestigationProfile({ filePath: 'src/views.ts' }).name).toBe('generic-utility');
        expect(selectInvestigationProfile({ filePath: 'src/news/feed.ts' }).name).toBe('generic-utility');
        expect(selectInvestigationProfile({ filePath: 'src/lib/rpcs.ts' }).name).toBe('generic-utility');
        expect(selectInvestigationProfile({ filePath: 'src/ws/server.ts' }).name).toBe('websocket-rpc');
        expect(selectInvestigationProfile({ filePath: 'src/websocketServer.ts' }).name).toBe('websocket-rpc');
    });

    it('uses word boundaries for auth path tokens', () => {
        expect(selectInvestigationProfile({ filePath: 'src/author/profile.ts' }).name).toBe('generic-utility');
        expect(selectInvestigationProfile({ filePath: 'src/lib/tokenizer.ts' }).name).toBe('generic-utility');
        expect(selectInvestigationProfile({ filePath: 'src/authMiddleware.ts' }).name).toBe('auth-service');
        expect(selectInvestigationProfile({ filePath: 'src/session_store.ts' }).name).toBe('auth-service');
    });

    it('all-handlers requirements are satisfiable by an empty inventory', () => {
        for (const profile of [HTTP_ROUTE_PROFILE, WEBSOCKET_RPC_PROFILE, AUTH_SERVICE_PROFILE]) {
            const allHandlers = profile.requirements.find(r => r.id.endsWith('-all-handlers'));
            expect(allHandlers?.satisfiedByEmptyInventory).toBe(true);
        }
    });
});

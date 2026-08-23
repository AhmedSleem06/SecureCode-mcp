import { describe, it, expect } from 'vitest';
import {
    selectInvestigationProfile,
    HTTP_ROUTE_PROFILE,
    WEBSOCKET_RPC_PROFILE,
    AUTH_SERVICE_PROFILE,
    GENERIC_UTILITY_PROFILE,
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
            architectureContext: 'Uses WebSocket and socket.io for real-time communication',
        });
        expect(profile.name).toBe('websocket-rpc');
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
});

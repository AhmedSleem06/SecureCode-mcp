/**
 * Target-specific investigation profiles.
 *
 * Different file types require different investigation steps. An HTTP route
 * handler needs route discovery and policy checks; a utility function needs
 * caller inventory and security-sensitive branch review. Using the wrong
 * checklist wastes steps on irrelevant tools (e.g., get_endpoints on a
 * file with no routes) and misses required steps for the actual target type.
 */

import type { InvestigationStep } from './investigationState';
import type { EvidenceRequirement } from './evidenceLedger';

export interface InvestigationProfile {
    name: string;
    requiredSteps: InvestigationStep[];
    description: string;
    requirements: EvidenceRequirement[];
}

export const HTTP_ROUTE_PROFILE: InvestigationProfile = {
    name: 'http-route',
    requiredSteps: [
        'initial-read',
        'route-discovery',
        'policy-check',
        'auth-symbol-search',
        'cross-file-flow',
        'config-inspection',
        'all-handlers-reviewed',
        'candidates-verified',
    ],
    description: 'HTTP route handler — requires route discovery, policy check, auth search, cross-file flow, config inspection, authorization analysis, and all-handlers-reviewed.',
    requirements: [
        { id: 'http-initial-read', description: 'Read the target file source', acceptedKinds: ['source-range'], requiredTools: ['read_file'], minimumCount: 1 },
        { id: 'http-route-discovery', description: 'Discover routes/endpoints', acceptedKinds: ['handler-inventory'], requiredTools: ['get_endpoints'], minimumCount: 1 },
        { id: 'http-policy-check', description: 'Check policy on route handlers', acceptedKinds: ['policy-result'], requiredTools: ['check_policy'], minimumCount: 1 },
        { id: 'http-auth-search', description: 'Find authentication symbols', acceptedKinds: ['symbol-definition', 'symbol-reference'], requiredTools: ['search_code'], minimumCount: 1 },
        { id: 'http-cross-file-flow', description: 'Trace cross-file data flow', acceptedKinds: ['cross-file-flow'], requiredTools: ['trace_flow_cross_file', 'trace_flow'], minimumCount: 1 },
        { id: 'http-config-inspection', description: 'Inspect security configuration', acceptedKinds: ['config-result'], requiredTools: ['read_config'], minimumCount: 1, acceptsNegative: true },
        { id: 'http-all-handlers', description: 'Review all discovered handlers', acceptedKinds: ['handler-inventory'], minimumCount: 2 },
        { id: 'http-authz-check', description: 'Verify authorization on authenticated vs unauthenticated paths', acceptedKinds: ['policy-result', 'guard-result'], requiredTools: ['check_policy', 'check_guard'], minimumCount: 1, acceptsNegative: true },
        { id: 'http-csrf-check', description: 'Verify CSRF/origin checks on mutation endpoints', acceptedKinds: ['guard-result', 'policy-result'], requiredTools: ['check_guard', 'check_policy'], minimumCount: 1, acceptsNegative: true },
    ],
};

export const WEBSOCKET_RPC_PROFILE: InvestigationProfile = {
    name: 'websocket-rpc',
    requiredSteps: [
        'initial-read',
        'route-discovery',
        'auth-symbol-search',
        'ownership-analysis',
        'cross-file-flow',
        'config-inspection',
        'all-handlers-reviewed',
        'candidates-verified',
    ],
    description: 'WebSocket RPC handler — requires method inventory, connection auth, per-method authorization, ownership analysis, command execution tracing, and rate-limit check.',
    requirements: [
        { id: 'ws-initial-read', description: 'Read the target file source', acceptedKinds: ['source-range'], requiredTools: ['read_file'], minimumCount: 1 },
        { id: 'ws-method-inventory', description: 'Inventory RPC methods', acceptedKinds: ['handler-inventory'], requiredTools: ['get_endpoints', 'search_code'], minimumCount: 1 },
        { id: 'ws-auth-search', description: 'Find authentication symbols', acceptedKinds: ['symbol-definition', 'symbol-reference'], requiredTools: ['search_code'], minimumCount: 1 },
        { id: 'ws-ownership-analysis', description: 'Trace ownership for resource methods', acceptedKinds: ['cross-file-flow', 'symbol-reference'], requiredTools: ['trace_flow_cross_file', 'search_code'], minimumCount: 1 },
        { id: 'ws-cross-file-flow', description: 'Trace cross-file data flow', acceptedKinds: ['cross-file-flow'], requiredTools: ['trace_flow_cross_file'], minimumCount: 1 },
        { id: 'ws-config-inspection', description: 'Inspect security configuration', acceptedKinds: ['config-result'], requiredTools: ['read_config'], minimumCount: 1, acceptsNegative: true },
        { id: 'ws-all-handlers', description: 'Review all RPC methods', acceptedKinds: ['handler-inventory'], minimumCount: 2 },
        { id: 'ws-per-method-authz', description: 'Verify per-method authorization (owner vs client roles)', acceptedKinds: ['guard-result', 'policy-result'], requiredTools: ['check_guard', 'check_policy'], minimumCount: 1, acceptsNegative: true },
        { id: 'ws-cmd-execution', description: 'Trace command execution paths (execFile, spawn, child_process)', acceptedKinds: ['cross-file-flow', 'source-range'], requiredTools: ['trace_flow_cross_file', 'trace_flow'], minimumCount: 1, acceptsNegative: true },
    ],
};

export const AUTH_SERVICE_PROFILE: InvestigationProfile = {
    name: 'auth-service',
    requiredSteps: [
        'initial-read',
        'auth-symbol-search',
        'cross-file-flow',
        'config-inspection',
        'tests-found',
        'all-handlers-reviewed',
        'candidates-verified',
    ],
    description: 'Authentication service — requires caller inventory, token issue/verify, role analysis, credential lifecycle, session revocation, bootstrap token handling, config inspection, and tests.',
    requirements: [
        { id: 'auth-initial-read', description: 'Read the target file source', acceptedKinds: ['source-range'], requiredTools: ['read_file'], minimumCount: 1 },
        { id: 'auth-symbol-search', description: 'Find auth function definitions', acceptedKinds: ['symbol-definition', 'symbol-reference'], requiredTools: ['search_code'], minimumCount: 1 },
        { id: 'auth-cross-file-flow', description: 'Trace credential flow across files', acceptedKinds: ['cross-file-flow'], requiredTools: ['trace_flow_cross_file'], minimumCount: 1 },
        { id: 'auth-config-inspection', description: 'Inspect auth configuration', acceptedKinds: ['config-result'], requiredTools: ['read_config'], minimumCount: 1, acceptsNegative: true },
        { id: 'auth-tests-found', description: 'Find tests for auth code', acceptedKinds: ['test-location'], requiredTools: ['find_tests'], minimumCount: 1, acceptsNegative: true },
        { id: 'auth-all-handlers', description: 'Review all auth operations', acceptedKinds: ['handler-inventory'], minimumCount: 1 },
        { id: 'auth-credential-lifecycle', description: 'Verify credential lifecycle (issue, verify, revoke, expire)', acceptedKinds: ['guard-result', 'cross-file-flow'], requiredTools: ['check_guard', 'trace_flow_cross_file'], minimumCount: 1, acceptsNegative: true },
        { id: 'auth-bootstrap-token', description: 'Verify bootstrap/pairing token handling', acceptedKinds: ['guard-result', 'policy-result'], requiredTools: ['check_guard', 'check_policy'], minimumCount: 1, acceptsNegative: true },
    ],
};

export const GENERIC_UTILITY_PROFILE: InvestigationProfile = {
    name: 'generic-utility',
    requiredSteps: [
        'initial-read',
        'cross-file-flow',
        'tests-found',
        'candidates-verified',
    ],
    description: 'Generic utility — requires initial read, caller inventory, security-sensitive branch review, tests, and verification.',
    requirements: [
        { id: 'util-initial-read', description: 'Read the target file source', acceptedKinds: ['source-range'], requiredTools: ['read_file'], minimumCount: 1 },
        { id: 'util-cross-file-flow', description: 'Trace data flow to sensitive sinks', acceptedKinds: ['cross-file-flow'], requiredTools: ['trace_flow_cross_file', 'trace_flow'], minimumCount: 1, acceptsNegative: true },
        { id: 'util-tests-found', description: 'Find tests for the utility', acceptedKinds: ['test-location'], requiredTools: ['find_tests'], minimumCount: 1, acceptsNegative: true },
    ],
};

export interface ProfileSelectionInput {
    filePath: string;
    architectureContext?: string;
    endpointContext?: string;
}

/**
 * Select an investigation profile based on the target file path and context.
 *
 * Heuristics:
 *   - File path contains "ws", "websocket", "rpc", "socket" → WebSocket RPC
 *   - File path contains "auth", "login", "token", "session", "credential" → Auth Service
 *   - Architecture context mentions "endpoint", "route", "handler", "express", "fastify" → HTTP Route
 *   - Otherwise → Generic Utility
 */
export function selectInvestigationProfile(input: ProfileSelectionInput): InvestigationProfile {
    const filePathLower = (input.filePath || '').toLowerCase();
    const archContextRaw = input.architectureContext;
    const archContext = (typeof archContextRaw === 'string' ? archContextRaw : '').toLowerCase();
    const endpointContextRaw = input.endpointContext;
    const endpointContext = (typeof endpointContextRaw === 'string' ? endpointContextRaw : '').toLowerCase();

    // WebSocket RPC detection
    if (/(ws|websocket|rpc|socket|wss)/i.test(filePathLower) ||
        /websocket|rpc\s+method|socket\.io/i.test(archContext)) {
        return WEBSOCKET_RPC_PROFILE;
    }

    // Authentication service detection
    if (/(auth|login|token|session|credential|password|jwt|oauth)/i.test(filePathLower) ||
        /auth.*service|token.*issue|credential.*lifecycle/i.test(archContext)) {
        return AUTH_SERVICE_PROFILE;
    }

    // HTTP route detection — check if the file is referenced in endpoint context
    // or the architecture context mentions routes/endpoints
    if (endpointContext.includes(input.filePath.toLowerCase()) ||
        /\b(endpoint|route|handler|express|fastify|router|app\.(get|post|put|delete|patch))\b/i.test(archContext) ||
        /\b(route|controller|handler|middleware)s?\b/i.test(filePathLower)) {
        return HTTP_ROUTE_PROFILE;
    }

    // Default: generic utility
    return GENERIC_UTILITY_PROFILE;
}

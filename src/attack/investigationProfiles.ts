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

export interface InvestigationProfile {
    name: string;
    requiredSteps: InvestigationStep[];
    description: string;
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
    description: 'HTTP route handler — requires route discovery, policy check, auth search, cross-file flow, config inspection, and all-handlers-reviewed.',
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
    description: 'WebSocket RPC handler — requires method inventory, connection auth, method authorization, ownership analysis, dangerous capability tracing, and rate-limit check.',
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
    description: 'Authentication service — requires caller inventory, token issue/verify, role transition analysis, credential lifecycle, config inspection, and tests.',
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

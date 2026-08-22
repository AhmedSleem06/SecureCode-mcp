import type { OperationCategory } from '../approval/types';

export interface ToolPolicy {
    name: string;
    category: OperationCategory;
    requiresApproval: boolean;
    approvalNote?: string;
}

export const TOOL_POLICIES: Record<string, ToolPolicy> = {
    'securecode.scan': {
        name: 'securecode.scan',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.map': {
        name: 'securecode.map',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.scan-dependencies': {
        name: 'securecode.scan-dependencies',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.scan-batch': {
        name: 'securecode.scan-batch',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.scan-secrets': {
        name: 'securecode.scan-secrets',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.agent-scan': {
        name: 'securecode.agent-scan',
        category: 'read-only',
        requiresApproval: false,
        approvalNote: 'Agent scan investigation is read-only. Fix generation within agent-scan requires its own approval prompt.',
    },
    'securecode.record-false-positive': {
        name: 'securecode.record-false-positive',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.get-agent-memory': {
        name: 'securecode.get-agent-memory',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.clear-agent-memory': {
        name: 'securecode.clear-agent-memory',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.add-known-fact': {
        name: 'securecode.add-known-fact',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.review-findings': {
        name: 'securecode.review-findings',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.decide-finding': {
        name: 'securecode.decide-finding',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.clear-finding-reviews': {
        name: 'securecode.clear-finding-reviews',
        category: 'read-only',
        requiresApproval: false,
    },
    'securecode.fix': {
        name: 'securecode.fix',
        category: 'paid-generation',
        requiresApproval: true,
        approvalNote: 'Fix generation calls /fix (consumes credits) and returns a patch. Approval required before the API call.',
    },
    'securecode.run-tests': {
        name: 'securecode.run-tests',
        category: 'paid-generation',
        requiresApproval: true,
        approvalNote: 'Test execution runs code in a sandbox. Approval required before execution.',
    },
    'securecode.attack': {
        name: 'securecode.attack',
        category: 'paid-generation',
        requiresApproval: true,
        approvalNote: 'Attack sends HTTP probes to a localhost server. Approval required. Currently disabled via SECURECODE_ATTACK_ENABLED.',
    },
};

export function getToolPolicy(toolName: string): ToolPolicy | undefined {
    return TOOL_POLICIES[toolName];
}

export function validateAllToolsHavePolicies(registeredTools: string[]): string[] {
    const missing: string[] = [];
    for (const name of registeredTools) {
        if (!TOOL_POLICIES[name]) {
            missing.push(name);
        }
    }
    return missing;
}

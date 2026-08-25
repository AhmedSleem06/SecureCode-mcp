import { describe, it, expect } from 'vitest';
import { TOOL_POLICIES, getToolPolicy, validateAllToolsHavePolicies } from '../src/approval/policy';

describe('Tool Policy', () => {
    it('every policy entry has required fields', () => {
        for (const [name, policy] of Object.entries(TOOL_POLICIES)) {
            expect(policy.name).toBe(name);
            expect(['read-only', 'sandboxed-verification', 'paid-generation', 'workspace-mutation']).toContain(policy.category);
            expect(typeof policy.requiresApproval).toBe('boolean');
        }
    });

    it('read-only tools do not require approval', () => {
        expect(TOOL_POLICIES['securecode.scan'].requiresApproval).toBe(false);
        expect(TOOL_POLICIES['securecode.map'].requiresApproval).toBe(false);
        expect(TOOL_POLICIES['securecode.agent-scan'].requiresApproval).toBe(false);
        expect(TOOL_POLICIES['securecode.agent-scan-batch'].requiresApproval).toBe(false);
    });

    it('paid-generation tools require approval', () => {
        expect(TOOL_POLICIES['securecode.fix'].requiresApproval).toBe(true);
        expect(TOOL_POLICIES['securecode.run-tests'].requiresApproval).toBe(true);
        expect(TOOL_POLICIES['securecode.attack'].requiresApproval).toBe(true);
    });

    it('getToolPolicy returns undefined for unknown tools', () => {
        expect(getToolPolicy('securecode.nonexistent')).toBeUndefined();
    });

    it('validateAllToolsHavePolicies returns empty for known tools', () => {
        const known = ['securecode.scan', 'securecode.fix', 'securecode.run-tests'];
        expect(validateAllToolsHavePolicies(known)).toEqual([]);
    });

    it('validateAllToolsHavePolicies returns missing tools', () => {
        const withUnknown = ['securecode.scan', 'securecode.unknown-tool'];
        const missing = validateAllToolsHavePolicies(withUnknown);
        expect(missing).toContain('securecode.unknown-tool');
        expect(missing).not.toContain('securecode.scan');
    });

    it('agent-scan notes that fix generation within it needs approval', () => {
        expect(TOOL_POLICIES['securecode.agent-scan'].approvalNote).toContain('Fix generation');
    });
});

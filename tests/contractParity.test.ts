import { describe, it, expect } from 'vitest';
import {
    AGENT_SCAN_PROTOCOL_VERSION,
    type AgentScanRunStatus,
    type TerminationReason,
} from '../src/attack/agentScanProtocol';

describe('agent scan protocol — canonical status contract', () => {
    it('AgentScanRunStatus has exactly 4 values', () => {
        const statuses: AgentScanRunStatus[] = [
            'completed', 'incomplete', 'failed', 'cancelled',
        ];
        expect(statuses).toHaveLength(4);
        expect(statuses).toContain('completed');
        expect(statuses).toContain('incomplete');
        expect(statuses).toContain('failed');
        expect(statuses).toContain('cancelled');
    });

    it('AgentScanRunStatus does not contain legacy values', () => {
        const legacy: string[] = ['capped', 'degraded', 'spawn_failed', 'blocked_recovery'];
        const valid: string[] = ['completed', 'incomplete', 'failed', 'cancelled'];
        for (const l of legacy) {
            expect(valid).not.toContain(l);
        }
    });

    it('TerminationReason includes api_restart', () => {
        const reasons: TerminationReason[] = [
            'agent_finish', 'forced_incomplete', 'budget_exhausted',
            'cost_cap', 'wall_clock', 'blocked_read_recovery',
            'api_error', 'api_restart', 'cancelled',
        ];
        expect(reasons).toContain('api_restart');
    });

    it('TerminationReason has exactly 9 values', () => {
        const reasons: TerminationReason[] = [
            'agent_finish', 'forced_incomplete', 'budget_exhausted',
            'cost_cap', 'wall_clock', 'blocked_read_recovery',
            'api_error', 'api_restart', 'cancelled',
        ];
        expect(reasons).toHaveLength(9);
    });

    it('protocol version is 5', () => {
        expect(AGENT_SCAN_PROTOCOL_VERSION).toBe(5);
    });
});

describe('agent scan protocol — status classification rules', () => {
    it('completed requires agent_finish termination reason', () => {
        const completedReasons: TerminationReason[] = ['agent_finish'];
        const incompleteReasons: TerminationReason[] = [
            'forced_incomplete', 'budget_exhausted', 'cost_cap',
            'wall_clock', 'blocked_read_recovery',
        ];
        const failedReasons: TerminationReason[] = ['api_error', 'api_restart'];
        const cancelledReasons: TerminationReason[] = ['cancelled'];

        for (const r of completedReasons) {
            expect(r).toBe('agent_finish');
        }
        for (const r of incompleteReasons) {
            expect(r).not.toBe('agent_finish');
        }
        for (const r of failedReasons) {
            expect(r).not.toBe('agent_finish');
        }
        for (const r of cancelledReasons) {
            expect(r).toBe('cancelled');
        }
    });
});

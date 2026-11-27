import { describe, it, expect } from 'vitest';
import { RENAMED_TOOLS } from '../src/mcp/tools';

describe('RENAMED_TOOLS dispatcher', () => {
    it('maps removed scan tool', () => {
        expect(RENAMED_TOOLS['securecode.scan']).toContain('agent-scan');
    });

    it('maps removed scan-batch tool', () => {
        expect(RENAMED_TOOLS['securecode.scan-batch']).toContain('agent-scan-batch');
    });

    it('maps removed attack tool', () => {
        expect(RENAMED_TOOLS['securecode.attack']).toContain('agent-scan');
    });

    it('maps old memory tools to securecode.memory', () => {
        expect(RENAMED_TOOLS['securecode.record-false-positive']).toContain('securecode.memory');
        expect(RENAMED_TOOLS['securecode.get-agent-memory']).toContain('securecode.memory');
        expect(RENAMED_TOOLS['securecode.clear-agent-memory']).toContain('securecode.memory');
        expect(RENAMED_TOOLS['securecode.add-known-fact']).toContain('securecode.memory');
    });

    it('maps clear-finding-reviews to decide-finding', () => {
        expect(RENAMED_TOOLS['securecode.clear-finding-reviews']).toContain('decide-finding');
    });

    it('does not map tools that still exist', () => {
        expect(RENAMED_TOOLS['securecode.agent-scan']).toBeUndefined();
        expect(RENAMED_TOOLS['securecode.memory']).toBeUndefined();
        expect(RENAMED_TOOLS['securecode.fix']).toBeUndefined();
    });
});

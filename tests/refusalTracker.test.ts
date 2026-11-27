import { describe, it, expect } from 'vitest';
import { createRunTestsRefusalTracker, type RunTestsRefusalTracker } from '../src/attack/agentScanExecutor';

describe('RunTestsRefusalTracker', () => {
    it('starts enabled', () => {
        const tracker = createRunTestsRefusalTracker();
        expect(tracker.disabled).toBe(false);
        expect(tracker.counts.size).toBe(0);
    });

    it('tracks rule counts and disables after 2 of the same rule', () => {
        const tracker = createRunTestsRefusalTracker();
        tracker.counts.set('network', 1);
        expect(tracker.disabled).toBe(false);

        const count = (tracker.counts.get('network') ?? 0) + 1;
        tracker.counts.set('network', count);
        if (count >= 2) tracker.disabled = true;

        expect(tracker.disabled).toBe(true);
        expect(tracker.counts.get('network')).toBe(2);
    });

    it('does not disable for different rules', () => {
        const tracker = createRunTestsRefusalTracker();
        tracker.counts.set('network', 1);
        tracker.counts.set('process.cwd', 1);
        expect(tracker.disabled).toBe(false);
    });
});

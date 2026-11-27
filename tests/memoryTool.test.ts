import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { toolMemory } from '../src/tools/agentMemoryTools';
import type { ServerContext } from '../src/mcp/types';

describe('securecode.memory', () => {
    let workspace: string;
    let ctx: ServerContext;

    beforeEach(() => {
        workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-memory-'));
        ctx = { workspaceRoot: workspace, apiUrl: '', apiToken: '' };
    });

    afterEach(() => {
        fs.rmSync(workspace, { recursive: true, force: true });
    });

    it('list returns empty memory on a fresh workspace', async () => {
        const result = await toolMemory(ctx, { action: 'list' }) as any;
        expect(result.falsePositives.count).toBe(0);
        expect(result.knownFacts.count).toBe(0);
    });

    it('add-fact stores a fact and list returns it', async () => {
        const addResult = await toolMemory(ctx, {
            action: 'add-fact',
            fact: 'Uses requireMembership for auth',
            source: 'src/middleware/auth.ts:5',
        }) as any;
        expect(addResult.success).toBe(true);
        expect(addResult.recorded.fact).toBe('Uses requireMembership for auth');

        const listResult = await toolMemory(ctx, { action: 'list' }) as any;
        expect(listResult.knownFacts.count).toBe(1);
        expect(listResult.knownFacts.entries[0].fact).toBe('Uses requireMembership for auth');
    });

    it('record-false-positive stores a false positive', async () => {
        const result = await toolMemory(ctx, {
            action: 'record-false-positive',
            filePath: 'src/app.ts',
            findingType: 'sql_injection',
            line: 42,
            evidence: 'db.query(sql)',
            reason: 'Uses parameterized query underneath',
        }) as any;
        expect(result.success).toBe(true);
        expect(result.recorded.findingType).toBe('sql_injection');

        const listResult = await toolMemory(ctx, { action: 'list' }) as any;
        expect(listResult.falsePositives.count).toBe(1);
    });

    it('record-false-positive requires all mandatory fields', async () => {
        await expect(toolMemory(ctx, {
            action: 'record-false-positive',
            filePath: 'src/app.ts',
        })).rejects.toThrow('findingType');
    });

    it('add-fact requires fact and source', async () => {
        await expect(toolMemory(ctx, { action: 'add-fact', fact: 'x' })).rejects.toThrow('source');
    });

    it('clear with id removes a specific false positive', async () => {
        const addResult = await toolMemory(ctx, {
            action: 'record-false-positive',
            filePath: 'src/x.ts',
            findingType: 'xss',
            line: 1,
            evidence: 'innerHTML',
            reason: 'sanitized',
        }) as any;
        const id = addResult.recorded.id;

        const clearResult = await toolMemory(ctx, { action: 'clear', id }) as any;
        expect(clearResult.success).toBe(true);

        const listResult = await toolMemory(ctx, { action: 'list' }) as any;
        expect(listResult.falsePositives.count).toBe(0);
    });

    it('clear without id removes all memory', async () => {
        await toolMemory(ctx, {
            action: 'record-false-positive',
            filePath: 'src/x.ts', findingType: 'xss', line: 1, evidence: 'e', reason: 'r',
        });
        await toolMemory(ctx, {
            action: 'add-fact', fact: 'fact1', source: 'src:1',
        });

        const clearResult = await toolMemory(ctx, { action: 'clear' }) as any;
        expect(clearResult.success).toBe(true);

        const listResult = await toolMemory(ctx, { action: 'list' }) as any;
        expect(listResult.falsePositives.count).toBe(0);
        expect(listResult.knownFacts.count).toBe(0);
    });

    it('rejects an invalid action', async () => {
        await expect(toolMemory(ctx, { action: 'invalid' })).rejects.toThrow('Unknown action');
    });
});

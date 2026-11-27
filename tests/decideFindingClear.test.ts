import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { toolDecideFinding, toolReviewFindings } from '../src/tools/findingReviewTools';
import { enqueueFindingReview } from '../src/audit/findingReviewQueue';
import type { ServerContext } from '../src/mcp/types';

describe('securecode.decide-finding — clear action', () => {
    let workspace: string;
    let ctx: ServerContext;

    beforeEach(() => {
        workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-decide-'));
        ctx = { workspaceRoot: workspace, apiUrl: '', apiToken: '' };
        enqueueCounter = 0;
    });

    afterEach(() => {
        fs.rmSync(workspace, { recursive: true, force: true });
    });

    let enqueueCounter = 0;
    function enqueue(): string {
        enqueueCounter++;
        const item = enqueueFindingReview(workspace, {
            workspaceRelativePath: `src/app${enqueueCounter}.ts`,
            fileContent: `const x = ${enqueueCounter};`,
            line: 10 + enqueueCounter,
            lineEnd: 15,
            findingType: 'sql_injection',
            severity: 'high',
            confidence: 80,
            proven: 'INCONCLUSIVE',
            reviewReason: 'sandbox-unavailable',
            evidence: `db.query(sql${enqueueCounter})`,
        });
        return item!.id;
    }

    it('clear by id removes a single review item', async () => {
        const id = enqueue();
        enqueue();

        const result = await toolDecideFinding(ctx, { decision: 'clear', id }) as any;
        expect(result.success).toBe(true);
        expect(result.removed).toBe(1);

        const list = await toolReviewFindings(ctx, {}) as any;
        expect(list.count).toBe(1);
    });

    it('clear without id removes all review items', async () => {
        enqueue();
        enqueue();

        const result = await toolDecideFinding(ctx, { decision: 'clear' }) as any;
        expect(result.success).toBe(true);
        expect(result.removed).toBe(2);

        const list = await toolReviewFindings(ctx, {}) as any;
        expect(list.count).toBe(0);
    });

    it('clear with resolvedOnly removes only resolved items', async () => {
        const id1 = enqueue();
        enqueue();

        await toolDecideFinding(ctx, { id: id1, decision: 'confirmed' });

        const result = await toolDecideFinding(ctx, { decision: 'clear', resolvedOnly: true }) as any;
        expect(result.success).toBe(true);
        expect(result.removed).toBe(1);

        const list = await toolReviewFindings(ctx, {}) as any;
        expect(list.count).toBe(1);
    });

    it('clear returns success:false when nothing to clear', async () => {
        const result = await toolDecideFinding(ctx, { decision: 'clear' }) as any;
        expect(result.success).toBe(false);
        expect(result.removed).toBe(0);
    });
});

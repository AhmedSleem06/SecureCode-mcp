import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

vi.mock('../src/project-map/taintTracker', () => ({
    trackTaint: vi.fn(),
}));

vi.mock('../src/project-map/crossFileTaintTracker', () => ({
    trackTaintCrossFile: vi.fn(),
}));

import { executeAction, executeFlowAction } from '../src/attack/agentScanExecutor';
import { formatEndpoints } from '../src/project-map/endpointDiscovery';
import { readSecurityConfig } from '../src/utils/securityConfig';
import { trackTaint } from '../src/project-map/taintTracker';
import { trackTaintCrossFile } from '../src/project-map/crossFileTaintTracker';
import { ApiClient } from '../src/api/client';

const SUFFIX = ' The tracker found no request-input sources it recognises in this file; this is not evidence the file is safe.';
const WS = fs.mkdtempSync(path.join(os.tmpdir(), 'honest-tools-'));
const ctx = { workspaceRoot: WS, apiUrl: 'http://localhost:3000', apiToken: 'test-token' } as any;
const target = { filePath: 'rpc.ts', language: 'typescript', fileContent: 'export const x = 1;' };
const client = new ApiClient({ baseUrl: 'http://localhost:3000', token: 'test-token' });

fs.writeFileSync(path.join(WS, 'rpc.ts'), 'export const x = 1;\n');

afterAll(() => {
    try { fs.rmSync(WS, { recursive: true, force: true }); } catch {}
});

describe('get_endpoints empty result', () => {
    it('states the tool limits', () => {
        expect(formatEndpoints([])).toBe(
            'No HTTP route handlers found. This tool does not detect WebSocket/RPC method tables or framework-specific routers — use search_code on the method table instead.',
        );
    });

    it('still lists endpoints when found', () => {
        const out = formatEndpoints([{ method: 'GET', path: '/a', file: 'a.ts', line: 3, framework: 'express' } as any]);
        expect(out).toContain('Found 1 endpoint(s):');
    });
});

describe('taint empty results', () => {
    beforeEach(() => vi.clearAllMocks());

    it('trace_flow empty result says it is not evidence of safety', async () => {
        (trackTaint as any).mockResolvedValue([]);
        const out = await executeAction({ type: 'trace_flow', filePath: 'rpc.ts', rationale: 'r' } as any, ctx, 'run-1', client, target as any);
        expect(out).toBe(`No taint flows found in rpc.ts.${SUFFIX}`);
    });

    it('trace_flow_cross_file empty result says it is not evidence of safety', async () => {
        (trackTaintCrossFile as any).mockResolvedValue([]);
        const out = await executeAction({ type: 'trace_flow_cross_file', filePath: 'rpc.ts', rationale: 'r' } as any, ctx, 'run-1', client, target as any);
        expect(out).toBe(`No cross-file taint flows found starting from rpc.ts.${SUFFIX}`);
    });

    it('structured trace_flow keeps refuted status with the new text', async () => {
        (trackTaint as any).mockResolvedValue([]);
        const res = await executeFlowAction({ type: 'trace_flow', filePath: 'rpc.ts', rationale: 'r' } as any, ctx, 'run-1', client, target as any);
        expect(res.observation).toBe(`No taint flows found in rpc.ts.${SUFFIX}`);
        expect(res.flowResult.status).toBe('refuted');
    });

    it('structured trace_flow_cross_file keeps refuted status with the new text', async () => {
        (trackTaintCrossFile as any).mockResolvedValue([]);
        const res = await executeFlowAction({ type: 'trace_flow_cross_file', filePath: 'rpc.ts', rationale: 'r' } as any, ctx, 'run-1', client, target as any);
        expect(res.observation).toBe(`No cross-file taint flows found starting from rpc.ts.${SUFFIX}`);
        expect(res.flowResult.status).toBe('refuted');
    });
});

describe('read_config empty result', () => {
    it('keeps the original start and names what was searched', async () => {
        const out = await readSecurityConfig(WS, 'all');
        const [first, second] = out.split('\n');
        expect(first).toBe('No security config files found. The project may not have explicit security config — check if it relies on framework defaults or environment variables.');
        expect(second.startsWith('Searched: ')).toBe(true);
        expect(second).toContain('.env.example');
        expect(second.length - 'Searched: '.length).toBeLessThanOrEqual(200);
        expect(second.endsWith('…')).toBe(true);
    });

    it('lists only the patterns for the requested kind', async () => {
        const out = await readSecurityConfig(WS, 'cors');
        expect(out.startsWith('No cors security config files found.')).toBe(true);
        expect(out).toContain('Searched: files in ./, config/, src/: cors.config.js, cors.config.ts; inline in *.{js,ts,mjs,jsx,tsx}: cors() call');
        expect(out).not.toContain('helmet');
    });

    it('says nothing was searched when the kind has no patterns', async () => {
        const out = await readSecurityConfig(WS, 'auth');
        expect(out.startsWith('No auth security config files found.')).toBe(true);
        expect(out).toContain('Searched: nothing — read_config has no auth file names or inline patterns to look for.');
    });

    it('via executeAction', async () => {
        const out = await executeAction({ type: 'read_config', configKind: 'auth', rationale: 'r' } as any, ctx, 'run-1', client, target as any);
        expect(out).toContain('Searched: nothing');
    });
});

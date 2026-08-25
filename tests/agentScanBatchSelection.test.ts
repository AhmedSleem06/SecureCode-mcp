import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { selectAgentScanBatchFiles } from '../src/attack/agentScanBatchSelection';
import type { ArchitectureContext } from '../src/project-map/architectureContext';

function makeArch(overrides?: Partial<ArchitectureContext>): ArchitectureContext {
    return {
        version: 1,
        depth: 'standard',
        derivedAt: Date.now(),
        projectMapBuiltAt: Date.now(),
        projectMapVersion: 1,
        project: { type: 'web', frameworks: ['express'], runtimes: ['node'], packageManager: 'npm', languages: ['typescript'] },
        importantFiles: [],
        trustBoundaries: [],
        dataFlows: [],
        securityControls: [],
        architectureRisks: [],
        recommendedScanOrder: [],
        summary: 'test',
        completeness: 'full',
        ...overrides,
    };
}

describe('selectAgentScanBatchFiles', () => {
    let workspaceRoot: string;

    beforeEach(() => {
        workspaceRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'batch-select-'));
    });

    afterEach(() => {
        try { fs.rmSync(workspaceRoot, { recursive: true, force: true }); } catch {}
    });

    function writeFile(relPath: string, content: string): void {
        const full = path.join(workspaceRoot, relPath);
        fs.mkdirSync(path.dirname(full), { recursive: true });
        fs.writeFileSync(full, content, 'utf8');
    }

    it('selects files from recommendedScanOrder in order', () => {
        writeFile('src/a.ts', 'const a = 1;');
        writeFile('src/b.ts', 'const b = 2;');
        writeFile('src/c.ts', 'const c = 3;');
        const arch = makeArch({ recommendedScanOrder: ['src/a.ts', 'src/b.ts', 'src/c.ts'] });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 3 });
        expect(result.selected).toHaveLength(3);
        expect(result.selected[0].filePath).toBe('src/a.ts');
        expect(result.selected[1].filePath).toBe('src/b.ts');
        expect(result.selected[2].filePath).toBe('src/c.ts');
    });

    it('removes duplicate paths', () => {
        writeFile('src/a.ts', 'const a = 1;');
        const arch = makeArch({ recommendedScanOrder: ['src/a.ts', 'src/a.ts', 'src/a.ts'] });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 5 });
        expect(result.selected).toHaveLength(1);
    });

    it('skips missing files without consuming slots', () => {
        writeFile('src/exists.ts', 'const x = 1;');
        const arch = makeArch({ recommendedScanOrder: ['src/missing.ts', 'src/exists.ts'] });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 3 });
        expect(result.selected).toHaveLength(1);
        expect(result.selected[0].filePath).toBe('src/exists.ts');
        expect(result.skipped).toHaveLength(1);
        expect(result.skipped[0].filePath).toBe('src/missing.ts');
    });

    it('falls back to importantFiles when recommendedScanOrder is short', () => {
        writeFile('src/a.ts', 'const a = 1;');
        writeFile('src/b.ts', 'const b = 2;');
        writeFile('src/c.ts', 'const c = 3;');
        const arch = makeArch({
            recommendedScanOrder: ['src/a.ts'],
            importantFiles: [
                { file: 'src/b.ts', role: 'route_handler', importance: 90, reasons: ['test'] },
                { file: 'src/c.ts', role: 'authentication', importance: 95, reasons: ['test'] },
            ],
        });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 3 });
        expect(result.selected).toHaveLength(3);
        expect(result.selected[0].filePath).toBe('src/a.ts');
        expect(result.selected[1].filePath).toBe('src/c.ts');
        expect(result.selected[2].filePath).toBe('src/b.ts');
    });

    it('output order is deterministic', () => {
        writeFile('src/a.ts', 'const a = 1;');
        writeFile('src/b.ts', 'const b = 2;');
        const arch = makeArch({ recommendedScanOrder: ['src/a.ts', 'src/b.ts'] });
        const r1 = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 2 });
        const r2 = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 2 });
        expect(r1.selected).toEqual(r2.selected);
    });

    it('clamps topN to 1..20', () => {
        writeFile('src/a.ts', 'const a = 1;');
        const arch = makeArch({ recommendedScanOrder: ['src/a.ts'] });
        const result0 = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 0 });
        expect(result0.selected).toHaveLength(1);
        const resultNeg = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: -5 });
        expect(resultNeg.selected).toHaveLength(1);
        const resultBig = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 100 });
        expect(resultBig.selected).toHaveLength(1);
    });

    it('skips empty files', () => {
        writeFile('src/empty.ts', '   \n  \n  ');
        writeFile('src/real.ts', 'const x = 1;');
        const arch = makeArch({ recommendedScanOrder: ['src/empty.ts', 'src/real.ts'] });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 2 });
        expect(result.selected).toHaveLength(1);
        expect(result.selected[0].filePath).toBe('src/real.ts');
        expect(result.skipped[0].reason).toContain('empty');
    });

    it('skips binary files', () => {
        const binaryContent = Buffer.concat([
            Buffer.from('some text \x00 binary'),
            Buffer.alloc(500, 0),
        ]);
        fs.mkdirSync(path.join(workspaceRoot, 'src'), { recursive: true });
        fs.writeFileSync(path.join(workspaceRoot, 'src/binary.ts'), binaryContent);
        writeFile('src/real.ts', 'const x = 1;');
        const arch = makeArch({ recommendedScanOrder: ['src/binary.ts', 'src/real.ts'] });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 2 });
        expect(result.selected).toHaveLength(1);
        expect(result.selected[0].filePath).toBe('src/real.ts');
        expect(result.skipped[0].reason).toContain('binary');
    });

    it('skips oversized files', () => {
        const big = 'x'.repeat(1_600_000);
        fs.mkdirSync(path.join(workspaceRoot, 'src'), { recursive: true });
        fs.writeFileSync(path.join(workspaceRoot, 'src/big.ts'), big);
        writeFile('src/real.ts', 'const x = 1;');
        const arch = makeArch({ recommendedScanOrder: ['src/big.ts', 'src/real.ts'] });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 2 });
        expect(result.selected).toHaveLength(1);
        expect(result.selected[0].filePath).toBe('src/real.ts');
        expect(result.skipped[0].reason).toContain('too large');
    });

    it('returns empty selection when architecture is null', () => {
        const result = selectAgentScanBatchFiles(workspaceRoot, null, { topN: 3 });
        expect(result.selected).toEqual([]);
        expect(result.skipped).toEqual([]);
    });

    it('uses importantFiles as primary when fileSelection is importantFiles', () => {
        writeFile('src/a.ts', 'const a = 1;');
        writeFile('src/b.ts', 'const b = 2;');
        const arch = makeArch({
            recommendedScanOrder: ['src/b.ts'],
            importantFiles: [
                { file: 'src/a.ts', role: 'authentication', importance: 95, reasons: ['test'] },
                { file: 'src/b.ts', role: 'route_handler', importance: 70, reasons: ['test'] },
            ],
        });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, {
            topN: 2,
            fileSelection: 'importantFiles',
        });
        expect(result.selected).toHaveLength(2);
        expect(result.selected[0].filePath).toBe('src/a.ts');
        expect(result.selected[1].filePath).toBe('src/b.ts');
    });

    it('assigns rank starting at 1 in selection order', () => {
        writeFile('src/a.ts', 'const a = 1;');
        writeFile('src/b.ts', 'const b = 2;');
        writeFile('src/c.ts', 'const c = 3;');
        const arch = makeArch({ recommendedScanOrder: ['src/a.ts', 'src/b.ts', 'src/c.ts'] });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 3 });
        expect(result.selected[0].rank).toBe(1);
        expect(result.selected[1].rank).toBe(2);
        expect(result.selected[2].rank).toBe(3);
    });

    it('attaches role and importance from importantFiles', () => {
        writeFile('src/auth.ts', 'const auth = 1;');
        const arch = makeArch({
            recommendedScanOrder: ['src/auth.ts'],
            importantFiles: [
                { file: 'src/auth.ts', role: 'authentication', importance: 95, reasons: ['test'] },
            ],
        });
        const result = selectAgentScanBatchFiles(workspaceRoot, arch, { topN: 1 });
        expect(result.selected[0].role).toBe('authentication');
        expect(result.selected[0].importance).toBe(95);
    });
});

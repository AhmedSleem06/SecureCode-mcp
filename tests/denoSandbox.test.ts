import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { EventEmitter } from 'events';

vi.mock('child_process', async (importOriginal) => {
    const actual = await importOriginal<typeof import('child_process')>();
    return {
        ...actual,
        spawn: vi.fn(),
        spawnSync: vi.fn(() => ({ status: 1, stdout: Buffer.from('') })),
    };
});

import { spawn } from 'child_process';
import { DenoSandbox, denoScriptExt, denoRunArgs } from '../src/utils/verificationSandbox';

interface SpawnCall {
    bin: string;
    args: string[];
    scriptFile: string;
    scriptContent: string;
}

describe('DenoSandbox', () => {
    let ws: string;
    let calls: SpawnCall[];

    beforeEach(() => {
        ws = fs.mkdtempSync(path.join(os.tmpdir(), 'deno-sandbox-'));
        calls = [];
        (spawn as any).mockReset();
        (spawn as any).mockImplementation((bin: string, args: string[]) => {
            const scriptFile = args[args.length - 1];
            calls.push({ bin, args, scriptFile, scriptContent: fs.readFileSync(scriptFile, 'utf8') });
            const proc: any = new EventEmitter();
            proc.stdout = new EventEmitter();
            proc.stderr = new EventEmitter();
            proc.pid = 4242;
            proc.kill = () => true;
            setImmediate(() => {
                proc.stdout.emit('data', Buffer.from('PASS: ran\n'));
                proc.emit('close', 0);
            });
            return proc;
        });
    });

    afterEach(() => {
        fs.rmSync(ws, { recursive: true, force: true });
    });

    it('runs a require()-only script as .cjs with the CJS/sloppy-import compat flags', async () => {
        const script = 'const { app } = require("../src/app");\nconsole.log("PASS: x");';
        const result = await new DenoSandbox().execute({ script, runner: 'deno', workspaceRoot: ws, timeoutMs: 5000 });

        expect(result.verdict).toBe('pass');
        expect(result.backend).toBe('deno');
        expect(calls).toHaveLength(1);
        const call = calls[0];
        expect(call.bin).toBe('deno');
        expect(call.args[0]).toBe('run');
        expect(call.scriptFile.endsWith('.cjs')).toBe(true);
        expect(call.scriptContent).toBe(script);
        expect(call.args).toContain('--unstable-detect-cjs');
        expect(call.args).toContain('--unstable-sloppy-imports');
        expect(call.args).toContain('--no-remote');
        expect(call.args).toContain('--no-prompt');
        expect(call.args).toContain('--allow-env=NODE_ENV');
        expect(call.args).toContain(`--allow-read=${ws},${call.scriptFile}`);
        expect(call.args.some(a => a.startsWith('--allow-net') || a.startsWith('--allow-run') || a === '--allow-all' || a === '-A')).toBe(false);
        expect(call.args.indexOf('--unstable-detect-cjs')).toBeLessThan(call.args.indexOf(call.scriptFile));
        expect(fs.existsSync(call.scriptFile)).toBe(false);
    });

    it('runs an ESM script as .mts', async () => {
        const script = 'import { handler } from "../src/app.ts";\nconsole.log("PASS: x");';
        await new DenoSandbox().execute({ script, runner: 'deno', workspaceRoot: ws, timeoutMs: 5000 });

        expect(calls[0].scriptFile.endsWith('.mts')).toBe(true);
        expect(calls[0].args).toContain('--unstable-detect-cjs');
    });

    it('runs an ESM script that uses createRequire as .mts', async () => {
        const script = [
            'import { createRequire } from "node:module";',
            'const require = createRequire(import.meta.url);',
            'const { app } = require("../src/app.js");',
            'console.log("PASS: x");',
        ].join('\n');
        await new DenoSandbox().execute({ script, runner: 'deno', workspaceRoot: ws, timeoutMs: 5000 });

        expect(calls[0].scriptFile.endsWith('.mts')).toBe(true);
    });

    it('applies the compat flags and per-script extension to the setup script too', async () => {
        await new DenoSandbox().execute({
            script: 'import "./x.js";\nconsole.log("PASS: x");',
            setupScript: 'require("../src/seed");\nconsole.log("seeded");',
            runner: 'deno',
            workspaceRoot: ws,
            timeoutMs: 5000,
        });

        expect(calls).toHaveLength(2);
        expect(calls[0].scriptFile.endsWith('.cjs')).toBe(true);
        expect(calls[0].args).toContain('--unstable-detect-cjs');
        expect(calls[0].args).toContain('--unstable-sloppy-imports');
        expect(calls[1].scriptFile.endsWith('.mts')).toBe(true);
        expect(calls[1].args).toContain('--unstable-sloppy-imports');
    });

    it('refuses python and command mode without spawning', async () => {
        const py = await new DenoSandbox().execute({ script: 'print("PASS: x")', runner: 'python3', workspaceRoot: ws, timeoutMs: 5000 });
        const cmd = await new DenoSandbox().execute({ mode: 'command', executable: 'npm', args: ['test'], workspaceRoot: ws, timeoutMs: 5000 });
        expect(py.verdict).toBe('blocked');
        expect(cmd.verdict).toBe('sandbox-unavailable');
        expect(spawn).not.toHaveBeenCalled();
    });
});

describe('denoScriptExt', () => {
    it('uses .cjs for require() scripts without ESM syntax', () => {
        expect(denoScriptExt('const a = require("./a");')).toBe('.cjs');
        expect(denoScriptExt('const Module = require("module");\nModule._load = () => {};')).toBe('.cjs');
    });

    it('uses .mts when the script has import/export or import.meta', () => {
        expect(denoScriptExt('import a from "./a";\nconst b = require("./b");')).toBe('.mts');
        expect(denoScriptExt('import { x } from "./a";')).toBe('.mts');
        expect(denoScriptExt('import "./side-effect";\nrequire("./b");')).toBe('.mts');
        expect(denoScriptExt('export const x = 1;\nrequire("./b");')).toBe('.mts');
        expect(denoScriptExt('const r = createRequire(import.meta.url); r("./b"); require("./c");')).toBe('.mts');
    });

    it('uses .mts when there is no require()', () => {
        expect(denoScriptExt('console.log("PASS: x");')).toBe('.mts');
        expect(denoScriptExt('const m = await import("./a.js");')).toBe('.mts');
    });

    it('does not treat an identifier starting with "import" as ESM syntax', () => {
        expect(denoScriptExt('importantValue = require("./a");')).toBe('.cjs');
    });
});

describe('denoRunArgs', () => {
    it('places permission and compat flags before the script path', () => {
        const args = denoRunArgs('/ws/.securecode/t.cjs', ['/ws', '/ws/.securecode/t.cjs'], '/ws/.securecode/tmp');
        expect(args).toEqual([
            'run',
            '--allow-read=/ws,/ws/.securecode/t.cjs',
            '--allow-write=/ws/.securecode/tmp',
            '--allow-env=NODE_ENV',
            '--no-remote',
            '--no-prompt',
            '--unstable-detect-cjs',
            '--unstable-sloppy-imports',
            '/ws/.securecode/t.cjs',
        ]);
    });
});

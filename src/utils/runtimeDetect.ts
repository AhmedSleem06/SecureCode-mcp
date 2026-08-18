import * as fs from 'fs';
import * as path from 'path';

export type ProjectRuntime = 'bun' | 'node' | 'deno';

export interface RuntimeInfo {
    runtime: ProjectRuntime;
    runner: string;
    hasBunLock: boolean;
}

export function detectRuntime(workspaceRoot: string): RuntimeInfo {
    const hasBunLock = fs.existsSync(path.join(workspaceRoot, 'bun.lockb')) ||
        fs.existsSync(path.join(workspaceRoot, 'bun.lock')) ||
        fs.existsSync(path.join(workspaceRoot, 'bunfig.toml'));

    if (hasBunLock) {
        return { runtime: 'bun', runner: 'bun', hasBunLock: true };
    }

    if (fs.existsSync(path.join(workspaceRoot, 'deno.json')) ||
        fs.existsSync(path.join(workspaceRoot, 'deno.jsonc'))) {
        return { runtime: 'deno', runner: 'deno', hasBunLock: false };
    }

    return { runtime: 'node', runner: 'tsx', hasBunLock: false };
}

export function computeRelativeImportPath(testFileDir: string, targetFilePath: string): string {
    const rel = path.relative(testFileDir, targetFilePath);
    const normalized = rel.replace(/\\/g, '/');
    const withoutExt = normalized.replace(/\.(ts|tsx|js|jsx|mjs|cjs)$/, '');
    return withoutExt.startsWith('.') ? withoutExt : `./${withoutExt}`;
}

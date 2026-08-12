import type { ServerContext } from '../mcp/types';
import { scanDependencies } from '../dependency/dependencyChecker';
import { FileCacheStore } from '../dependency/depCache';

/**
 * securecode.scan-dependencies — scan local lockfiles for known vulnerabilities.
 *
 * Read-only: no approval needed. Runs entirely locally — only package name+version
 * leave the machine (to OSV.dev, GitHub Advisory, NVD). No source code is sent.
 *
 * Supports 5 lockfile types: package-lock.json, yarn.lock, pnpm-lock.yaml,
 * Pipfile.lock, requirements.txt.
 */
export async function toolScanDependencies(ctx: ServerContext, _args: any): Promise<unknown> {
    const cache = new FileCacheStore(ctx.workspaceRoot);

    const result = await scanDependencies({
        workspaceRoot: ctx.workspaceRoot,
        state: cache,
        licensePolicy: 'warn',
        useGhsa: true,
    });

    return {
        findings: result.findings.map((f) => ({
            check_id: f.check_id,
            severity: f.severity,
            message: f.message,
            source: f.source,
            dependency: f.dependency,
        })),
        packageCount: result.packageCount,
        unresolvedCount: result.unresolvedCount,
        lockfiles: result.lockfiles,
        ghsaSkipped: result.ghsaSkipped ?? false,
    };
}

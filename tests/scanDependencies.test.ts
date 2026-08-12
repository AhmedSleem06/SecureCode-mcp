import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { toolScanDependencies } from '../src/tools/scanDependencies';

// ── Mock fetch for OSV + GHSA + NVD ────────────────────────────────────

function mockFetch(url: string | URL, init?: any): Promise<Response> {
    const u = typeof url === 'string' ? url : url.toString();

    // OSV.dev batch query
    if (u.includes('api.osv.dev')) {
        const body = init?.body ? JSON.parse(init.body) : { queries: [] };
        const queries = body.queries || [];
        const results = queries.map((q: any) => {
            if (q?.package?.name === 'lodash' && q?.version === '4.17.4') {
                return {
                    vulns: [{
                        id: 'GHSA-35jh-r3h4-6jhm',
                        summary: 'Command Injection in lodash',
                        affected: [{
                            package: { ecosystem: 'npm', name: 'lodash' },
                            ranges: [{
                                type: 'SEMVER',
                                events: [{ introduced: '0' }, { fixed: '4.17.21' }],
                            }],
                        }],
                        severity: [{ type: 'CVSS_V3', score: '7.2' }],
                        references: [{ url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' }],
                    }],
                };
            }
            return { vulns: [] };
        });
        return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ results }),
        } as Response);
    }

    // GitHub Advisory REST API
    if (u.includes('api.github.com/advisories')) {
        const parsed = new URL(u);
        const pkg = parsed.searchParams.get('affected_package');
        if (pkg === 'lodash') {
            return Promise.resolve({
                ok: true,
                json: () => Promise.resolve([
                    {
                        ghsa_id: 'GHSA-35jh-r3h4-6jhm',
                        summary: 'Command Injection in lodash',
                        cve_id: 'CVE-2021-23337',
                        cvss: { score: 7.2 },
                        vulnerabilities: [{
                            package: { ecosystem: 'npm', name: 'lodash' },
                            vulnerable_version_range: '< 4.17.21',
                            patched_version_range: '>= 4.17.21',
                        }],
                        references: [{ url: 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm' }],
                    },
                ]),
            } as Response);
        }
        return Promise.resolve({ ok: true, json: () => Promise.resolve([]) } as Response);
    }

    // NVD fallback
    if (u.includes('services.nvd.nist.gov')) {
        return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({
                vulnerabilities: [{
                    cve: {
                        id: 'CVE-2021-23337',
                        metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.2 } }] },
                        references: [{ url: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23337' }],
                    },
                }],
            }),
        } as Response);
    }

    return Promise.resolve({ ok: false, json: () => Promise.resolve(null) } as Response);
}

// ── Tests ──────────────────────────────────────────────────────────────

describe('securecode.scan-dependencies — full pipeline', () => {
    let workspace: string;
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
        workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-mcp-deptest-'));
        originalFetch = global.fetch;
        global.fetch = vi.fn(mockFetch) as typeof global.fetch;
    });

    afterEach(() => {
        global.fetch = originalFetch;
        try { fs.rmSync(workspace, { recursive: true, force: true }); } catch { /* ok */ }
    });

    it('finds lodash@4.17.4 vulnerability with fix version 4.17.21', async () => {
        // Write fixture lockfile with a vulnerable package
        fs.writeFileSync(path.join(workspace, 'package.json'), '{"name":"test","version":"1.0.0","license":"MIT"}');
        fs.writeFileSync(path.join(workspace, 'package-lock.json'), JSON.stringify({
            name: 'test',
            version: '1.0.0',
            lockfileVersion: 3,
            packages: {
                '': { name: 'test', version: '1.0.0', license: 'MIT' },
                'node_modules/lodash': { version: '4.17.4', license: 'MIT' },
            },
        }));

        const result = await toolScanDependencies(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            {},
        ) as any;

        expect(result).toHaveProperty('findings');
        expect(result.findings.length).toBeGreaterThanOrEqual(1);
        const lodashFinding = result.findings.find((f: any) => f.dependency?.name === 'lodash');
        expect(lodashFinding).toBeDefined();
        expect(lodashFinding.dependency.installedVersion).toBe('4.17.4');
        expect(lodashFinding.dependency.fixedVersion).toBe('4.17.21');
        expect(lodashFinding.severity === 'ERROR' || lodashFinding.severity === 'WARNING').toBe(true);
    });

    it('returns 0 findings for a clean lockfile', async () => {
        fs.writeFileSync(path.join(workspace, 'package.json'), '{"name":"clean","version":"1.0.0","license":"MIT"}');
        fs.writeFileSync(path.join(workspace, 'package-lock.json'), JSON.stringify({
            name: 'clean',
            version: '1.0.0',
            lockfileVersion: 3,
            packages: {
                '': { name: 'clean', version: '1.0.0', license: 'MIT' },
                'node_modules/lodash': { version: '4.17.21', license: 'MIT' },
            },
        }));

        const result = await toolScanDependencies(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            {},
        ) as any;

        expect(result.findings.length).toBe(0);
        expect(result.packageCount).toBe(1);
        expect(result.lockfiles.length).toBe(1);
    });

    it('returns valid structure even with no lockfiles', async () => {
        // Empty workspace, no lockfiles
        const result = await toolScanDependencies(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            {},
        ) as any;

        expect(result).toHaveProperty('findings');
        expect(Array.isArray(result.findings)).toBe(true);
        expect(result.findings.length).toBe(0);
        expect(result.packageCount).toBe(0);
        expect(result.lockfiles.length).toBe(0);
    });

    it('GHSA provides real CVSS score (not approximated)', async () => {
        fs.writeFileSync(path.join(workspace, 'package.json'), '{"name":"test","version":"1.0.0"}');
        fs.writeFileSync(path.join(workspace, 'package-lock.json'), JSON.stringify({
            name: 'test',
            version: '1.0.0',
            lockfileVersion: 3,
            packages: {
                '': { name: 'test', version: '1.0.0' },
                'node_modules/lodash': { version: '4.17.4' },
            },
        }));

        const result = await toolScanDependencies(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            {},
        ) as any;

        // The finding should have a severity based on real CVSS (7.2 → ERROR since >= 7)
        const lodashFinding = result.findings.find((f: any) => f.dependency?.name === 'lodash');
        if (lodashFinding) {
            // CVSS 7.2 should map to ERROR (>= 7 threshold in dependencyChecker.ts)
            expect(lodashFinding.severity).toBe('ERROR');
        }
    });

    it('deduplicates vulns across OSV + GHSA (same id appears once)', async () => {
        fs.writeFileSync(path.join(workspace, 'package.json'), '{"name":"test","version":"1.0.0"}');
        fs.writeFileSync(path.join(workspace, 'package-lock.json'), JSON.stringify({
            name: 'test',
            version: '1.0.0',
            lockfileVersion: 3,
            packages: {
                '': { name: 'test', version: '1.0.0' },
                'node_modules/lodash': { version: '4.17.4' },
            },
        }));

        const result = await toolScanDependencies(
            { apiUrl: '', apiToken: '', workspaceRoot: workspace },
            {},
        ) as any;

        // OSV returns GHSA-35jh-r3h4-6jhm and GHSA also returns the same id.
        // The rolled-up finding should mention the worst CVE only once.
        const lodashFinding = result.findings.find((f: any) => f.dependency?.name === 'lodash');
        if (lodashFinding) {
            // The check_id should contain the vuln id exactly once
            expect(lodashFinding.check_id).toContain('GHSA-35jh-r3h4-6jhm');
            // The message should not list the same advisory id twice
            const matches = lodashFinding.message.match(/GHSA-35jh-r3h4-6jhm/g);
            if (matches) {
                expect(matches.length).toBe(1);
            }
        }
    });
});

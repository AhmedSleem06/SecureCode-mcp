import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { queryOsvBatch, enrichWithNvd } from '../src/dependency/osvClient';
import type { ResolvedPackage, Vulnerability } from '../src/dependency/types';
import type { CacheStore } from '../src/dependency/finding';

function makeMockFetch() {
    return vi.fn(async (url: string | URL) => {
        const u = typeof url === 'string' ? url : url.toString();

        if (u === 'https://api.osv.dev/v1/querybatch') {
            return {
                ok: true,
                json: async () => ({
                    results: [
                        { vulns: [{ id: 'GHSA-test-1234-abcd' }] },
                        { vulns: [] },
                    ],
                }),
            } as Response;
        }

        if (u === 'https://api.osv.dev/v1/vulns/GHSA-test-1234-abcd') {
            return {
                ok: true,
                json: async () => ({
                    id: 'GHSA-test-1234-abcd',
                    summary: 'Test vulnerability in django',
                    aliases: ['CVE-2021-99999'],
                    affected: [{
                        package: { ecosystem: 'PyPI', name: 'django' },
                        ranges: [{
                            type: 'ECOSYSTEM',
                            events: [{ introduced: '2.0' }, { fixed: '2.2.28' }],
                        }],
                    }],
                    severity: [{ type: 'CVSS_V3', score: '9.8' }],
                    references: [{ url: 'https://example.com/advisory' }],
                }),
            } as Response;
        }

        return { ok: false, status: 404 } as Response;
    });
}

describe('OSV client — hydration', () => {
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
        originalFetch = global.fetch;
    });

    afterEach(() => {
        global.fetch = originalFetch;
    });

    it('hydrates advisory details from individual vuln endpoint', async () => {
        global.fetch = makeMockFetch() as typeof global.fetch;

        const packages: ResolvedPackage[] = [
            { ecosystem: 'pip', name: 'django', version: '2.2.0', direct: true },
            { ecosystem: 'pip', name: 'requests', version: '2.31.0', direct: true },
        ];

        const result = await queryOsvBatch(packages);
        const djangoKey = 'PyPI:django@2.2.0';
        expect(result.has(djangoKey)).toBe(true);
        const vulns = result.get(djangoKey)!;
        expect(vulns.length).toBe(1);
        expect(vulns[0].id).toBe('GHSA-test-1234-abcd');
        expect(vulns[0].summary).toBe('Test vulnerability in django');
        expect(vulns[0].cvssScore).toBe(9.8);
        expect(vulns[0].affected.length).toBe(1);
        expect(vulns[0].affected[0].fixed).toBe('2.2.28');
        expect(vulns[0].aliases).toContain('CVE-2021-99999');

        const requestsKey = 'PyPI:requests@2.31.0';
        expect(result.has(requestsKey)).toBe(false);
    });

    it('uses cache for hydrated vulns', async () => {
        const mockFetch = vi.fn(async (url: string | URL, init?: any) => {
            const u = typeof url === 'string' ? url : url.toString();
            if (u === 'https://api.osv.dev/v1/querybatch') {
                return {
                    ok: true,
                    json: async () => ({
                        results: [
                            { vulns: [{ id: 'GHSA-test-1234-abcd' }] },
                        ],
                    }),
                } as Response;
            }
            if (u === 'https://api.osv.dev/v1/vulns/GHSA-test-1234-abcd') {
                return {
                    ok: true,
                    json: async () => ({
                        id: 'GHSA-test-1234-abcd',
                        summary: 'Test vuln',
                        affected: [],
                        severity: [{ type: 'CVSS_V3', score: '5.0' }],
                    }),
                } as Response;
            }
            return { ok: false, status: 404 } as Response;
        });
        global.fetch = mockFetch as typeof global.fetch;

        const cache: CacheStore = {
            get: vi.fn().mockReturnValue(undefined),
            update: vi.fn(),
        };

        const packages: ResolvedPackage[] = [
            { ecosystem: 'pip', name: 'django', version: '2.2.0' },
        ];

        await queryOsvBatch(packages, cache);
        expect(cache.update).toHaveBeenCalledWith(
            'osv.vuln.GHSA-test-1234-abcd',
            expect.objectContaining({ id: 'GHSA-test-1234-abcd' }),
        );

        (cache.get as ReturnType<typeof vi.fn>).mockImplementation((key: string) => {
            if (key === 'osv.vuln.GHSA-test-1234-abcd') {
                return {
                    id: 'GHSA-test-1234-abcd',
                    source: 'osv',
                    sources: ['osv'],
                    summary: 'cached',
                    affected: [],
                    cvssScore: 9.8,
                };
            }
            return undefined;
        });

        const fetchCallsBefore = mockFetch.mock.calls.length;
        await queryOsvBatch(packages, cache);
        const vulnFetches = mockFetch.mock.calls.slice(fetchCallsBefore)
            .filter(c => (c[0] as string).includes('/v1/vulns/'));
        expect(vulnFetches.length).toBe(0);
    });

    it('handles partial fetch failures gracefully', async () => {
        let callCount = 0;
        global.fetch = vi.fn(async (url: string | URL) => {
            const u = typeof url === 'string' ? url : url.toString();
            if (u === 'https://api.osv.dev/v1/querybatch') {
                return {
                    ok: true,
                    json: async () => ({
                        results: [
                            { vulns: [{ id: 'GHSA-good' }, { id: 'GHSA-fail' }] },
                        ],
                    }),
                } as Response;
            }
            if (u.includes('GHSA-good')) {
                return {
                    ok: true,
                    json: async () => ({
                        id: 'GHSA-good',
                        summary: 'Good vuln',
                        affected: [],
                        severity: [{ type: 'CVSS_V3', score: '5.0' }],
                    }),
                } as Response;
            }
            throw new Error('network error');
        }) as typeof global.fetch;

        const packages: ResolvedPackage[] = [
            { ecosystem: 'npm', name: 'test-pkg', version: '1.0.0' },
        ];

        const result = await queryOsvBatch(packages);
        const vulns = result.get('npm:test-pkg@1.0.0');
        expect(vulns).toBeDefined();
        expect(vulns!.length).toBe(1);
        expect(vulns![0].id).toBe('GHSA-good');
    });
});

describe('enrichWithNvd — CVE alias lookup', () => {
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
        originalFetch = global.fetch;
    });

    afterEach(() => {
        global.fetch = originalFetch;
    });

    it('looks up CVE via aliases when id is not a CVE', async () => {
        global.fetch = vi.fn(async (url: string | URL) => {
            const u = typeof url === 'string' ? url : url.toString();
            if (u.includes('CVE-2021-99999')) {
                return {
                    ok: true,
                    json: async () => ({
                        vulnerabilities: [{
                            cve: {
                                id: 'CVE-2021-99999',
                                metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.1 } }] },
                                references: [],
                            },
                        }],
                    }),
                } as Response;
            }
            return { ok: false } as Response;
        }) as typeof global.fetch;

        const cache: CacheStore = {
            get: () => undefined,
            update: vi.fn(),
        };

        const vulns: Vulnerability[] = [{
            id: 'GHSA-test-abcd',
            source: 'osv',
            sources: ['osv'],
            summary: 'test',
            affected: [],
            aliases: ['CVE-2021-99999'],
        }];

        await enrichWithNvd(vulns, cache);
        expect(vulns[0].cvssScore).toBe(9.1);
    });
});

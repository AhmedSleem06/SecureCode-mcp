import { describe, it, expect } from 'vitest';
import { testOnlyLabel, isTestHelperName } from '../src/attack/testCodeLabel';

function synaraConfig(): string[] {
    const lines: string[] = Array.from({ length: 242 }, (_, i) => `// prod line ${i + 1}`);
    lines.push('export class ServerConfig extends ServiceMap.Service<ServerConfig, ServerConfigShape>()(');
    lines.push('  "t3/config/ServerConfig",');
    lines.push(') {');
    lines.push('  static readonly layerTest = (');
    lines.push('    cwd: string,');
    lines.push('    baseDirOrOverrides: string | Partial<ServerConfigShape>,');
    lines.push('  ) =>');
    lines.push('    Layer.effect(');
    lines.push('      ServerConfig,');
    lines.push('      Effect.gen(function* () {');
    while (lines.length < 299) {
        const n = lines.length + 1;
        lines.push(n === 287 ? '          authToken: undefined,' : `          field${n}: value${n},`);
    }
    lines.push('      }),');
    lines.push('    );');
    lines.push('}');
    return lines;
}

const PROD = [
    'import express from "express";',
    '',
    'export function createApp() {',
    '  const app = express();',
    '  app.use(express.json());',
    '  app.get("/health", (req, res) => {',
    '    res.json({ ok: true });',
    '  });',
    '  const token = process.env.AUTH_TOKEN;',
    '  if (!token) throw new Error("missing token");',
    '  return app;',
    '}',
];

describe('testOnlyLabel — test paths', () => {
    it.each(['src/foo.test.ts', 'tests/x.ts', 'src/__tests__/a.ts', 'fixtures/a.ts', 'src/foo.spec.tsx', 'app/test_views.py'])(
        'labels %s',
        (p) => {
            expect(testOnlyLabel(p, PROD, 10)).toBe('[TEST-ONLY CODE: test file — not production behaviour]');
        },
    );

    it.each(['src/latest/x.ts', 'src/contest.ts', 'src/attestation.ts', 'src/testimonials/a.ts'])('does not label %s', (p) => {
        expect(testOnlyLabel(p, PROD, 10)).toBeNull();
    });
});

describe('testOnlyLabel — test helpers in prod files', () => {
    it('labels a read inside ServerConfig.layerTest', () => {
        const lines = synaraConfig();
        expect(lines[245]).toBe('  static readonly layerTest = (');
        expect(lines[286]).toContain('authToken: undefined');
        const label = testOnlyLabel('apps/server/src/config.ts', lines, 280, 300);
        expect(label).toBe('[TEST-ONLY CODE: inside layerTest (line 246) — not production behaviour]');
    });

    it('labels a read starting exactly on the helper declaration', () => {
        expect(testOnlyLabel('apps/server/src/config.ts', synaraConfig(), 246, 260)).toContain('inside layerTest (line 246)');
    });

    it('notes a test helper that starts later in the read range', () => {
        expect(testOnlyLabel('apps/server/src/config.ts', synaraConfig(), 240, 290))
            .toBe('[CONTAINS TEST-ONLY CODE: layerTest starts at line 246 — code inside it is not production behaviour]');
    });

    it('does not label a read after the helper has closed', () => {
        const lines = [
            'export class Cfg {',
            '  static readonly layerTest = (x: string) => ({',
            '    authToken: undefined,',
            '  });',
            '  static readonly layer = Layer.effect(',
            '    Cfg,',
            '    loadConfig(),',
            '  );',
            '}',
        ];
        expect(testOnlyLabel('src/cfg.ts', lines, 6, 7)).toBeNull();
    });

    it('follows expression-bodied arrows and chained calls across lines', () => {
        const lines = [
            'export class Cfg {',
            '  static readonly layerTest =',
            '    (x: string) =>',
            '      Layer.succeed(Cfg, { authToken: undefined })',
            '        .pipe(',
            '          Layer.provide(Base),',
            '        );',
            '  static readonly layer = Layer.effect(',
            '    Cfg,',
            '    loadConfig(),',
            '  );',
            '}',
        ];
        expect(testOnlyLabel('src/cfg.ts', lines, 6, 6)).toContain('inside layerTest (line 2)');
        expect(testOnlyLabel('src/cfg.ts', lines, 4, 4)).toContain('inside layerTest (line 2)');
        expect(testOnlyLabel('src/cfg.ts', lines, 10, 10)).toBeNull();
    });

    it('labels mock/fake factories', () => {
        const lines = [
            'export const createMockDb = () => ({',
            '  query: async () => [],',
            '  close: () => {},',
            '});',
        ];
        expect(testOnlyLabel('src/db.ts', lines, 2, 3)).toContain('inside createMockDb (line 1)');
    });

    it('labels python test functions by indentation', () => {
        const lines = [
            'import os',
            '',
            'def test_login_defaults():',
            '    token = None',
            '    assert login(token)',
            '',
            'def login(token):',
            '    return token == os.environ["TOKEN"]',
        ];
        expect(testOnlyLabel('app/auth.py', lines, 5, 5)).toContain('inside test_login_defaults (line 3)');
        expect(testOnlyLabel('app/auth.py', lines, 8, 8)).toBeNull();
    });

    it('returns null for an ordinary prod read', () => {
        expect(testOnlyLabel('src/app.ts', PROD, 10, 12)).toBeNull();
    });

    it('returns null for prod names that merely contain test/mock substrings', () => {
        const lines = [
            'export function isTestMode() {',
            '  return process.env.NODE_ENV === "test";',
            '}',
            'export async function runTests(req, res) {',
            '  const contestEntry = await db.contest.find(req.params.id);',
            '  const attestation = await verify(contestEntry);',
            '  const latest = attestation.latest;',
            '  return res.json({ latest });',
            '}',
            'export async function testConnection() {',
            '  return db.ping();',
            '}',
        ];
        expect(testOnlyLabel('src/server.ts', lines, 2, 2)).toBeNull();
        expect(testOnlyLabel('src/server.ts', lines, 6, 8)).toBeNull();
        expect(testOnlyLabel('src/server.ts', lines, 11, 11)).toBeNull();
        expect(testOnlyLabel('src/server.ts', lines, 1, lines.length)).toBeNull();
    });

    it('ignores test-helper names in comments', () => {
        const lines = ['// static readonly layerTest = (', 'export function handler() {', '  return 1;', '}'];
        expect(testOnlyLabel('src/h.ts', lines, 3, 3)).toBeNull();
    });
});

describe('isTestHelperName', () => {
    it.each(['layerTest', 'createMockDb', 'makeTestServer', 'mockServer', 'fakeClock', 'TestLayer', 'dbFixture', 'httpStub', 'resetForTesting', 'test_login'])(
        'accepts %s',
        (n) => expect(isTestHelperName(n)).toBe(true),
    );

    it.each(['isTestMode', 'runTests', 'contestEntry', 'attestation', 'latest', 'testConnection', 'Testimonial', 'Mockup', 'Faker', 'isMock', 'useFixture'])(
        'rejects %s',
        (n) => expect(isTestHelperName(n)).toBe(false),
    );
});

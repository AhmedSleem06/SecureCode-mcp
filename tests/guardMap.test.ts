import { describe, it, expect } from 'vitest';
import { buildGuardMap } from '../src/attack/guardMap';

function fileWith(entries: Record<number, string>, length = 3000): string {
    const lines = Array.from({ length }, (_, i) => `const v${i + 1} = ${i + 1};`);
    for (const [line, text] of Object.entries(entries)) lines[Number(line) - 1] = text;
    return lines.join('\n');
}

describe('buildGuardMap', () => {
    it('lists use sites of authorization checks with 1-based line numbers', () => {
        const code = fileWith({
            1: "import { requireWsOwnerSession, isOwner } from './auth';",
            10: 'export const requireWsOwnerSession = Effect.gen(function* () {',
            20: 'function requireOwner(req) {',
            30: 'const checkPermission = (user, perm) => user.perms.includes(perm);',
            1290: '    yield* requireWsOwnerSession;',
            2296: '  handler: requireWsOwnerSession.pipe(Effect.flatMap(run)),',
            2333: '  if (!isOwner(user, doc)) throw new Forbidden();',
            2400: '  requireOwner(req); checkPermission(user, "write");',
            2401: '  yield* requireWsOwnerSession; yield* requireWsOwnerSession;',
        });

        const map = buildGuardMap(code);
        const lines = map.split('\n');

        expect(lines[0]).toBe('Authorization checks used in this file:');
        expect(lines[1]).toBe('requireWsOwnerSession: used at 1290, 2296, 2401 (4 uses)');
        expect(map).toContain('isOwner: used at 2333 (1 use)');
        expect(map).toContain('requireOwner: used at 2400 (1 use)');
        expect(map).toContain('checkPermission: used at 2400 (1 use)');
        expect(map).not.toMatch(/\b(1|10|20|30),/);
        expect(map).not.toMatch(/used at (1|10|20|30) /);
    });

    it('skips comments, multi-line imports, re-exports and method definitions', () => {
        const code = [
            'import {',
            '    requireAdminRole,',
            '} from "./auth";',
            '// requireAdminRole(req) is called below',
            '/*',
            ' * requireAdminRole(req)',
            ' */',
            'export { requireAdminRole } from "./auth";',
            'class Guard {',
            '    requireAdminRole(req: Request): void {',
            '    }',
            '}',
            'requireAdminRole(req); // requireAdminRole again',
        ].join('\n');

        expect(buildGuardMap(code)).toBe('Authorization checks used in this file:\nrequireAdminRole: used at 13 (1 use)');
    });

    it('returns an empty string when the file has no authorization checks', () => {
        expect(buildGuardMap('const a = 1;\nfunction requireOwner() {}\n// isAdmin(user)\n')).toBe('');
    });

    it('sorts by use count and caps identifiers and line numbers', () => {
        const lines: string[] = [];
        for (let i = 0; i < 40; i++) lines.push('requireOwner(req);');
        for (let k = 0; k < 15; k++) {
            for (let j = 0; j <= k; j++) lines.push(`checkRole${String.fromCharCode(65 + k)}Access(user);`);
        }
        const map = buildGuardMap(lines.join('\n'), 10_000);
        const out = map.split('\n');

        expect(out[1]).toMatch(/^requireOwner: used at 1, 2, .*, 30, … \(40 uses\)$/);
        expect(out[1].split(', ').length).toBe(31);
        expect(out[2]).toMatch(/^checkRoleOAccess: .*\(15 uses\)$/);
        expect(out).toHaveLength(1 + 12 + 1);
        expect(out[out.length - 1]).toBe('… 4 more');
    });

    it('respects maxChars', () => {
        const lines: string[] = [];
        for (let k = 0; k < 12; k++) {
            for (let j = 0; j < 30; j++) lines.push(`verifyAdmin${String.fromCharCode(65 + k)}Session(user);`);
        }
        const map = buildGuardMap(lines.join('\n'), 400);

        expect(map.length).toBeLessThanOrEqual(400);
        expect(map.startsWith('Authorization checks used in this file:\nverifyAdminASession: used at 1, 2,')).toBe(true);
        expect(map.endsWith('…')).toBe(true);
    });
});

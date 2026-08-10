import { describe, it, expect } from 'vitest';
import { trackTaint } from '../src/project-map/taintTracker';

describe('Taint Propagation Tracker', () => {

    // ── Direct flow ──────────────────────────────────────────────────────

    it('detects direct flow: const q = req.body.q; exec(q)', async () => {
        const code = `const q = req.body.q;
exec(q);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.body.q');
        expect(results[0].sink).toBe('exec');
        expect(results[0].isTainted).toBe(true);
        expect(results[0].canonicalType).toBe('command_injection');
    });

    it('detects direct flow into db.query with concatenation', async () => {
        const code = `const id = req.body.id;
db.query("SELECT * FROM users WHERE id = " + id);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.body.id');
        expect(results[0].sink).toBe('sql-concat');
        expect(results[0].canonicalType).toBe('sql_injection');
    });

    // ── Indirect flow ─────────────────────────────────────────────────────

    it('detects indirect flow through multiple assignments', async () => {
        const code = `const q = req.body.q;
const x = q;
const y = x;
exec(y);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.body.q');
        expect(results[0].propagationPath.length).toBeGreaterThanOrEqual(3);
    });

    // ── Template literal ───────────────────────────────────────────────────

    it('detects taint through template interpolation', async () => {
        const code = [
            'db.query(`SELECT * FROM users WHERE id = ${req.body.id}`);',
        ].join('\n');
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.body.id');
        expect(results[0].canonicalType).toBe('sql_injection');
    });

    // ── Sanitized (NOT tainted) ────────────────────────────────────────────

    it('does NOT flag sanitized flow: parseInt strips taint', async () => {
        const code = `const q = req.body.q;
const id = parseInt(q);
db.query("SELECT * FROM users WHERE id = " + id);`;
        const results = await trackTaint(code, 'javascript');
        // parseInt strips taint → no taint reaches the sink
        expect(results).toHaveLength(0);
    });

    it('does NOT flag Number() sanitizer', async () => {
        const code = `const q = req.body.q;
const id = Number(q);
db.query("SELECT * FROM users WHERE id = " + id);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(0);
    });

    // ── No flow (hardcoded) ────────────────────────────────────────────────

    it('does NOT flag hardcoded string', async () => {
        const code = `const q = "hardcoded";
exec(q);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(0);
    });

    it('does NOT flag when source and sink are unrelated', async () => {
        const code = `const q = req.body.q;
const cmd = "ls -la";
exec(cmd);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(0);
    });

    // ── Destructuring ──────────────────────────────────────────────────────

    it('detects taint through destructuring', async () => {
        const code = `const { q } = req.body;
exec(q);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.body');
    });

    // ── Member access propagation ─────────────────────────────────────────

    it('detects taint through member access: const x = req.body; exec(x.q)', async () => {
        const code = `const x = req.body;
exec(x.q);`;
        const results = await trackTaint(code, 'javascript');
        // x is tainted (from req.body), and x.q is a member access on tainted x
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.body');
    });

    // ── Different source types ─────────────────────────────────────────────

    it('detects req.query source', async () => {
        const code = `const q = req.query.q;
exec(q);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.query.q');
    });

    it('detects req.params source', async () => {
        const code = `const id = req.params.id;
db.query("SELECT * FROM users WHERE id = " + id);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.params.id');
    });

    it('detects req.headers source', async () => {
        const code = `const token = req.headers.authorization;
res.redirect(token);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.headers.authorization');
    });

    // ── Inside function ────────────────────────────────────────────────────

    it('detects taint inside a function body', async () => {
        const code = `function handler(req, res) {
  const q = req.body.q;
  exec(q);
}`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].source).toBe('req.body.q');
    });

    // ── Inter-function (taint-returning function) ──────────────────────────

    it('detects inter-function taint through return', async () => {
        const code = `function getInput(req) {
  return req.body.q;
}
const q = getInput(req);
exec(q);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        expect(results[0].isTainted).toBe(true);
    });

    // ── Multiple sinks ─────────────────────────────────────────────────────

    it('detects multiple tainted sinks in one function', async () => {
        const code = `const q = req.body.q;
const url = req.query.url;
exec(q);
res.redirect(url);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(2);
        const types = results.map(r => r.canonicalType).sort();
        expect(types).toContain('command_injection');
        expect(types).toContain('open_redirect');
    });

    // ── Python ──────────────────────────────────────────────────────────────

    it('detects Python request.GET taint', async () => {
        const code = `q = request.GET.get('q')
os.system(q)`;
        const results = await trackTaint(code, 'python');
        expect(results).toHaveLength(1);
        expect(results[0].isTainted).toBe(true);
    });

    it('detects Python request.args taint', async () => {
        const code = `q = request.args.get('q')
cursor.execute(q)`;
        const results = await trackTaint(code, 'python');
        expect(results).toHaveLength(1);
        expect(results[0].canonicalType).toBe('sql_injection');
    });

    it('does NOT flag Python int() sanitized flow', async () => {
        const code = `q = request.GET.get('q')
id = int(q)
cursor.execute("SELECT * FROM users WHERE id = " + str(id))`;
        const results = await trackTaint(code, 'python');
        // int() strips taint → no taint reaches the sink
        expect(results).toHaveLength(0);
    });

    it('does NOT flag Python hardcoded string', async () => {
        const code = `q = "hardcoded"
os.system(q)`;
        const results = await trackTaint(code, 'python');
        expect(results).toHaveLength(0);
    });

    // ── Graceful degradation ────────────────────────────────────────────────

    it('returns empty array for empty source', async () => {
        const results = await trackTaint('', 'javascript');
        expect(results).toEqual([]);
    });

    it('returns empty array when no sinks present', async () => {
        const code = `const q = req.body.q;
console.log(q);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toEqual([]);
    });

    it('returns empty array when no sources present', async () => {
        const code = `const q = "hello";
exec(q);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toEqual([]);
    });

    // ── Propagation path ───────────────────────────────────────────────────

    it('records full propagation path from source to sink', async () => {
        const code = `const q = req.body.q;
const x = q;
exec(x);`;
        const results = await trackTaint(code, 'javascript');
        expect(results).toHaveLength(1);
        const path = results[0].propagationPath;
        expect(path.length).toBeGreaterThanOrEqual(3);
        expect(path[0].operation).toBe('source');
        expect(path[path.length - 1].operation).toBe('sink-arg');
    });
});

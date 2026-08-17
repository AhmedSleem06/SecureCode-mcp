import { describe, it, expect } from 'vitest';
import { evaluateGuard } from '../src/project-map/guardEvaluator';

describe('Guard Effectiveness Evaluator', () => {

    // ── Sanitizer-numeric ──────────────────────────────────────────────────

    it('parseInt is effective against SQL injection', async () => {
        const guard = `function sanitize(x) { return parseInt(x, 10); }`;
        const result = await evaluateGuard(guard, 'sanitize', 'sql_injection', 'javascript');
        expect(result.effective).toBe(true);
        expect(result.guardType).toBe('sanitizer-numeric');
    });

    it('parseInt is effective against XSS', async () => {
        const guard = `function sanitize(x) { return parseInt(x, 10); }`;
        const result = await evaluateGuard(guard, 'sanitize', 'xss', 'javascript');
        expect(result.effective).toBe(true);
    });

    it('parseInt is effective against command injection', async () => {
        const guard = `function sanitize(x) { return parseInt(x, 10); }`;
        const result = await evaluateGuard(guard, 'sanitize', 'command_injection', 'javascript');
        expect(result.effective).toBe(true);
    });

    // ── Sanitizer-html ─────────────────────────────────────────────────────

    it('escapeHtml is effective against XSS', async () => {
        const guard = `function escapeHtml(x) { return escape(x); }`;
        const result = await evaluateGuard(guard, 'escapeHtml', 'xss', 'javascript');
        expect(result.effective).toBe(true);
        expect(result.guardType).toBe('sanitizer-html');
    });

    it('escapeHtml is NOT effective against SQL injection', async () => {
        const guard = `function escapeHtml(x) { return escape(x); }`;
        const result = await evaluateGuard(guard, 'escapeHtml', 'sql_injection', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.bypassExample).toBeDefined();
    });

    it('escape is NOT effective against command injection', async () => {
        const guard = `function clean(x) { return escape(x); }`;
        const result = await evaluateGuard(guard, 'clean', 'command_injection', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.bypassExample).toBeDefined();
    });

    // ── Parameterized query ───────────────────────────────────────────────

    it('parameterized query is effective against SQL injection', async () => {
        const guard = `function safeQuery(db, id) {
  return db.query("SELECT * FROM users WHERE id = ?", [id]);
}`;
        const result = await evaluateGuard(guard, 'safeQuery', 'sql_injection', 'javascript');
        expect(result.effective).toBe(true);
        expect(result.guardType).toBe('parameterized-query');
    });

    // ── Auth: JWT ──────────────────────────────────────────────────────────

    it('jwt.verify with algorithm pinning is NOT effective against access control (auth != authorization)', async () => {
        const guard = `function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  jwt.verify(token, SECRET, { algorithms: ['HS256'] });
  next();
}`;
        const result = await evaluateGuard(guard, 'requireAuth', 'broken_access_control', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.guardType).toBe('auth-jwt-verify');
    });

    it('jwt.verify WITHOUT algorithm pinning is NOT effective against access control', async () => {
        const guard = `function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  jwt.verify(token, SECRET);
  next();
}`;
        const result = await evaluateGuard(guard, 'requireAuth', 'broken_access_control', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.guardType).toBe('auth-jwt-verify-noalg');
        expect(result.bypassExample).toBeDefined();
    });

    // ── Auth: session ──────────────────────────────────────────────────────

    it('session check is NOT effective against access control (auth != authorization)', async () => {
        const guard = `function requireLogin(req, res, next) {
  if (!req.session.user) return res.status(401).send();
  next();
}`;
        const result = await evaluateGuard(guard, 'requireLogin', 'broken_access_control', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.guardType).toBe('auth-session');
    });

    // ── Auth: API key ─────────────────────────────────────────────────────

    it('API key check is NOT effective against access control (auth != authorization)', async () => {
        const guard = `function requireApiKey(req, res, next) {
  if (!req.headers['x-api-key']) return res.status(401).send();
  next();
}`;
        const result = await evaluateGuard(guard, 'requireApiKey', 'broken_access_control', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.guardType).toBe('auth-api-key');
    });

    // ── Allowlist ──────────────────────────────────────────────────────────

    it('literal allowlist is effective against SQL injection', async () => {
        const guard = `function validate(x) {
  if (['name', 'email', 'id'].includes(x)) return x;
  throw new Error('invalid');
}`;
        const result = await evaluateGuard(guard, 'validate', 'sql_injection', 'javascript');
        expect(result.effective).toBe(true);
        expect(result.guardType).toBe('allowlist-literal');
    });

    // ── Helmet ────────────────────────────────────────────────────────────

    it('helmet is NOT effective against XSS', async () => {
        const guard = `function setup(app) { app.use(helmet()); }`;
        const result = await evaluateGuard(guard, 'setup', 'xss', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.guardType).toBe('helmet');
        expect(result.bypassExample).toBeDefined();
    });

    // ── Rate limiting ────────────────────────────────────────────────────

    it('rate limiting is NOT effective against access control', async () => {
        const guard = `function setup(app) {
  const limiter = rateLimit({ windowMs: 60000, max: 100 });
  app.use(limiter);
}`;
        const result = await evaluateGuard(guard, 'setup', 'broken_access_control', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.guardType).toBe('rate-limit');
    });

    // ── CORS permissive ───────────────────────────────────────────────────

    it('permissive CORS is NOT effective against access control', async () => {
        const guard = `function setup(app) {
  app.use(cors({ origin: '*' }));
}`;
        const result = await evaluateGuard(guard, 'setup', 'broken_access_control', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.guardType).toBe('cors-permissive');
    });

    // ── Unknown guard ─────────────────────────────────────────────────────

    it('unknown guard returns effective=false with reason', async () => {
        const guard = `function doSomething(x) { return x + 1; }`;
        const result = await evaluateGuard(guard, 'doSomething', 'sql_injection', 'javascript');
        expect(result.effective).toBe(false);
        expect(result.guardType).toBe('unknown');
        expect(result.reason).toContain('unknown');
    });

    // ── Python guards ─────────────────────────────────────────────────────

    it('Python int() is effective against SQL injection', async () => {
        const guard = `def sanitize(x):
    return int(x)`;
        const result = await evaluateGuard(guard, 'sanitize', 'sql_injection', 'python');
        expect(result.effective).toBe(true);
        expect(result.guardType).toBe('sanitizer-numeric');
    });

    it('Python markupsafe.escape is effective against XSS', async () => {
        const guard = `def clean(x):
    return markupsafe.escape(x)`;
        const result = await evaluateGuard(guard, 'clean', 'xss', 'python');
        expect(result.effective).toBe(true);
        expect(result.guardType).toBe('sanitizer-html');
    });

    // ── GuardEvaluation output ────────────────────────────────────────────

    it('returns all required fields', async () => {
        const guard = `function f(x) { return parseInt(x, 10); }`;
        const result = await evaluateGuard(guard, 'f', 'sql_injection', 'javascript');
        expect(result).toHaveProperty('guardName', 'f');
        expect(result).toHaveProperty('guardType');
        expect(result).toHaveProperty('attackType', 'sql_injection');
        expect(result).toHaveProperty('effective');
        expect(result).toHaveProperty('reason');
    });
});

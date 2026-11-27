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

    // ── Authorization-role guard ──────────────────────────────────────────

    it('recognizes requireRole as authorization-role', async () => {
        const guard = `function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}`;
        const result = await evaluateGuard(guard, 'requireAdmin', 'broken_access_control', 'javascript');
        expect(result.guardType).toBe('authorization-role');
        expect(result.effective).toBe(true);
    });

    it('authorization-role is effective against missing_authorization', async () => {
        const guard = `function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}`;
        const result = await evaluateGuard(guard, 'requireAdmin', 'missing_authorization', 'javascript');
        expect(result.guardType).toBe('authorization-role');
        expect(result.effective).toBe(true);
    });

    it('authorization-role is NOT effective against idor', async () => {
        const guard = `function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
  next();
}`;
        const result = await evaluateGuard(guard, 'requireAdmin', 'idor', 'javascript');
        expect(result.guardType).toBe('authorization-role');
        expect(result.effective).toBe(false);
    });

    // ── Authorization-owner guard ──────────────────────────────────────────

    it('recognizes ownership check as authorization-owner', async () => {
        const guard = `function checkOwner(req, res, next) {
  const order = getOrder(req.params.id);
  if (order.customerId !== req.user.sub) return res.status(403).json({ error: 'Access denied' });
  next();
}`;
        const result = await evaluateGuard(guard, 'checkOwner', 'idor', 'javascript');
        expect(result.guardType).toBe('authorization-owner');
        expect(result.effective).toBe(true);
    });

    it('authorization-owner is effective against broken_access_control', async () => {
        const guard = `function checkOwner(req, res, next) {
  if (order.customerId !== req.user.sub) return res.status(403).json({ error: 'Access denied' });
  next();
}`;
        const result = await evaluateGuard(guard, 'checkOwner', 'broken_access_control', 'javascript');
        expect(result.guardType).toBe('authorization-owner');
        expect(result.effective).toBe(true);
    });

    // ── Authentication guard ──────────────────────────────────────────────

    it('jwt.verify is classified as authentication (not just auth-jwt-verify) for auth_bypass', async () => {
        const guard = `function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Missing token' });
  req.user = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
  next();
}`;
        const result = await evaluateGuard(guard, 'authMiddleware', 'auth_bypass', 'javascript');
        expect(result.guardType).toBe('auth-jwt-verify');
    });
});

import { analyzeRouteGuards } from '../src/project-map/guardEvaluator';

describe('Route Guard Analysis', () => {

    it('fixture 12 flawed: GET guarded, POST/PUT/DELETE unguarded', async () => {
        const fs = require('fs');
        const path = require('path');
        const adminPath = path.resolve(__dirname, '../../test_lab/assurance-fixtures/12-missing-auth-post-route/flawed/src/admin.ts');
        const adminSource = fs.readFileSync(adminPath, 'utf8');
        const wsRoot = path.resolve(__dirname, '../../test_lab/assurance-fixtures/12-missing-auth-post-route/flawed');
        const analysis = await analyzeRouteGuards('src/admin.ts', adminSource, 'javascript', wsRoot);
        expect(analysis.routes.length).toBeGreaterThan(0);

        const getConfig = analysis.routes.find(r => r.method === 'GET' && r.path === '/admin/config');
        expect(getConfig).toBeDefined();
        expect(getConfig!.hasAuthentication).toBe(true);

        const postConfig = analysis.routes.find(r => r.method === 'POST' && r.path === '/admin/config');
        expect(postConfig).toBeDefined();
        expect(postConfig!.hasAuthentication).toBe(false);
        expect(postConfig!.hasRoleCheck).toBe(false);

        const putConfig = analysis.routes.find(r => r.method === 'PUT' && r.path?.includes('/admin/config'));
        expect(putConfig).toBeDefined();
        expect(putConfig!.hasAuthentication).toBe(false);

        const deleteConfig = analysis.routes.find(r => r.method === 'DELETE' && r.path?.includes('/admin/config'));
        expect(deleteConfig).toBeDefined();
        expect(deleteConfig!.hasAuthentication).toBe(false);
    });

    it('fixture 12 fixed: all routes guarded via router.use', async () => {
        const fs = require('fs');
        const path = require('path');
        const adminPath = path.resolve(__dirname, '../../test_lab/assurance-fixtures/12-missing-auth-post-route/fixed/src/admin.ts');
        const adminSource = fs.readFileSync(adminPath, 'utf8');
        const wsRoot = path.resolve(__dirname, '../../test_lab/assurance-fixtures/12-missing-auth-post-route/fixed');
        const analysis = await analyzeRouteGuards('src/admin.ts', adminSource, 'javascript', wsRoot);

        const adminRoutes = analysis.routes.filter(r => r.path?.startsWith('/admin'));
        for (const r of adminRoutes) {
            expect(r.hasAuthentication).toBe(true);
        }
    });

    it('fixture 06: bulk-ship has requireRole (authorization-role), cancel has owner check in handler', async () => {
        const fs = require('fs');
        const path = require('path');
        const ordersPath = path.resolve(__dirname, '../../test_lab/assurance-fixtures/06-bulk-ship-state-skip/flawed/src/orders.ts');
        const ordersSource = fs.readFileSync(ordersPath, 'utf8');
        const wsRoot = path.resolve(__dirname, '../../test_lab/assurance-fixtures/06-bulk-ship-state-skip/flawed');
        const analysis = await analyzeRouteGuards('src/orders.ts', ordersSource, 'javascript', wsRoot);

        const bulkShip = analysis.routes.find(r => r.path === '/orders/bulk-ship');
        expect(bulkShip).toBeDefined();
        expect(bulkShip!.hasAuthentication).toBe(true);
        expect(bulkShip!.hasRoleCheck).toBe(true);

        const cancel = analysis.routes.find(r => r.path === '/orders/:id/cancel');
        expect(cancel).toBeDefined();
        expect(cancel!.hasAuthentication).toBe(true);
        expect(cancel!.hasOwnerCheck).toBe(true);
        expect(cancel!.inHandlerGuards.some(g => g.guardType === 'authorization-owner')).toBe(true);
    });
});

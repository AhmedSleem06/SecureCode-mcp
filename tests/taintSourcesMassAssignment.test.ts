import { describe, it, expect } from 'vitest';
import { trackTaint } from '../src/project-map/taintTracker';

describe('Taint Sources — mass assignment / privilege escalation', () => {

    it('detects destructured req.body field assigned to object property: user.role = role', async () => {
        const code = `
app.put('/users/me', (req, res) => {
    const { username, email, role, plan } = req.body;
    const user = getUser(req.userId);
    if (username) user.username = username;
    if (email) user.email = email;
    if (role) user.role = role;
    if (plan) user.plan = plan;
    save(user);
    res.json(user);
});`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBeGreaterThanOrEqual(2);
        const sinkProps = massAssign.map(r => r.sink);
        expect(sinkProps).toContain('mass-assignment');
    });

    it('detects req.body.role assigned to object property directly', async () => {
        const code = `
app.put('/profile', (req, res) => {
    const role = req.body.role;
    const user = findUser(req.userId);
    user.role = role;
    save(user);
});`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBeGreaterThanOrEqual(1);
    });

    it('detects nested destructuring: const { profile: { role } } = req.body', async () => {
        const code = `
const body = req.body;
const role = body.role;
user.role = role;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBeGreaterThanOrEqual(1);
    });

    it('detects const body = req.body; body.role → user.role = body.role', async () => {
        const code = `
const body = req.body;
user.role = body.role;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBeGreaterThanOrEqual(1);
    });

    it('detects multiple privilege-sensitive properties: isAdmin, permissions, balance', async () => {
        const code = `
const { isAdmin, permissions, balance } = req.body;
user.isAdmin = isAdmin;
user.permissions = permissions;
user.balance = balance;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBe(3);
    });

    it('does NOT flag when hardcoded value is assigned', async () => {
        const code = `
user.role = 'member';
user.isAdmin = false;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBe(0);
    });

    it('detects request.body destructuring (generic request)', async () => {
        const code = `
const { role } = request.body;
user.role = role;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBeGreaterThanOrEqual(1);
    });

    it('detects ctx.request.body destructuring (Koa-style)', async () => {
        const code = `
const { role } = ctx.request.body;
user.role = role;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBeGreaterThanOrEqual(1);
    });

    it('detects req.query mass assignment into status', async () => {
        const code = `
const { status } = req.query;
user.status = status;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBeGreaterThanOrEqual(1);
    });

    it('reports mass-assignment flows with source pointing to req.body', async () => {
        const code = `
const { role } = req.body;
user.role = role;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBe(1);
        expect(massAssign[0].source).toBe('req.body');
        expect(massAssign[0].isTainted).toBe(true);
        expect(massAssign[0].propagationPath.length).toBeGreaterThanOrEqual(2);
    });

    it('fixture: trimmed users.ts role-escalation pattern', async () => {
        const code = `
import { Router } from 'express';
const router = Router();

function requireAuth(req: any, res: any, next: any) {
    if (!req.headers.authorization) return res.status(401).json({ error: 'Unauthorized' });
    next();
}

function requireAdmin(req: any, res: any, next: any) {
    if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    next();
}

router.put('/users/me', requireAuth, (req, res) => {
    const { username, email, role, plan } = req.body;
    const user = { username: 'old', email: 'old@e.com', role: 'member', plan: 'free' };
    if (username) user.username = username;
    if (email) user.email = email;
    if (role) user.role = role;
    if (plan) user.plan = plan;
    res.json(user);
});

export default router;`;
        const results = await trackTaint(code, 'typescript');
        const massAssign = results.filter(r => r.canonicalType === 'mass_assignment');
        expect(massAssign.length).toBeGreaterThanOrEqual(2);
        const roleFlow = massAssign.find(r =>
            r.propagationPath.some(p => p.variable.includes('role')),
        );
        expect(roleFlow).toBeDefined();
    });
});

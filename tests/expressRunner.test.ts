import { describe, it, expect, beforeEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { spawnSync } from 'child_process';

function runInFreshProcess(scriptBody: string, fixtureFiles?: Record<string, string>): { stdout: string; stderr: string; exitCode: number } {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-runner-test-'));
  try {
    const harnessSource = path.resolve(__dirname, '../src/assurance/harness/expressRunner.cjs');
    fs.copyFileSync(harnessSource, path.join(tmpDir, 'expressRunner.cjs'));

    if (fixtureFiles) {
      for (const [name, content] of Object.entries(fixtureFiles)) {
        const filePath = path.join(tmpDir, name);
        fs.mkdirSync(path.dirname(filePath), { recursive: true });
        fs.writeFileSync(filePath, content, 'utf8');
      }
    }

    const testFile = path.join(tmpDir, 'test.cjs');
    fs.writeFileSync(testFile, scriptBody, 'utf8');

    const r = spawnSync(process.execPath, [testFile], {
      cwd: tmpDir,
      timeout: 15_000,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { NODE_ENV: 'test', PATH: process.env.PATH || '', PATHEXT: process.env.PATHEXT || '', SystemRoot: process.env.SystemRoot || '' },
    });

    return {
      stdout: r.stdout?.toString('utf8') || '',
      stderr: r.stderr?.toString('utf8') || '',
      exitCode: r.status ?? -1,
    };
  } finally {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  }
}

describe('expressRunner.cjs', () => {
  describe('single handler', () => {
    it('invokes a sync GET handler and returns the response', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/hello', { query: { name: 'world' } });
          const out = { sent: res.sent, status: res.status, body: res.body, timedOut: res.timedOut };
          console.log(JSON.stringify(out));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();
          app.get('/hello', (req, res) => {
            res.json({ greeting: 'Hello ' + (req.query.name || 'stranger') });
          });
          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(200);
      expect(out.body).toEqual({ greeting: 'Hello world' });
      expect(out.timedOut).toBe(false);
    });

    it('reports status as undefined before any send method runs', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/hang');
          console.log(JSON.stringify({ sent: res.sent, status: res.status, timedOut: res.timedOut }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();
          app.get('/hang', (req, res, next) => {
            // calls next without sending
            next();
          });
          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(false);
    });
  });

  describe('middleware chain with async handler', () => {
    it('runs middleware before the route handler and awaits async', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('POST', '/api/data', {
            headers: { authorization: 'Bearer valid-token' },
            body: { value: 42 }
          });
          console.log(JSON.stringify({ sent: res.sent, status: res.status, body: res.body }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();

          // auth middleware
          app.use((req, res, next) => {
            if (req.headers.authorization === 'Bearer valid-token') {
              req.user = { id: 1, role: 'admin' };
              next();
            } else {
              res.status(401).json({ error: 'unauthorized' });
            }
          });

          app.post('/api/data', async (req, res) => {
            // simulate async work
            await new Promise(r => setTimeout(r, 50));
            res.json({ saved: true, userId: req.user.id, value: req.body.value });
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(200);
      expect(out.body).toEqual({ saved: true, userId: 1, value: 42 });
    });

    it('middleware can short-circuit and block the route handler', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('POST', '/api/data', {
            headers: { authorization: 'Bearer bad-token' },
            body: { value: 42 }
          });
          console.log(JSON.stringify({ sent: res.sent, status: res.status, body: res.body }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();

          app.use((req, res, next) => {
            if (req.headers.authorization === 'Bearer valid-token') {
              req.user = { id: 1 };
              next();
            } else {
              res.status(401).json({ error: 'unauthorized' });
            }
          });

          app.post('/api/data', async (req, res) => {
            res.json({ saved: true });
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(401);
      expect(out.body).toEqual({ error: 'unauthorized' });
    });
  });

  describe('error middleware', () => {
    it('catches a thrown error and passes to error middleware', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/boom');
          console.log(JSON.stringify({ sent: res.sent, status: res.status, body: res.body }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();

          app.get('/boom', (req, res) => {
            throw new Error('kaboom');
          });

          app.use((err, req, res, next) => {
            res.status(500).json({ error: err.message });
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(500);
      expect(out.body).toEqual({ error: 'kaboom' });
    });

    it('uncaught error without error middleware results in 500', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/boom');
          console.log(JSON.stringify({ sent: res.sent, status: res.status, error: res.error }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();

          app.get('/boom', (req, res) => {
            throw new Error('kaboom');
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(500);
      expect(out.error).toBe('kaboom');
    });

    it('async rejection is caught as an error', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('POST', '/async-fail', { body: {} });
          console.log(JSON.stringify({ sent: res.sent, status: res.status, error: res.error }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();

          app.post('/async-fail', async (req, res) => {
            await new Promise((_, reject) => setTimeout(() => reject(new Error('async boom')), 10));
            res.json({ ok: true });
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(500);
      expect(out.error).toBe('async boom');
    });
  });

  describe('sc.mock()', () => {
    it('replaces a dependency before loading the target', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        const calls = [];
        sc.mock('jsonwebtoken', {
          verify: (token, secret) => {
            calls.push({ token, secret });
            if (token === 'good-token') return { sub: 'user1' };
            throw new Error('invalid token');
          },
          sign: (payload, secret) => 'signed-' + payload.sub
        });

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/profile', {
            headers: { authorization: 'Bearer good-token' }
          });
          console.log(JSON.stringify({ status: res.status, body: res.body, calls }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const jwt = require('jsonwebtoken');
          const app = express();

          app.get('/profile', (req, res) => {
            try {
              const token = (req.headers.authorization || '').replace('Bearer ', '');
              const decoded = jwt.verify(token, 'secret');
              res.json({ user: decoded.sub });
            } catch (e) {
              res.status(401).json({ error: 'bad token' });
            }
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.status).toBe(200);
      expect(out.body).toEqual({ user: 'user1' });
      expect(out.calls).toHaveLength(1);
      expect(out.calls[0].token).toBe('good-token');
    });
  });

  describe('sc.routes()', () => {
    it('lists all registered routes', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        console.log(JSON.stringify(sc.routes()));
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();
          app.get('/a', (req, res) => res.send('a'));
          app.post('/b', (req, res) => res.send('b'));
          app.delete('/c/:id', (req, res) => res.send('c'));
          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const routes = JSON.parse(result.stdout.trim());
      expect(routes).toContain('GET /a');
      expect(routes).toContain('POST /b');
      expect(routes).toContain('DELETE /c/:id');
    });
  });

  describe('path params', () => {
    it('matches :name params from the route pattern', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/users/42');
          console.log(JSON.stringify({ status: res.status, body: res.body }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();
          app.get('/users/:id', (req, res) => {
            res.json({ id: req.params.id });
          });
          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.status).toBe(200);
      expect(out.body).toEqual({ id: '42' });
    });
  });

  describe('sendStatus', () => {
    it('sets status and marks sent', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('DELETE', '/item/5');
          console.log(JSON.stringify({ sent: res.sent, status: res.status }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();
          app.delete('/item/:id', (req, res) => {
            res.sendStatus(204);
          });
          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(204);
    });
  });

  describe('multiple middleware in chain', () => {
    it('runs three middleware before the handler in order', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/chain');
          console.log(JSON.stringify({ status: res.status, body: res.body }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();

          app.use((req, res, next) => { req.order = ['mw1']; next(); });
          app.use((req, res, next) => { req.order.push('mw2'); next(); });
          app.use((req, res, next) => { req.order.push('mw3'); next(); });

          app.get('/chain', (req, res) => {
            res.json({ order: req.order });
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.status).toBe(200);
      expect(out.body.order).toEqual(['mw1', 'mw2', 'mw3']);
    });
  });

  describe('the race condition bug (cause 1)', () => {
    it('waits for async handler to finish before resolving', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('POST', '/transfer', {
            headers: { authorization: 'Bearer [REDACTED]' },
            body: { from: 'alice', to: 'bob', amount: 100 }
          });
          console.log(JSON.stringify({
            sent: res.sent,
            status: res.status,
            body: res.body,
            timedOut: res.timedOut
          }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();

          const balances = { alice: 500, bob: 200 };

          app.use((req, res, next) => {
            const token = (req.headers.authorization || '').replace('Bearer ', '');
            if (token === '[REDACTED]') {
              req.user = { name: 'alice' };
              next();
            } else {
              res.status(401).json({ error: 'unauthorized' });
            }
          });

          app.post('/transfer', async (req, res) => {
            await new Promise(r => setTimeout(r, 100));
            const { from, to, amount } = req.body;
            if (balances[from] < amount) {
              return res.status(400).json({ error: 'insufficient funds' });
            }
            balances[from] -= amount;
            balances[to] = (balances[to] || 0) + amount;
            res.json({ success: true, balances: { [from]: balances[from], [to]: balances[to] } });
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(200);
      expect(out.body.success).toBe(true);
      expect(out.timedOut).toBe(false);
    });
  });

  describe('redirect', () => {
    it('handles res.redirect()', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/old');
          console.log(JSON.stringify({ sent: res.sent, status: res.status, headers: res.headers }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();
          app.get('/old', (req, res) => {
            res.redirect(301, '/new');
          });
          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(true);
      expect(out.status).toBe(301);
      expect(out.headers.location).toBe('/new');
    });
  });

  describe('no matching route', () => {
    it('resolves with sent false when no route matches', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/nonexistent');
          console.log(JSON.stringify({ sent: res.sent, status: res.status }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();
          app.get('/exists', (req, res) => res.send('ok'));
          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.sent).toBe(false);
    });
  });

  describe('route-level middleware (multiple handlers on one route)', () => {
    it('runs all handlers passed to app.get(path, mw1, mw2, handler)', () => {
      const result = runInFreshProcess(`
        const sc = require('./expressRunner.cjs');

        sc.load('./app.cjs');

        (async () => {
          const res = await sc.invoke('GET', '/protected');
          console.log(JSON.stringify({ status: res.status, body: res.body }));
        })();
      `, {
        'app.cjs': `
          const express = require('express');
          const app = express();

          function checkAuth(req, res, next) {
            req.authed = true;
            next();
          }
          function checkRole(req, res, next) {
            req.role = 'admin';
            next();
          }

          app.get('/protected', checkAuth, checkRole, (req, res) => {
            res.json({ authed: req.authed, role: req.role });
          });

          app.listen(3000);
        `
      });

      expect(result.exitCode).toBe(0);
      const out = JSON.parse(result.stdout.trim());
      expect(out.status).toBe(200);
      expect(out.body).toEqual({ authed: true, role: 'admin' });
    });
  });
});

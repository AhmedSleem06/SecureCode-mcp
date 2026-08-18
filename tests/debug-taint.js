const { trackTaint } = require('../dist/project-map/taintTracker');

const cases = [
    {
        name: 'Express SQLi',
        code: `app.post('/search', (req, res) => {
  const name = req.body.name;
  db.query('SELECT * FROM users WHERE name = ' + name, (err, rows) => {
    res.json(rows);
  });
});`,
    },
    {
        name: 'Next.js Prisma SQLi (tagged template)',
        code: `export async function POST(req: Request) {
  const body = await req.json();
  const result = await prisma.$queryRaw\`SELECT * FROM users WHERE name = '\${body.name}'\`;
  return Response.json(result);
}`,
    },
    {
        name: 'Next.js Prisma SQLi (unsafe call)',
        code: `export async function POST(req: Request) {
  const body = await req.json();
  const result = await prisma.$queryRawUnsafe('SELECT * FROM users WHERE name = ' + body.name);
  return Response.json(result);
}`,
    },
    {
        name: 'XSS innerHTML',
        code: `export async function POST(req: Request) {
  const body = await req.json();
  const el = document.createElement('div');
  el.innerHTML = body.html;
  return Response.json({ ok: true });
}`,
    },
];

async function main() {
    for (const tc of cases) {
        console.log(`\n=== ${tc.name} ===`);
        try {
            const results = await trackTaint(tc.code, 'typescript');
            if (results.length === 0) {
                console.log('  No flows found');
            } else {
                for (const r of results) {
                    console.log(`  ${r.source} (L${r.sourceLine}) -> ${r.sink} (L${r.sinkLine}) [${r.canonicalType}]`);
                    console.log(`  Path: ${r.propagationPath.map(p => `L${p.line}:${p.operation}`).join(' -> ')}`);
                }
            }
        } catch (err) {
            console.log(`  ERROR: ${err.message}`);
        }
    }
}

main();

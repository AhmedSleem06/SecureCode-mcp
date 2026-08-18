const { parseSource } = require('../dist/project-map/parserLoader');
const { walk } = require('../dist/project-map/astHelpers');

async function main() {
    const code = `export async function POST(req: Request) {
  const body = await req.json();
  const result = await prisma.$queryRawUnsafe('SELECT * FROM users WHERE name = ' + body.name);
  return Response.json(result);
}`;
    const parsed = await parseSource(code, 'typescript');
    if (!parsed) { console.log('PARSE FAILED'); return; }

    console.log('=== All nodes ===');
    for (const node of walk(parsed.root)) {
        const text = code.slice(node.startIndex, node.endIndex).split('\n')[0].slice(0, 80);
        console.log(`  ${node.type} @ L${node.startPosition.row + 1}: ${text}`);
    }
}
main().catch(console.error);

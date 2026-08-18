const { trackTaint } = require('../dist/project-map/taintTracker');
const { parseSource } = require('../dist/project-map/parserLoader');
const { matchTaintSource } = require('../dist/project-map/taintSources');
const { matchSink } = require('../dist/project-map/sinkRegistry');

async function main() {
    // Test 1: Check if matchTaintSource works for new patterns
    console.log('=== matchTaintSource tests ===');
    console.log('req.json (typescript):', matchTaintSource('req.json', 'typescript')?.prefix ?? 'NO MATCH');
    console.log('req.body (typescript):', matchTaintSource('req.body', 'typescript')?.prefix ?? 'NO MATCH');
    console.log('req.body.name (typescript):', matchTaintSource('req.body.name', 'typescript')?.prefix ?? 'NO MATCH');
    console.log('request.json (typescript):', matchTaintSource('request.json', 'typescript')?.prefix ?? 'NO MATCH');

    // Test 2: Check parsing
    console.log('\n=== Parse test ===');
    const code = `export async function POST(req: Request) {
  const body = await req.json();
  const result = await prisma.$queryRawUnsafe('SELECT * FROM users WHERE name = ' + body.name);
  return Response.json(result);
}`;
    const parsed = await parseSource(code, 'typescript');
    console.log('Parsed:', parsed ? 'YES' : 'NO');
    if (parsed) {
        console.log('Root type:', parsed.root.type);
        console.log('Root namedChildren:', parsed.root.namedChildren.map(c => c.type));
    }

    // Test 3: Full trackTaint
    console.log('\n=== trackTaint ===');
    const results = await trackTaint(code, 'typescript');
    console.log('Results:', results.length);
    for (const r of results) {
        console.log(`  ${r.source} L${r.sourceLine} -> ${r.sink} L${r.sinkLine} [${r.canonicalType}]`);
    }

    // Test 4: Simple Express
    console.log('\n=== Express simple ===');
    const expressCode = `function handler(req, res) {
  const name = req.body.name;
  db.query('SELECT * FROM users WHERE name = ' + name);
}`;
    const parsed2 = await parseSource(expressCode, 'typescript');
    console.log('Parsed:', parsed2 ? 'YES' : 'NO');
    if (parsed2) {
        console.log('Root children:', parsed2.root.namedChildren.map(c => c.type));
    }
    const results2 = await trackTaint(expressCode, 'typescript');
    console.log('Results:', results2.length);
    for (const r of results2) {
        console.log(`  ${r.source} L${r.sourceLine} -> ${r.sink} L${r.sinkLine} [${r.canonicalType}]`);
    }
}

main().catch(console.error);

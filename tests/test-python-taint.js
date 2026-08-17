const { trackTaint } = require('../dist/project-map/taintTracker');

const cases = [
    {
        name: 'Django SQLi (cursor.execute + string concat)',
        code: `def search(request):
    name = request.GET.get('name')
    from django.db import connection
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    rows = cursor.fetchall()
    return JsonResponse({'users': rows})`,
        lang: 'python',
        expectType: 'sql_injection',
    },
    {
        name: 'Flask SQLi (db.session.execute + text)',
        code: `@app.route('/search')
def search():
    name = request.args.get('name')
    result = db.session.execute(text("SELECT * FROM users WHERE name = '" + name + "'"))
    return jsonify({'users': result.fetchall()})`,
        lang: 'python',
        expectType: 'sql_injection',
    },
    {
        name: 'Django command injection (os.system)',
        code: `import os
def ping(request):
    host = request.GET.get('host')
    os.system('ping -c 1 ' + host)
    return JsonResponse({'status': 'ok'})`,
        lang: 'python',
        expectType: 'command_injection',
    },
    {
        name: 'Flask SSTI (render_template_string)',
        code: `from flask import render_template_string, request
@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string('<h1>Hello ' + name + '</h1>')`,
        lang: 'python',
        expectType: 'ssti',
    },
    {
        name: 'Django path traversal (open)',
        code: `def read_file(request):
    filename = request.GET.get('file')
    with open('/app/data/' + filename) as f:
        return JsonResponse({'content': f.read()})`,
        lang: 'python',
        expectType: 'path_traversal',
    },
    {
        name: 'Python pickle deserialization',
        code: `import pickle
import base64
def load_data(request):
    data = request.POST.get('data')
    obj = pickle.loads(base64.b64decode(data))
    return JsonResponse({'result': str(obj)})`,
        lang: 'python',
        expectType: 'insecure_deserialization',
    },
];

async function main() {
    let passed = 0, failed = 0;
    for (const tc of cases) {
        try {
            const results = await trackTaint(tc.code, tc.lang);
            const match = results.find(r => r.canonicalType === tc.expectType);
            if (match) {
                console.log(`PASS: ${tc.name}`);
                console.log(`  ${match.source} L${match.sourceLine} -> ${match.sink} L${match.sinkLine} [${match.canonicalType}]`);
                passed++;
            } else if (results.length > 0) {
                console.log(`FAIL: ${tc.name} — found ${results.length} flow(s) but wrong type:`);
                for (const r of results) console.log(`  ${r.source} L${r.sourceLine} -> ${r.sink} L${r.sinkLine} [${r.canonicalType}]`);
                failed++;
            } else {
                console.log(`FAIL: ${tc.name} — no flows found`);
                failed++;
            }
        } catch (err) {
            console.log(`ERROR: ${tc.name} — ${err.message}`);
            failed++;
        }
    }
    console.log(`\n${passed}/${passed + failed} passed (${failed} failed)`);
    process.exit(failed > 0 ? 1 : 0);
}

main();

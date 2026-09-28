import * as fs from 'fs';
import * as path from 'path';
import { CredentialStore } from './src/auth/credentialStore';
import { toolMap } from './src/tools/map';

async function main(): Promise<void> {
    const creds = CredentialStore.get();
    if (!creds) {
        console.error('Not authenticated. Run securecode-mcp login.');
        process.exit(1);
    }

    const workspace = path.resolve(__dirname, '..', 'test_lab', 'synara');
    const outFile = path.join(workspace, '.securecode', 'architecture-scout-result.json');

    console.log('Architecture scout starting');
    console.log(`Workspace: ${workspace}`);
    console.log(`API: ${creds.apiUrl}`);
    console.log(`Token storage: ${creds.storedAt}`);
    console.log('');

    const depth = (process.argv[2] as 'quick' | 'standard' | 'deep') || 'standard';

    const result = await toolMap(
        {
            apiUrl: creds.apiUrl,
            apiToken: creds.apiToken,
            workspaceRoot: workspace,
        },
        {
            action: 'architecture',
            depth,
            _progress: (p: number, t: number, m: string) => {
                console.log(`[${p}/${t}] ${m}`);
            },
        },
    );

    fs.mkdirSync(path.dirname(outFile), { recursive: true });
    fs.writeFileSync(outFile, JSON.stringify(result, null, 2));
    console.log('');
    console.log('ARCHITECTURE_SCOUT_DONE');
    console.log(`Wrote ${outFile}`);
    const r = result as Record<string, unknown>;
    console.log(`status=${r.status} cached=${r.cached} depth=${r.depth} steps=${r.stepsUsed}`);
}

main().catch((err) => {
    console.error('ARCHITECTURE_SCOUT_FAILED');
    console.error(err?.message || err);
    process.exit(1);
});

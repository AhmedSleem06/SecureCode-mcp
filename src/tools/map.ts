import * as fs from 'fs';
import * as path from 'path';
import type { ProjectMap } from '../api/types';
import type { ServerContext } from '../mcp/types';

export async function toolMap(ctx: ServerContext, args: any): Promise<unknown> {
    const action = (args.action as string) || 'endpoints';
    const mapPath = path.join(ctx.workspaceRoot, '.securecode', 'project-map.json');

    if (!fs.existsSync(mapPath)) {
        return {
            endpoints: [],
            note: 'No Project Map cache found. Run "securecode-mcp map --build" or open the workspace in VS Code with the SecureCode extension and run "SecureCode: Rebuild Project Map".',
        };
    }

    let map: ProjectMap;
    try {
        map = JSON.parse(fs.readFileSync(mapPath, 'utf8')) as ProjectMap;
    } catch {
        return {
            endpoints: [],
            error: 'Project Map cache is corrupted. Rebuild the map.',
        };
    }

    if (action === 'status') {
        return {
            builtAt: map.builtAt,
            version: map.version,
            endpointCount: (map.endpoints || []).length,
            fileCount: map.files ? Object.keys(map.files).length : 0,
        };
    }

    return {
        endpoints: (map.endpoints || []).map((e) => ({
            method: e.method,
            path: e.path,
            handler: e.handlerName,
            sourceFile: e.sourceFile,
            line: e.line,
            authScheme: e.authScheme,
            dataLayer: e.dataLayer,
            middleware: e.middleware,
            params: e.params,
            confidence: e.confidence,
        })),
        builtAt: map.builtAt,
        version: map.version,
    };
}

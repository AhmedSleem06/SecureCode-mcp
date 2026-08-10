import type { ServerContext } from '../mcp/types';
import { ApprovalBroker } from '../approval/broker';
import { runAttack } from '../attack/agentLoop';
import { readCache } from '../project-map/cache';
import { readFileFromWorkspace, inferLanguage } from '../utils/files';
import type { EndpointContext } from '../api/types';

export async function toolAttack(ctx: ServerContext, args: any): Promise<unknown> {
    let code: string | undefined = args.code;
    let language: string | undefined = args.language;
    const filePath = args.filePath as string | undefined;

    if (!code && filePath) {
        const file = readFileFromWorkspace(ctx.workspaceRoot, filePath);
        code = file.code;
        language = language || file.language;
    }

    if (!code) {
        return {
            applied: false,
            note: 'Provide code or filePath for the endpoint to attack.',
        };
    }

    if (!language) {
        return {
            applied: false,
            note: 'Could not determine language. Provide language or filePath with a known extension.',
        };
    }

    const map = readCache(ctx.workspaceRoot);
    if (!map || !map.endpoints || map.endpoints.length === 0) {
        return {
            applied: false,
            note: 'No Project Map found or no endpoints mapped. Run securecode.map with action "build" first.',
        };
    }

    let endpoint: any;
    if (filePath) {
        const relPath = filePath.replace(/\\/g, '/').replace(/^\.\//, '');
        endpoint = (map.endpoints as any[]).find((e) => {
            const sf = (e.sourceFile || '').replace(/\\/g, '/');
            return sf === relPath || sf.endsWith('/' + relPath) || sf.endsWith(relPath);
        });
    }
    if (!endpoint) {
        endpoint = map.endpoints[0];
    }

    const port = args.port || args.targetPort || 3000;
    const targetHost = args.targetHost || '127.0.0.1';

    const summary = `Attack endpoint ${endpoint.method} ${endpoint.path} from ${endpoint.sourceFile}\n` +
        `Target: ${targetHost}:${port}\n` +
        `Vulnerability: ${args.vulnerabilityType || '(auto-detected)'}\n` +
        `Budget: max ${12} steps, 90s wall clock`;

    const broker = new ApprovalBroker();
    await broker.start();

    try {
        const result = await broker.requestApproval(
            'securecode.attack',
            summary,
            [endpoint.path, targetHost, port, code, args.vulnerabilityType],
            60_000,
        );

        if (!result.approved) {
            return {
                applied: false,
                reason: result.reason,
                requestId: result.requestId,
            };
        }

        const attackResult = await runAttack(
            ctx,
            { method: endpoint.method, path: endpoint.path, sourceFile: endpoint.sourceFile, handlerName: endpoint.handlerName },
            code,
            language,
            {
                targetPort: port,
                targetHost,
                signal: undefined,
            },
        );

        return {
            applied: true,
            status: attackResult.status,
            report: attackResult.report,
            error: attackResult.error,
        };
    } finally {
        await broker.stop();
    }
}

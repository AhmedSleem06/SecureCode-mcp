import type { ServerContext } from '../mcp/types';
import { runTests, type RunTestsRequest } from '../utils/testRunner';

export async function toolRunTests(ctx: ServerContext, args: any): Promise<unknown> {
    const req: RunTestsRequest = {
        mode: args.mode,
        testFiles: args.testFiles,
        testPattern: args.testPattern,
        packageManager: args.packageManager,
        script: args.script,
        runner: args.runner,
        setupScript: args.setupScript,
        timeoutMs: args.timeoutMs,
    };

    const result = await runTests(req, ctx.workspaceRoot, { signal: args._signal });

    return {
        approved: result.approved,
        requestId: result.requestId,
        mode: result.mode,
        status: result.status,
        exitCode: result.exitCode,
        output: result.output,
        backend: result.backend,
        command: result.command,
        durationMs: result.durationMs,
    };
}

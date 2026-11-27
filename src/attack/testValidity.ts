import { parseHarnessLog, parseProofMarker, type HarnessLog } from './proofTypes';

export interface TestValidityResult {
    valid: boolean;
    reason?: string;
}

export interface TestValidityOptions {
    kind: 'proof' | 'scenario';
    controlOk?: boolean | null;
    strictEngine?: boolean;
}

export function engineValidity(output: string): TestValidityResult {
    const harnessLog = parseHarnessLog(output);
    if (!harnessLog.found) return { valid: true };
    if (harnessLog.engine === 'emulated' && harnessLog.unsupported && harnessLog.unsupported.length > 0) {
        return { valid: false, reason: `the test helper cannot model this routing (${harnessLog.unsupported.join(', ')})` };
    }
    return { valid: true };
}

export function testValidity(output: string, opts?: TestValidityOptions): TestValidityResult {
    const kind = opts?.kind ?? 'proof';
    const harnessLog = parseHarnessLog(output);

    const engineCheck = engineValidity(output);
    if (!engineCheck.valid) return engineCheck;

    if (harnessLog.found) {
        for (const call of harnessLog.calls) {
            if (!call.matched) {
                return { valid: false, reason: `harness: ${call.method} ${call.path} did not match any registered route` };
            }
            if (call.timedOut) {
                return { valid: false, reason: `harness: ${call.method} ${call.path} timed out` };
            }
            if (!call.sent) {
                return { valid: false, reason: `harness: ${call.method} ${call.path} got no response (sent=false)` };
            }
        }
    }

    if (kind === 'scenario') {
        if (opts?.controlOk === false) {
            return { valid: false, reason: 'scenario control step failed (controlOk=false)' };
        }
        return { valid: true };
    }

    const marker = parseProofMarker(output);
    if (marker.found) {
        if (marker.setup === 'fail') {
            return { valid: false, reason: `proof setup failed${marker.setupNote ? ': ' + marker.setupNote : ''}` };
        }
        if (marker.baseline !== 'pass') {
            return { valid: false, reason: 'proof baseline did not pass' };
        }
    }

    return { valid: true };
}

import { execSync, execFileSync } from 'child_process';
import * as os from 'os';

const SERVICE_NAME = process.env.SECURECODE_KEYCHAIN_SERVICE || 'SecureCode-MCP';
const ACCOUNT_NAME = 'api-token';

export type Platform = 'darwin' | 'win32' | 'linux';

function detectPlatform(): Platform {
    const platform = os.platform();
    if (platform === 'darwin' || platform === 'win32' || platform === 'linux') {
        return platform;
    }
    return 'linux';
}

const KeychainDarwin = {
    set(token: string): void {
        execSync(
            `security add-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}" -w "${token.replace(/"/g, '\\"')}" -U`,
            { stdio: 'pipe' },
        );
    },

    get(): string | null {
        try {
            const buf = execSync(
                `security find-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}" -w`,
                { stdio: 'pipe', encoding: 'utf8' },
            );
            return buf.trim() || null;
        } catch {
            return null;
        }
    },

    delete(): boolean {
        try {
            execSync(
                `security delete-generic-password -s "${SERVICE_NAME}" -a "${ACCOUNT_NAME}"`,
                { stdio: 'pipe' },
            );
            return true;
        } catch {
            return false;
        }
    },
};

function runPowerShell(script: string, input?: string): string {
    const encoded = Buffer.from(script, 'utf16le').toString('base64');
    return execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], {
        stdio: 'pipe',
        encoding: 'utf8',
        ...(input !== undefined ? { input } : {}),
        windowsHide: true,
    });
}

const CRED_STRUCT = `
public class CredMan {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredWriteW(ref CREDENTIAL cred, uint flags);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredReadW(string target, uint type, uint flags, out IntPtr cred);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CredDeleteW(string target, uint type, uint flags);
    [DllImport("advapi32.dll")]
    public static extern void CredFree(IntPtr cred);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }
}`;

const PS_PRELUDE = `$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
${CRED_STRUCT}
"@
`;

const KeychainWin32 = {
    set(token: string): void {
        const script = `${PS_PRELUDE}
$token = [Console]::In.ReadToEnd()
$bytes = [System.Text.Encoding]::Unicode.GetBytes($token)
$ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
try {
    [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)
    $cred = New-Object CredMan+CREDENTIAL
    $cred.Type = 1
    $cred.TargetName = "${SERVICE_NAME}"
    $cred.CredentialBlobSize = $bytes.Length
    $cred.CredentialBlob = $ptr
    $cred.Persist = 2
    $cred.UserName = "${ACCOUNT_NAME}"
    if (-not [CredMan]::CredWriteW([ref]$cred, 0)) { throw "CredWrite failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())" }
} finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
}
`;
        runPowerShell(script, token);
    },

    get(): string | null {
        const script = `${PS_PRELUDE}
$ptr = [IntPtr]::Zero
if (-not [CredMan]::CredReadW("${SERVICE_NAME}", 1, 0, [ref]$ptr)) { exit 0 }
try {
    $cred = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][CredMan+CREDENTIAL])
    $len = [int]$cred.CredentialBlobSize
    $bytes = New-Object byte[] $len
    [Runtime.InteropServices.Marshal]::Copy($cred.CredentialBlob, $bytes, 0, $len)
    [Console]::Out.Write([System.Text.Encoding]::Unicode.GetString($bytes))
} finally {
    [CredMan]::CredFree($ptr)
}
`;
        try {
            const token = runPowerShell(script).trim();
            return token || null;
        } catch {
            return null;
        }
    },

    delete(): boolean {
        const script = `${PS_PRELUDE}
if (-not [CredMan]::CredDeleteW("${SERVICE_NAME}", 1, 0)) { exit 1 }
`;
        try {
            runPowerShell(script);
            return true;
        } catch {
            return false;
        }
    },
};

const KeychainLinux = {
    set(token: string): void {
        execSync(
            `secret-tool store --label="${SERVICE_NAME}" service "${SERVICE_NAME}" account "${ACCOUNT_NAME}" <<< '${token.replace(/'/g, "'\\''")}'`,
            { stdio: 'pipe', shell: '/bin/bash' },
        );
    },

    get(): string | null {
        try {
            const buf = execSync(
                `secret-tool lookup service "${SERVICE_NAME}" account "${ACCOUNT_NAME}"`,
                { stdio: 'pipe', encoding: 'utf8' },
            );
            return buf.trim() || null;
        } catch {
            return null;
        }
    },

    delete(): boolean {
        try {
            execSync(
                `secret-tool clear service "${SERVICE_NAME}" account "${ACCOUNT_NAME}"`,
                { stdio: 'pipe' },
            );
            return true;
        } catch {
            return false;
        }
    },
};

const IMPLS: Record<Platform, typeof KeychainDarwin> = {
    darwin: KeychainDarwin,
    win32: KeychainWin32,
    linux: KeychainLinux,
};

export function sanitizeKeychainError(err: any, secret: string): string {
    const stderr = typeof err?.stderr === 'string' ? err.stderr : Buffer.isBuffer(err?.stderr) ? err.stderr.toString('utf8') : '';
    const firstLine = stderr.split(/\r?\n/).map((l: string) => l.trim()).find((l: string) => l.length > 0) || '';
    const code = typeof err?.status === 'number' ? `exit ${err.status}` : (err?.code ? String(err.code) : 'error');
    let detail = firstLine.slice(0, 200);
    if (secret) detail = detail.split(secret).join('***');
    detail = detail.replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, '***');
    return detail ? `keychain write failed (${code}): ${detail}` : `keychain write failed (${code})`;
}

export interface KeychainResult {
    success: boolean;
    method: 'keychain' | 'file';
    platform: Platform;
    error?: string;
}

export class Keychain {
    static isAvailable(): boolean {
        const platform = detectPlatform();
        try {
            if (platform === 'darwin') {
                execSync('which security', { stdio: 'pipe' });
                return true;
            } else if (platform === 'win32') {
                return true;
            } else if (platform === 'linux') {
                execSync('which secret-tool', { stdio: 'pipe' });
                return true;
            }
        } catch {
            return false;
        }
        return false;
    }

    static get(): string | null {
        const platform = detectPlatform();
        try {
            return IMPLS[platform].get();
        } catch {
            return null;
        }
    }

    static set(token: string): KeychainResult {
        const platform = detectPlatform();
        try {
            IMPLS[platform].set(token);
            return { success: true, method: 'keychain', platform };
        } catch (err: any) {
            return { success: false, method: 'file', platform, error: sanitizeKeychainError(err, token) };
        }
    }

    static delete(): boolean {
        const platform = detectPlatform();
        try {
            return IMPLS[platform].delete();
        } catch {
            return false;
        }
    }

    static getPlatform(): Platform {
        return detectPlatform();
    }
}

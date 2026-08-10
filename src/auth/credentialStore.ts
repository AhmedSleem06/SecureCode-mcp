import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { Keychain } from './keychain';

const CRED_DIR = path.join(os.homedir(), '.securecode');
const CRED_FILE = path.join(CRED_DIR, 'credentials.json');

export interface StoredCredentials {
    apiToken: string;
    apiUrl: string;
    storedAt: string;
}

const DEFAULT_API_URL = 'https://api.usesecurecode.tech';

export class CredentialStore {
    static get(): StoredCredentials | null {
        const envToken = process.env.SECURECODE_API_TOKEN;
        const envUrl = process.env.SECURECODE_API_URL || DEFAULT_API_URL;
        if (envToken) {
            return { apiToken: envToken, apiUrl: envUrl, storedAt: 'env' };
        }

        const token = Keychain.get();
        if (token) {
            return {
                apiToken: token,
                apiUrl: DEFAULT_API_URL,
                storedAt: 'keychain',
            };
        }

        try {
            if (!fs.existsSync(CRED_FILE)) return null;
            const stat = fs.statSync(CRED_FILE);
            if (stat.mode & 0o077) {
                console.error(`[securecode] Warning: ${CRED_FILE} is group/world accessible. Run: chmod 600 ${CRED_FILE}`);
            }
            const raw = fs.readFileSync(CRED_FILE, 'utf8');
            const parsed = JSON.parse(raw) as StoredCredentials;
            if (!parsed.apiToken || !parsed.apiUrl) return null;
            return parsed;
        } catch {
            return null;
        }
    }

    static save(credentials: StoredCredentials): { method: string; warning?: string } {
        const kcResult = Keychain.set(credentials.apiToken);
        if (kcResult.success) {
            this.saveMetadata(credentials);
            return { method: 'keychain' };
        }

        if (!fs.existsSync(CRED_DIR)) {
            fs.mkdirSync(CRED_DIR, { recursive: true, mode: 0o700 });
        }
        fs.writeFileSync(CRED_FILE, JSON.stringify(credentials, null, 2), { mode: 0o600 });
        return {
            method: 'file',
            warning: kcResult.error
                ? `OS keychain unavailable (${kcResult.error}). Credentials stored in ${CRED_FILE} (mode 0600).`
                : undefined,
        };
    }

    static clear(): boolean {
        let removed = Keychain.delete();
        try {
            if (fs.existsSync(CRED_FILE)) {
                fs.unlinkSync(CRED_FILE);
                removed = true;
            }
        } catch {
            // best effort
        }
        try {
            const metaFile = path.join(CRED_DIR, 'metadata.json');
            if (fs.existsSync(metaFile)) {
                fs.unlinkSync(metaFile);
                removed = true;
            }
        } catch {
            // best effort
        }
        return removed;
    }

    static getOrThrow(): StoredCredentials {
        const creds = CredentialStore.get();
        if (!creds) {
            throw new Error(
                'Not authenticated. Run `securecode-mcp login` or set SECURECODE_API_TOKEN environment variable.',
            );
        }
        return creds;
    }

    private static saveMetadata(credentials: StoredCredentials): void {
        if (!fs.existsSync(CRED_DIR)) {
            fs.mkdirSync(CRED_DIR, { recursive: true, mode: 0o700 });
        }
        const metaFile = path.join(CRED_DIR, 'metadata.json');
        const metadata = {
            apiUrl: credentials.apiUrl,
            storedAt: credentials.storedAt,
            method: 'keychain',
        };
        fs.writeFileSync(metaFile, JSON.stringify(metadata, null, 2), { mode: 0o600 });
    }

    static getMetadata(): { apiUrl: string; storedAt: string; method: string } | null {
        const metaFile = path.join(CRED_DIR, 'metadata.json');
        try {
            if (!fs.existsSync(metaFile)) return null;
            return JSON.parse(fs.readFileSync(metaFile, 'utf8'));
        } catch {
            return null;
        }
    }
}

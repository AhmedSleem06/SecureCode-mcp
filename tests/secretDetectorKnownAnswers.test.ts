import { describe, it, expect } from 'vitest';
import { detectSecrets } from '../src/utils/secretDetector';

const k = (...p: string[]) => p.join('');

describe('secretDetector — comprehensive known-answer tests', () => {
    const positives: Array<[string, string, string[]]> = [
        ['AWS access key id', `const id = "${k('AKIA', 'IOSFODNN7EXAMPLE')}";`, ['aws_key_id']],
        ['AWS secret access key', `aws_secret_access_key = ${k('wJalrXUtnFEMI/K7MDENG/', 'bPxRfiCYEXAMPLEKEY')}`, ['aws_secret_key']],
        ['OpenAI key (sk-proj-)', `const key = "${k('sk-', 'proj-', 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z')}";`, ['openai_key']],
        ['Anthropic key', `ANTHROPIC_API_KEY=${k('sk-', 'ant-', 'api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z')}`, ['anthropic_key']],
        ['GitHub classic PAT', `token: ${k('ghp_', 'a'.repeat(36))}`, ['github_pat']],
        ['GitHub fine-grained', `const t = "${k('github_', 'pat_', '11ABCDEFG0123456789_abcdefg')}";`, ['github_fine_grained']],
        ['GitHub OAuth token', `const t = "${k('gho_', 'a'.repeat(36))}";`, ['github_oauth']],
        ['GitHub server token', `const t = "${k('ghs_', 'a'.repeat(36))}";`, ['github_oauth']],
        ['GitHub user token', `const t = "${k('ghu_', 'a'.repeat(36))}";`, ['github_oauth']],
        ['Stripe live key', `stripe = "${k('sk_', 'live_', '51Habcdefghijklmnopqrstuv')}"`, ['stripe_key']],
        ['SendGrid key', `const sg = "${k('SG.', 'abcdefghijklmnopqrstuv.', 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG')}";`, ['sendgrid_key']],
        ['Slack webhook URL', `const hook = "${k('https://hooks.slack.com/services/', 'T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX')}";`, ['slack_webhook']],
        ['Slack token', `const t = "${k('xoxb-', 'abc123def456-ghi789jkl012')}";`, ['slack_token']],
        ['JWT token', 'const t = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";', ['jwt']],
        ['Google API key', `const g = "${k('AIza', 'SyB1234567890abcdefghijklmnopqrstuv')}";`, ['google_api_key']],
        ['npm token', `const t = "${k('npm_', 'a'.repeat(36))}";`, ['npm_token']],
        ['hardcoded fallback secret', `const JWT_SECRET = process.env.JWT_SECRET || 'prod-secret-key-rsa256';`, ['fallback_secret']],
        ['password in object', `const db = { user: 'admin', password: 'Sup3rS3cret!' };`, ['credential_assignment']],
        ['DB connection string', `const url = "${k('postgres://app:', 'S3cretPass@db.internal:5432/prod')}";`, ['connection_string']],
        ['private key PEM', `${k('-----BEGIN ', 'RSA PRIVATE KEY-----')}\nMIIEowIBAAKCAQEA7Z1y\nabcdefghijklmnop\n${k('-----END ', 'RSA PRIVATE KEY-----')}`, ['private_key']],
        ['env file DB_PASSWORD', `DB_PASSWORD=supersecret123`, ['env_file_secret']],
        ['env file API_KEY', `API_KEY=${'sk_' + 'live_'}12345678901234567890`, ['stripe_key']],
        ['Supabase service role', `SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Imxhc3NkamZrbGFqc2RmbGtqYXNkZmxr`, ['supabase_service_role']],
        ['Google service account', `"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."`, ['google_service_account']],
        ['Twilio API key', `const t = "${k('SK', '0123456789abcdef0123456789abcdef')}";`, ['twilio_key']],
        ['generic secret HIGH entropy', `const SECRET = "aH7kP9mQxR2sT5uV8wY1zA3bC6dE0fG";`, ['generic_secret']],
        ['token assignment', `const access_token = "eyJ0b2tlbiI6ImFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6"`, ['credential_assignment']],
        ['stripe webhook secret', `STRIPE_WEBHOOK_SECRET=${k('whsec_', 'a1b2c3d4e5f6g7h8i9j0k1l2')}`, ['stripe_webhook_secret', 'env_file_secret']],
        ['export env DATABASE_PASSWORD', `export DATABASE_PASSWORD="h7Gk2Lp9xQ4m"`, ['env_file_secret']],
        ['env OPENAI_API_KEY', `OPENAI_API_KEY=${k('sk-', 'proj-', 'Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z')}`, ['openai_key']],
    ];

    const negatives: Array<[string, string]> = [
        ['timestamp number', 'createdAt: 1795734011319,'],
        ['order id digits', "const orderId = '4000123412341234567';"],
        ['author email in docs', '// maintained by jane.doe@example.com'],
        ['env lookup without a value', 'const key = process.env.API_KEY;'],
        ['password field name only', "if (!req.body.password) return res.status(400);"],
        ['import statement', "import { JWT_SECRET } from './config';"],
        ['type annotation', 'password: string;'],
        ['placeholder changeme', "const secret = 'changeme';"],
        ['placeholder your-key-here', "const API_KEY = 'your-key-here';"],
        ['placeholder template', "const TOKEN = '<your-token>';"],
        ['env var reference', "const JWT_SECRET = process.env.JWT_SECRET;"],
        ['req.query reference', "const token = req.query.token;"],
        ['config function call', "const key = getConfig('API_KEY');"],
        ['boolean password check', "const hasPassword = !!password;"],
        ['comment with key word', "// TODO: set up API_KEY"],
        ['empty string secret', "const SECRET = '';"],
        ['test assertion', "expect(token).toBe('expected-value');"],
        ['log line', "console.log('Using default SECRET_KEY');"],
        ['password length check', "if (password.length < 8) return false;"],
        ['SQL column name', "SELECT password, email FROM users;"],
        ['fallback URL', "signupUrl: process.env.SIGNUP_URL || 'https://usesecurecode.tech',"],
        ['fallback base URL', "openrouterBaseUrl: process.env.OPENROUTER_BASE_URL || 'https://openrouter.ai/api/v1',"],
        ['fallback non-secret env', "polarServer: process.env.POLAR_SERVER || 'production',"],
        ['fallback DNS order', "if ((process.env.DNS_RESULT_ORDER || 'ipv4first') === 'ipv4first') {"],
        ['fallback file path', "const PERMANENT_BAN_FILE = process.env.PERMANENT_BAN_FILE || '/app/permanent-bans.txt';"],
        ['fallback unset sentinel', "apiKey: config.openrouterApiKey || process.env.OPENROUTER_API_KEY || 'unset',"],
        ['object key: identifier', "{ key: 'supabaseUrl', envVar: 'SUPABASE_URL' },"],
        ['object key: kebab-case', "key: 'refund-failures',"],
        ['template literal log', "console.log(`[Fireworks] Client initialized${process.env.FIREWORKS_API_KEY ? ' with auth token' : ' (NO TOKEN)'}`)"],
        ['taxonomy self-ref', "hardcoded_secret: 'hardcoded_secret',"],
        ['comment connection string', "// Connection strings with embedded credentials: protocol://user:pass@host"],
        ['comment conn example', "// .env-style assignments: DB_PASSWORD=..., REDIS_URL=postgres://user:pass@..., SECRET_KEY=..."],
        ['keychain service name', "const SERVICE_NAME = process.env.SECURECODE_KEYCHAIN_SERVICE || 'SecureCode-MCP';"],
        ['mutation operator map', "hardcoded_password: 'secrets_in_source',"],
        ['env PORT number', 'PORT=3000'],
        ['env NODE_ENV', 'NODE_ENV=production'],
        ['env empty value', 'API_KEY='],
        ['env placeholder', 'API_KEY=your-key-here'],
        ['env URL without creds', 'DATABASE_URL=postgres://localhost:5432/dev'],
    ];

    for (const [name, code, expectedTypes] of positives) {
        it(`POSITIVE: detects ${name}`, () => {
            const findings = detectSecrets(code);
            expect(findings.length).toBeGreaterThan(0);
            const foundTypes = findings.map(f => f.type);
            const hasExpected = expectedTypes.some(t => foundTypes.includes(t));
            expect(hasExpected).toBe(true);
        });
    }

    for (const [name, code] of negatives) {
        it(`NEGATIVE: does not flag ${name}`, () => {
            const findings = detectSecrets(code);
            expect(findings.length).toBe(0);
        });
    }

    it('emails detected only with includePii', () => {
        expect(detectSecrets('user@example.com')).toEqual([]);
        const f = detectSecrets('user@example.com', { includePii: true });
        expect(f.find(x => x.type === 'email')).toBeDefined();
    });

    it('credit card with valid Luhn only', () => {
        const valid = detectSecrets('card: 4532015112830366');
        expect(valid.find(f => f.type === 'credit_card')).toBeDefined();
        const invalid = detectSecrets('order: 4532015112830367');
        expect(invalid.find(f => f.type === 'credit_card')).toBeUndefined();
    });

    it('multiline PEM private key detected', () => {
        const pem = [
            k('-----BEGIN ', 'RSA PRIVATE KEY-----'),
            'MIIEowIBAAKCAQEA7Z1y',
            'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4',
            k('-----END ', 'RSA PRIVATE KEY-----'),
        ].join('\n');
        const f = detectSecrets(pem);
        expect(f.find(x => x.type === 'private_key')).toBeDefined();
    });

    it('reports correct line numbers for multiline content', () => {
        const code = `line1\nline2\nconst key = "${k('AKIA', 'IOSFODNN7EXAMPLE')}";\nline4`;
        const f = detectSecrets(code);
        const aws = f.find(x => x.type === 'aws_key_id');
        expect(aws).toBeDefined();
        expect(aws!.line).toBe(3);
    });

    it('Anthropic key produces exactly one finding (anthropic_key), not openai_key or env_file_secret', () => {
        const code = `ANTHROPIC_API_KEY=${k('sk-', 'ant-', 'api03-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z')}`;
        const f = detectSecrets(code);
        expect(f.length).toBe(1);
        expect(f[0].type).toBe('anthropic_key');
    });

    it('Stripe webhook secret produces exactly one finding (stripe_webhook_secret)', () => {
        const code = `STRIPE_WEBHOOK_SECRET=${k('whsec_', 'a1b2c3d4e5f6g7h8i9j0k1l2')}`;
        const f = detectSecrets(code);
        expect(f.length).toBe(1);
        expect(f[0].type).toBe('stripe_webhook_secret');
    });
});

import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { parseGoMod } from '../src/dependency/parsers/gomod';
import { parseCargoLock } from '../src/dependency/parsers/cargo';
import { parseGemfileLock } from '../src/dependency/parsers/gemfile';
import { parseComposerLock } from '../src/dependency/parsers/composer';
import { parsePoetryLock } from '../src/dependency/parsers/poetry';
import { parseUvLock } from '../src/dependency/parsers/uv';
import { parsePackagesLockJson } from '../src/dependency/parsers/nuget';
import { parsePubspecLock } from '../src/dependency/parsers/pubspec';

const fixtures = path.join(__dirname, 'fixtures', 'deps');

describe('Go parser (go.mod)', () => {
    it('parses require directives', () => {
        const result = parseGoMod(path.join(fixtures, 'go.mod'));
        expect(result).not.toBeNull();
        expect(result!.ecosystem).toBe('go');
        expect(result!.packages.length).toBe(1);
        expect(result!.packages[0].name).toBe('golang.org/x/text');
        expect(result!.packages[0].version).toBe('0.3.0');
        expect(result!.packages[0].ecosystem).toBe('go');
    });
});

describe('Cargo.lock parser', () => {
    it('parses [[package]] entries', () => {
        const result = parseCargoLock(path.join(fixtures, 'Cargo.lock'));
        expect(result).not.toBeNull();
        expect(result!.ecosystem).toBe('cargo');
        expect(result!.packages.length).toBe(2);
        const libc = result!.packages.find(p => p.name === 'libc');
        expect(libc).toBeDefined();
        expect(libc!.version).toBe('0.2.80');
        const tokio = result!.packages.find(p => p.name === 'tokio');
        expect(tokio).toBeDefined();
        expect(tokio!.version).toBe('1.0.0');
    });
});

describe('Gemfile.lock parser', () => {
    it('parses specs section', () => {
        const result = parseGemfileLock(path.join(fixtures, 'Gemfile.lock'));
        expect(result).not.toBeNull();
        expect(result!.ecosystem).toBe('rubygems');
        expect(result!.packages.length).toBe(2);
        const rack = result!.packages.find(p => p.name === 'rack');
        expect(rack).toBeDefined();
        expect(rack!.version).toBe('2.0.0');
    });
});

describe('composer.lock parser', () => {
    it('parses packages + packages-dev', () => {
        const result = parseComposerLock(path.join(fixtures, 'composer.lock'));
        expect(result).not.toBeNull();
        expect(result!.ecosystem).toBe('composer');
        expect(result!.packages.length).toBe(3);
        const guzzle = result!.packages.find(p => p.name === 'guzzlehttp/guzzle');
        expect(guzzle).toBeDefined();
        expect(guzzle!.version).toBe('6.5.0');
        const phpunit = result!.packages.find(p => p.name === 'phpunit/phpunit');
        expect(phpunit).toBeDefined();
    });
});

describe('poetry.lock parser', () => {
    it('parses [[package]] entries', () => {
        const result = parsePoetryLock(path.join(fixtures, 'poetry.lock'));
        expect(result).not.toBeNull();
        expect(result!.packages.length).toBe(2);
        const django = result!.packages.find(p => p.name === 'django');
        expect(django).toBeDefined();
        expect(django!.version).toBe('2.2.0');
        expect(django!.ecosystem).toBe('pip');
    });
});

describe('uv.lock parser', () => {
    it('parses [[package]] entries', () => {
        const result = parseUvLock(path.join(fixtures, 'uv.lock'));
        expect(result).not.toBeNull();
        expect(result!.packages.length).toBe(2);
        const flask = result!.packages.find(p => p.name === 'flask');
        expect(flask).toBeDefined();
        expect(flask!.version).toBe('2.0.0');
    });
});

describe('packages.lock.json parser (NuGet)', () => {
    it('parses dependencies', () => {
        const result = parsePackagesLockJson(path.join(fixtures, 'packages.lock.json'));
        expect(result).not.toBeNull();
        expect(result!.ecosystem).toBe('nuget');
        expect(result!.packages.length).toBe(2);
        const nj = result!.packages.find(p => p.name === 'Newtonsoft.Json');
        expect(nj).toBeDefined();
        expect(nj!.version).toBe('13.0.1');
        expect(nj!.direct).toBe(true);
    });
});

describe('pubspec.lock parser (Dart/Pub)', () => {
    it('parses packages section', () => {
        const result = parsePubspecLock(path.join(fixtures, 'pubspec.lock'));
        expect(result).not.toBeNull();
        expect(result!.ecosystem).toBe('pub');
        expect(result!.packages.length).toBe(2);
        const http = result!.packages.find(p => p.name === 'http');
        expect(http).toBeDefined();
        expect(http!.version).toBe('0.13.0');
    });
});

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { detectRuntime } from '../src/utils/runtimeDetect';
import { createEffectMock } from '../src/utils/effectMock';
import {
    pickImageForRunner,
    pickImageForCommand,
    runnerInvocation,
    fileExtFor,
    isCompiledLangRunner,
    buildCompiledLangPlacement,
    parseJavaPackagePath,
    isOfflineDepsFailure,
} from '../src/utils/verificationSandbox';
import { checkTestSafety } from '../src/utils/testSafety';
import { runLocalTest } from '../src/utils/localTestRunner';
import type { SandboxBackend, SandboxExecuteOptions, SandboxExecuteResult } from '../src/utils/verificationSandbox';

process.env.SECURECODE_TEST_MODE = '1';

function mkdtempRoot(): string {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'multilang-'));
}

function write(root: string, rel: string, content: string): void {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, content, 'utf8');
}

describe('detectRuntime — Go', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('detects go from .go file extension', () => {
        write(root, 'main.go', 'package main');
        const info = detectRuntime(root, 'main.go');
        expect(info.runtime).toBe('go');
        expect(info.runner).toBe('go');
        expect(info.suggestedRunner).toBe('go');
        expect(info.packageManager).toBe('go');
    });

    it('detects go from go.mod manifest', () => {
        write(root, 'go.mod', 'module example.com/app\ngo 1.23\n');
        const info = detectRuntime(root);
        expect(info.runtime).toBe('go');
        expect(info.framework).toBe('net/http');
    });

    it('detects gin framework from go.mod', () => {
        write(root, 'go.mod', 'module example.com/app\ngo 1.23\nrequire github.com/gin-gonic/gin v1.9.1\n');
        const info = detectRuntime(root, 'handler.go');
        expect(info.framework).toBe('gin');
        expect(info.testabilityTier).toBe(1);
    });

    it('detects echo framework from go.mod', () => {
        write(root, 'go.mod', 'module example.com/app\ngo 1.23\nrequire github.com/labstack/echo v4.11.0\n');
        const info = detectRuntime(root, 'handler.go');
        expect(info.framework).toBe('echo');
        expect(info.testabilityTier).toBe(1);
    });

    it('detects depsInstalled from vendor directory', () => {
        write(root, 'go.mod', 'module example.com/app\ngo 1.23\n');
        write(root, 'vendor/modules.txt', '');
        const info = detectRuntime(root, 'main.go');
        expect(info.depsInstalled).toBe(true);
    });
});

describe('detectRuntime — Ruby', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('detects ruby from .rb file extension', () => {
        write(root, 'app.rb', 'puts "hi"');
        const info = detectRuntime(root, 'app.rb');
        expect(info.runtime).toBe('ruby');
        expect(info.runner).toBe('ruby');
        expect(info.suggestedRunner).toBe('ruby');
    });

    it('detects rails from Gemfile.lock', () => {
        write(root, 'Gemfile.lock', '    rails (7.1.2)\n');
        const info = detectRuntime(root, 'app/controllers/main.rb');
        expect(info.framework).toBe('rails');
        expect(info.frameworkVersion).toBe('7.1.2');
        expect(info.testabilityTier).toBe(1);
    });

    it('detects depsInstalled from vendor/bundle', () => {
        write(root, 'Gemfile', 'source "https://rubygems.org"');
        write(root, 'vendor/bundle/.keep', '');
        const info = detectRuntime(root, 'app.rb');
        expect(info.depsInstalled).toBe(true);
    });
});

describe('detectRuntime — PHP', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('detects php from .php file extension', () => {
        write(root, 'index.php', '<?php echo "hi"; ?>');
        const info = detectRuntime(root, 'index.php');
        expect(info.runtime).toBe('php');
        expect(info.runner).toBe('php');
    });

    it('detects laravel from composer.lock', () => {
        write(root, 'composer.lock', '{"packages": [{"name": "laravel/framework", "version": "v10.0"}]}');
        const info = detectRuntime(root, 'routes/web.php');
        expect(info.framework).toBe('laravel');
        expect(info.testabilityTier).toBe(1);
    });

    it('detects depsInstalled from vendor directory', () => {
        write(root, 'composer.json', '{}');
        write(root, 'vendor/autoload.php', '');
        const info = detectRuntime(root, 'index.php');
        expect(info.depsInstalled).toBe(true);
    });
});

describe('detectRuntime — Java', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('detects java from .java file extension', () => {
        write(root, 'App.java', 'public class App {}');
        const info = detectRuntime(root, 'App.java');
        expect(info.runtime).toBe('java');
    });

    it('detects java from .kt file extension', () => {
        write(root, 'App.kt', 'fun main() {}');
        const info = detectRuntime(root, 'App.kt');
        expect(info.runtime).toBe('java');
    });

    it('detects spring-boot from pom.xml with maven runner', () => {
        write(root, 'pom.xml', '<project><properties><spring-boot.version>3.2.0</spring-boot.version></properties></project>');
        const info = detectRuntime(root, 'src/main/java/App.java');
        expect(info.framework).toBe('spring-boot');
        expect(info.frameworkVersion).toBe('3.2.0');
        expect(info.runner).toBe('java-maven');
        expect(info.packageManager).toBe('maven');
        expect(info.testabilityTier).toBe(1);
    });

    it('detects spring-boot from build.gradle with gradle runner', () => {
        write(root, 'build.gradle', "plugins { id 'org.springframework.boot' version '3.2.0' }\nspring-boot");
        const info = detectRuntime(root, 'src/main/java/App.java');
        expect(info.framework).toBe('spring-boot');
        expect(info.runner).toBe('java-gradle');
        expect(info.packageManager).toBe('gradle');
    });

    it('detects plain java with pom.xml', () => {
        write(root, 'pom.xml', '<project><modelVersion>4.0.0</modelVersion></project>');
        const info = detectRuntime(root, 'src/main/java/App.java');
        expect(info.runtime).toBe('java');
        expect(info.framework).toBeNull();
        expect(info.runner).toBe('java-maven');
    });
});

describe('detectRuntime — .NET', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('detects dotnet from .cs file extension', () => {
        write(root, 'Program.cs', 'class Program {}');
        const info = detectRuntime(root, 'Program.cs');
        expect(info.runtime).toBe('dotnet');
        expect(info.runner).toBe('dotnet');
        expect(info.suggestedRunner).toBe('dotnet');
    });

    it('detects aspnet-core from .csproj with Web SDK', () => {
        write(root, 'App.csproj', '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>');
        const info = detectRuntime(root, 'Program.cs');
        expect(info.framework).toBe('aspnet-core');
        expect(info.frameworkVersion).toBe('8.0');
        expect(info.testabilityTier).toBe(1);
    });

    it('detects aspnet-core from .csproj with AspNetCore package', () => {
        write(root, 'App.csproj', '<Project><ItemGroup><PackageReference Include="Microsoft.AspNetCore.App" /></ItemGroup><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>');
        const info = detectRuntime(root, 'Program.cs');
        expect(info.framework).toBe('aspnet-core');
    });

    it('detects depsInstalled from obj/project.assets.json', () => {
        write(root, 'App.csproj', '<Project Sdk="Microsoft.NET.Sdk.Web"></Project>');
        write(root, 'obj/project.assets.json', '{}');
        const info = detectRuntime(root, 'Program.cs');
        expect(info.depsInstalled).toBe(true);
    });
});

describe('pickImageForRunner — new languages', () => {
    const origEnv = { ...process.env };

    afterEach(() => {
        for (const k of Object.keys(process.env)) {
            if (!(k in origEnv)) delete process.env[k];
        }
        for (const [k, v] of Object.entries(origEnv)) {
            process.env[k] = v;
        }
    });

    it('returns golang:1.23-alpine for go', () => {
        delete process.env.SECURECODE_SANDBOX_GO_IMAGE;
        expect(pickImageForRunner('go').image).toBe('golang:1.23-alpine');
    });

    it('returns ruby:3.3-slim for ruby', () => {
        delete process.env.SECURECODE_SANDBOX_RUBY_IMAGE;
        expect(pickImageForRunner('ruby').image).toBe('ruby:3.3-slim');
    });

    it('returns php:8.3-cli for php', () => {
        delete process.env.SECURECODE_SANDBOX_PHP_IMAGE;
        expect(pickImageForRunner('php').image).toBe('php:8.3-cli');
    });

    it('returns maven:3.9-eclipse-temurin-21 for java-maven', () => {
        delete process.env.SECURECODE_SANDBOX_JAVA_MAVEN_IMAGE;
        expect(pickImageForRunner('java-maven').image).toBe('maven:3.9-eclipse-temurin-21');
    });

    it('returns gradle:8-jdk21 for java-gradle', () => {
        delete process.env.SECURECODE_SANDBOX_JAVA_GRADLE_IMAGE;
        expect(pickImageForRunner('java-gradle').image).toBe('gradle:8-jdk21');
    });

    it('returns mcr.microsoft.com/dotnet/sdk:8.0 for dotnet', () => {
        delete process.env.SECURECODE_SANDBOX_DOTNET_IMAGE;
        expect(pickImageForRunner('dotnet').image).toBe('mcr.microsoft.com/dotnet/sdk:8.0');
    });

    it('respects SECURECODE_SANDBOX_GO_IMAGE override', () => {
        process.env.SECURECODE_SANDBOX_GO_IMAGE = 'my-go:latest';
        expect(pickImageForRunner('go').image).toBe('my-go:latest');
    });

    it('respects SECURECODE_SANDBOX_DOTNET_IMAGE override', () => {
        process.env.SECURECODE_SANDBOX_DOTNET_IMAGE = 'my-dotnet:latest';
        expect(pickImageForRunner('dotnet').image).toBe('my-dotnet:latest');
    });
});

describe('pickImageForCommand — new executables', () => {
    it('returns golang:1.23-alpine for go', () => {
        expect(pickImageForCommand('go').image).toBe('golang:1.23-alpine');
    });

    it('returns ruby:3.3-slim for ruby', () => {
        expect(pickImageForCommand('ruby').image).toBe('ruby:3.3-slim');
    });

    it('returns ruby:3.3-slim for bundle', () => {
        expect(pickImageForCommand('bundle').image).toBe('ruby:3.3-slim');
    });

    it('returns php:8.3-cli for php', () => {
        expect(pickImageForCommand('php').image).toBe('php:8.3-cli');
    });

    it('returns maven image for mvn', () => {
        expect(pickImageForCommand('mvn').image).toBe('maven:3.9-eclipse-temurin-21');
    });

    it('returns gradle image for gradle', () => {
        expect(pickImageForCommand('gradle').image).toBe('gradle:8-jdk21');
    });

    it('returns dotnet/sdk for dotnet', () => {
        expect(pickImageForCommand('dotnet').image).toBe('mcr.microsoft.com/dotnet/sdk:8.0');
    });
});

describe('buildCompiledLangPlacement', () => {
    it('go: places sc_proof_test.go in the target file directory', () => {
        const p = buildCompiledLangPlacement('go', 'package main_test', 'cmd/server/main.go');
        expect(p.testRelPath).toBe('cmd/server/sc_proof_test.go');
        expect(p.runCmd).toBe('go test -run TestSecureCodeProof -v -count=1 ./cmd/server');
    });

    it('go: defaults to root when no targetFilePath', () => {
        const p = buildCompiledLangPlacement('go', 'package main_test');
        expect(p.testRelPath).toBe('sc_proof_test.go');
        expect(p.runCmd).toContain('./.');
    });

    it('go: handles root-level target file', () => {
        const p = buildCompiledLangPlacement('go', 'package main_test', 'main.go');
        expect(p.testRelPath).toBe('sc_proof_test.go');
        expect(p.runCmd).toContain('./.');
    });

    it('ruby: places sc_proof.rb at project root', () => {
        const p = buildCompiledLangPlacement('ruby', 'require "test/unit"', 'app/controllers/users.rb');
        expect(p.testRelPath).toBe('sc_proof.rb');
        expect(p.runCmd).toBe('bundle exec ruby sc_proof.rb');
    });

    it('php: places sc_proof.php at project root', () => {
        const p = buildCompiledLangPlacement('php', '<?php', 'routes/web.php');
        expect(p.testRelPath).toBe('sc_proof.php');
        expect(p.runCmd).toBe('php sc_proof.php');
    });

    it('java-maven: places in src/test/java/<package>/', () => {
        const script = 'package com.example.app;\nimport org.junit.Test;\npublic class ScProofTest {}';
        const p = buildCompiledLangPlacement('java-maven', script, 'src/main/java/com/example/app/UserController.java');
        expect(p.testRelPath).toBe('src/test/java/com/example/app/ScProofTest.java');
        expect(p.runCmd).toContain('mvn -o -q test -Dtest=ScProofTest');
        expect(p.runCmd).toContain('-Dmaven.repo.local=/tmp/m2');
        expect(p.runCmd).toContain('-Dmaven.repo.local.tail=/tmp/m2-ro');
    });

    it('java-gradle: places in src/test/java/<package>/', () => {
        const script = 'package com.myapp;\npublic class ScProofTest {}';
        const p = buildCompiledLangPlacement('java-gradle', script);
        expect(p.testRelPath).toBe('src/test/java/com/myapp/ScProofTest.java');
        expect(p.runCmd).toContain('gradle test --offline --no-daemon --tests ScProofTest');
    });

    it('java: falls back to src/test/java when no package line', () => {
        const p = buildCompiledLangPlacement('java-maven', 'public class ScProofTest {}');
        expect(p.testRelPath).toBe('src/test/java/ScProofTest.java');
    });

    it('dotnet: places ScProof/ScProofTest.cs', () => {
        const p = buildCompiledLangPlacement('dotnet', 'using Xunit;', 'Program.cs');
        expect(p.testRelPath).toBe('ScProof/ScProofTest.cs');
        expect(p.runCmd).toBe('dotnet test ScProof --no-restore');
    });
});

describe('parseJavaPackagePath', () => {
    it('parses a package line to a directory path', () => {
        expect(parseJavaPackagePath('package com.example.app;\nimport org.junit.Test;')).toBe('com/example/app');
    });

    it('returns empty when no package line', () => {
        expect(parseJavaPackagePath('import org.junit.Test;')).toBe('');
    });

    it('handles single-segment package', () => {
        expect(parseJavaPackagePath('package app;')).toBe('app');
    });
});

describe('runnerInvocation — new runners', () => {
    it('invokes go test with target dir', () => {
        const cmd = runnerInvocation('go', 'cmd/server/sc_proof_test.go', '/workspace');
        expect(cmd).toContain('go test');
        expect(cmd).toContain('-run TestSecureCodeProof');
        expect(cmd).toContain('./cmd/server');
        expect(cmd).not.toContain('./...');
    });

    it('invokes go test at root when file is at root', () => {
        const cmd = runnerInvocation('go', 'sc_proof_test.go', '/workspace');
        expect(cmd).toContain('./.');
    });

    it('invokes bundle exec ruby', () => {
        const cmd = runnerInvocation('ruby', '/workspace/.securecode/test.rb');
        expect(cmd).toContain('bundle exec ruby');
    });

    it('invokes php', () => {
        const cmd = runnerInvocation('php', '/workspace/.securecode/test.php');
        expect(cmd).toContain('php');
    });

    it('invokes mvn for java-maven with chained local repo', () => {
        const cmd = runnerInvocation('java-maven', '');
        expect(cmd).toContain('mvn');
        expect(cmd).toContain('-o');
        expect(cmd).toContain('ScProofTest');
        expect(cmd).toContain('-Dmaven.repo.local=/tmp/m2');
        expect(cmd).toContain('-Dmaven.repo.local.tail=/tmp/m2-ro');
    });

    it('invokes gradle for java-gradle with --no-daemon', () => {
        const cmd = runnerInvocation('java-gradle', '');
        expect(cmd).toContain('gradle test');
        expect(cmd).toContain('--offline');
        expect(cmd).toContain('--no-daemon');
        expect(cmd).toContain('ScProofTest');
    });

    it('invokes dotnet test ScProof', () => {
        const cmd = runnerInvocation('dotnet', '');
        expect(cmd).toContain('dotnet test ScProof');
        expect(cmd).toContain('--no-restore');
    });
});

describe('fileExtFor — new runners', () => {
    it('go → .go', () => { expect(fileExtFor('go')).toBe('.go'); });
    it('ruby → .rb', () => { expect(fileExtFor('ruby')).toBe('.rb'); });
    it('php → .php', () => { expect(fileExtFor('php')).toBe('.php'); });
    it('java-maven → .java', () => { expect(fileExtFor('java-maven')).toBe('.java'); });
    it('java-gradle → .java', () => { expect(fileExtFor('java-gradle')).toBe('.java'); });
    it('dotnet → .cs', () => { expect(fileExtFor('dotnet')).toBe('.cs'); });
});

describe('isCompiledLangRunner', () => {
    it('returns true for go/ruby/php/java-maven/java-gradle/dotnet', () => {
        for (const r of ['go', 'ruby', 'php', 'java-maven', 'java-gradle', 'dotnet']) {
            expect(isCompiledLangRunner(r)).toBe(true);
        }
    });

    it('returns false for node/tsx/python', () => {
        for (const r of ['node', 'tsx', 'python', 'python3', 'bun', 'deno']) {
            expect(isCompiledLangRunner(r)).toBe(false);
        }
    });
});

describe('isOfflineDepsFailure', () => {
    it('detects Go module failure', () => {
        const r = isOfflineDepsFailure('go: cannot find module providing package github.com/gin-gonic/gin');
        expect(r.match).toBe(true);
        expect(r.detail).toContain('cannot find module');
    });

    it('detects Go GOPROXY=off failure', () => {
        const r = isOfflineDepsFailure('module lookup disabled by GOPROXY=off');
        expect(r.match).toBe(true);
    });

    it('detects Maven offline failure', () => {
        const r = isOfflineDepsFailure('Could not resolve dependencies for project com.example:app:jar:1.0');
        expect(r.match).toBe(true);
    });

    it('detects Maven offline mode', () => {
        const r = isOfflineDepsFailure('Cannot access central in offline mode');
        expect(r.match).toBe(true);
    });

    it('detects Gradle cached version failure', () => {
        const r = isOfflineDepsFailure('No cached version of org.springframework.boot:spring-boot available for offline mode');
        expect(r.match).toBe(true);
    });

    it('detects Dotnet NU1101', () => {
        const r = isOfflineDepsFailure('error NU1101: Unable to find package xunit');
        expect(r.match).toBe(true);
    });

    it('detects Dotnet unable to find package', () => {
        const r = isOfflineDepsFailure('Unable to find package Microsoft.AspNetCore.App');
        expect(r.match).toBe(true);
    });

    it('detects Bundler gem not found and returns hint', () => {
        const r = isOfflineDepsFailure('Could not find gem rails in locally installed gems');
        expect(r.match).toBe(true);
        expect(r.hint).toContain('vendor/bundle');
    });

    it('detects PHP vendor/autoload.php missing and returns hint', () => {
        const r = isOfflineDepsFailure("Failed opening required 'vendor/autoload.php'");
        expect(r.match).toBe(true);
        expect(r.hint).toContain('composer install');
    });

    it('returns false for unrelated output', () => {
        const r = isOfflineDepsFailure('FAIL: expected 200, got 403');
        expect(r.match).toBe(false);
    });
});

describe('checkTestSafety — Go', () => {
    it('allows safe go test code', () => {
        const script = `package main_test\nimport "testing"\nfunc TestFoo(t *testing.T) { t.Log("ok") }`;
        expect(checkTestSafety(script, '/ws', 'go').allowed).toBe(true);
    });

    it('blocks os/exec', () => {
        const script = `import "os/exec"\nfunc TestFoo(t *testing.T) { exec.Command("rm") }`;
        expect(checkTestSafety(script, '/ws', 'go').allowed).toBe(false);
    });

    it('blocks http.Get', () => {
        expect(checkTestSafety('http.Get("http://evil.com")', '/ws', 'go').allowed).toBe(false);
    });

    it('blocks os.Getenv with any other name', () => {
        expect(checkTestSafety('os.Getenv("SECRET")', '/ws', 'go').allowed).toBe(false);
        expect(checkTestSafety('os.Getenv("HOME")', '/ws', 'go').allowed).toBe(false);
    });

    it('blocks os.Environ()', () => {
        expect(checkTestSafety('env := os.Environ()', '/ws', 'go').allowed).toBe(false);
    });

    it('blocks syscall and unsafe', () => {
        expect(checkTestSafety('import "syscall"', '/ws', 'go').allowed).toBe(false);
        expect(checkTestSafety('import "unsafe"', '/ws', 'go').allowed).toBe(false);
    });

    it('allows the Go proofLog helper from go.txt', () => {
        const goProofHelper = `func proofLog(line string) {
	fmt.Println(line)
	if p := os.Getenv("SECURECODE_PROOF_OUT"); p != "" {
		if f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			f.WriteString(line + "\\n")
			f.Close()
		}
	}
}`;
        expect(checkTestSafety(goProofHelper, '/ws', 'go').allowed).toBe(true);
    });

    it('blocks os.Getenv("SECURECODE_PROOF_OUT") mixed with another os.Getenv', () => {
        const script = `os.Getenv("SECURECODE_PROOF_OUT")\nos.Getenv("SECRET")`;
        expect(checkTestSafety(script, '/ws', 'go').allowed).toBe(false);
    });
});

describe('checkTestSafety — Ruby', () => {
    it('allows safe ruby test code', () => {
        const script = `require "test/unit"\nclass MyTest < Test::Unit::TestCase\n  def test_ok\n    assert true\n  end\nend`;
        expect(checkTestSafety(script, '/ws', 'ruby').allowed).toBe(true);
    });

    it('blocks system()', () => {
        expect(checkTestSafety('system("rm -rf /")', '/ws', 'ruby').allowed).toBe(false);
    });

    it('blocks backticks', () => {
        expect(checkTestSafety('output = `whoami`', '/ws', 'ruby').allowed).toBe(false);
    });

    it('blocks ENV with any other key', () => {
        expect(checkTestSafety('ENV["SECRET"]', '/ws', 'ruby').allowed).toBe(false);
        expect(checkTestSafety("ENV['HOME']", '/ws', 'ruby').allowed).toBe(false);
    });

    it('blocks ENV.to_h', () => {
        expect(checkTestSafety('ENV.to_h', '/ws', 'ruby').allowed).toBe(false);
    });

    it('blocks Net::HTTP', () => {
        expect(checkTestSafety('Net::HTTP.get("evil.com")', '/ws', 'ruby').allowed).toBe(false);
    });

    it('allows the Ruby proof_log helper from rails.txt', () => {
        const rubyProofHelper = `def proof_log(line)
  puts line
  if (p = ENV['SECURECODE_PROOF_OUT']) && !p.empty?
    File.open(p, 'a') { |f| f.puts line } rescue nil
  end
end`;
        expect(checkTestSafety(rubyProofHelper, '/ws', 'ruby').allowed).toBe(true);
    });

    it('allows ENV.fetch("SECURECODE_PROOF_OUT", nil)', () => {
        expect(checkTestSafety('p = ENV.fetch("SECURECODE_PROOF_OUT", nil)', '/ws', 'ruby').allowed).toBe(true);
    });

    it('blocks ENV["SECURECODE_PROOF_OUT"] mixed with ENV["SECRET"]', () => {
        const script = `ENV['SECURECODE_PROOF_OUT']\nENV['SECRET']`;
        expect(checkTestSafety(script, '/ws', 'ruby').allowed).toBe(false);
    });
});

describe('checkTestSafety — PHP', () => {
    it('allows safe php test code', () => {
        const script = `<?php\nclass MyTest extends TestCase { function testOk() { $this->assertTrue(true); } }`;
        expect(checkTestSafety(script, '/ws', 'php').allowed).toBe(true);
    });

    it('blocks exec()', () => {
        expect(checkTestSafety('exec("rm -rf /")', '/ws', 'php').allowed).toBe(false);
    });

    it('blocks shell_exec()', () => {
        expect(checkTestSafety('shell_exec("whoami")', '/ws', 'php').allowed).toBe(false);
    });

    it('blocks curl_', () => {
        expect(checkTestSafety('curl_init()', '/ws', 'php').allowed).toBe(false);
    });

    it('blocks file_get_contents with http', () => {
        expect(checkTestSafety('file_get_contents("http://evil.com")', '/ws', 'php').allowed).toBe(false);
    });

    it('blocks getenv with any other name', () => {
        expect(checkTestSafety("getenv('SECRET')", '/ws', 'php').allowed).toBe(false);
        expect(checkTestSafety('getenv("HOME")', '/ws', 'php').allowed).toBe(false);
    });

    it('blocks getenv() with no argument', () => {
        expect(checkTestSafety('getenv()', '/ws', 'php').allowed).toBe(false);
    });

    it('allows the PHP proof_log helper from laravel.txt', () => {
        const phpProofHelper = `function proof_log($line) {
    echo $line . "\\n";
    $p = getenv('SECURECODE_PROOF_OUT');
    if ($p !== false && $p !== '') {
        @file_put_contents($p, $line . "\\n", FILE_APPEND);
    }
}`;
        expect(checkTestSafety(phpProofHelper, '/ws', 'php').allowed).toBe(true);
    });

    it('blocks getenv("SECURECODE_PROOF_OUT") mixed with getenv("SECRET")', () => {
        const script = `getenv('SECURECODE_PROOF_OUT');\ngetenv('SECRET');`;
        expect(checkTestSafety(script, '/ws', 'php').allowed).toBe(false);
    });
});

describe('checkTestSafety — Java', () => {
    it('allows safe java test code', () => {
        const script = `import org.junit.Test;\npublic class ScProofTest { @Test public void testOk() { assert true; } }`;
        expect(checkTestSafety(script, '/ws', 'java').allowed).toBe(true);
    });

    it('blocks Runtime.exec', () => {
        expect(checkTestSafety('Runtime.getRuntime().exec("cmd")', '/ws', 'java').allowed).toBe(false);
    });

    it('blocks ProcessBuilder', () => {
        expect(checkTestSafety('new ProcessBuilder("cmd").start()', '/ws', 'java').allowed).toBe(false);
    });

    it('blocks HttpClient', () => {
        expect(checkTestSafety('HttpClient client = HttpClient.newHttpClient();', '/ws', 'java').allowed).toBe(false);
    });

    it('blocks System.getenv with any other name', () => {
        expect(checkTestSafety('System.getenv("SECRET")', '/ws', 'java').allowed).toBe(false);
    });

    it('allows the Java proofLog helper from spring.txt', () => {
        const javaProofHelper = `static void proofLog(String line) {
        System.out.println(line);
        String p = System.getenv("SECURECODE_PROOF_OUT");
        if (p != null && !p.isEmpty()) {
            try { Files.writeString(Path.of(p), line + "\\n", CREATE, APPEND); } catch (Exception ignored) {}
        }
    }`;
        expect(checkTestSafety(javaProofHelper, '/ws', 'java').allowed).toBe(true);
    });

    it('blocks System.getenv("SECURECODE_PROOF_OUT") mixed with System.getenv("SECRET")', () => {
        const script = `System.getenv("SECURECODE_PROOF_OUT");\nSystem.getenv("SECRET");`;
        expect(checkTestSafety(script, '/ws', 'java').allowed).toBe(false);
    });
});

describe('checkTestSafety — C#', () => {
    it('allows safe C# test code', () => {
        const script = `using Xunit;\npublic class ScProofTest { [Fact] public void TestOk() { Assert.True(true); } }`;
        expect(checkTestSafety(script, '/ws', 'csharp').allowed).toBe(true);
    });

    it('blocks Process.Start', () => {
        expect(checkTestSafety('Process.Start("cmd")', '/ws', 'csharp').allowed).toBe(false);
    });

    it('blocks HttpClient', () => {
        expect(checkTestSafety('var client = new HttpClient();', '/ws', 'csharp').allowed).toBe(false);
    });

    it('blocks Environment.GetEnvironmentVariable with any other name', () => {
        expect(checkTestSafety('Environment.GetEnvironmentVariable("SECRET")', '/ws', 'csharp').allowed).toBe(false);
    });

    it('allows the C# ProofLog helper from aspnet.txt', () => {
        const csharpProofHelper = `static void ProofLog(string line)
    {
        Console.WriteLine(line);
        var p = Environment.GetEnvironmentVariable("SECURECODE_PROOF_OUT");
        if (!string.IsNullOrEmpty(p))
        {
            try { File.AppendAllText(p, line + "\\n"); } catch { }
        }
    }`;
        expect(checkTestSafety(csharpProofHelper, '/ws', 'csharp').allowed).toBe(true);
    });

    it('blocks Environment.GetEnvironmentVariable("SECURECODE_PROOF_OUT") mixed with another read', () => {
        const script = `Environment.GetEnvironmentVariable("SECURECODE_PROOF_OUT");\nEnvironment.GetEnvironmentVariable("SECRET");`;
        expect(checkTestSafety(script, '/ws', 'csharp').allowed).toBe(false);
    });
});

describe('no local mode for compiled languages', () => {
    function makeMockBackend(name: string): SandboxBackend {
        return {
            name,
            available: true,
            async execute(_opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
                return { verdict: 'pass', output: 'PASS: ok', exitCode: 0, backend: name };
            },
        };
    }

    let tmpWs: string;
    beforeEach(() => { tmpWs = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-noloc-')); });
    afterEach(() => { try { fs.rmSync(tmpWs, { recursive: true, force: true }); } catch {} });

    it('returns sandbox-unavailable for go with local backend', async () => {
        const result = await runLocalTest('package main_test', 'go', tmpWs, { sandboxBackend: makeMockBackend('local') });
        expect(result.verdict).toBe('sandbox-unavailable');
        expect(result.output).toContain('Docker is required');
        expect(result.output).toContain('go');
    });

    it('returns sandbox-unavailable for ruby with local backend', async () => {
        const result = await runLocalTest('puts "hi"', 'ruby', tmpWs, { sandboxBackend: makeMockBackend('local') });
        expect(result.verdict).toBe('sandbox-unavailable');
        expect(result.output).toContain('Docker is required');
    });

    it('returns sandbox-unavailable for php with local/reduced backend', async () => {
        const result = await runLocalTest('<?php echo "hi"; ?>', 'php', tmpWs, { sandboxBackend: makeMockBackend('local/reduced') });
        expect(result.verdict).toBe('sandbox-unavailable');
    });

    it('returns sandbox-unavailable for java-maven with local backend', async () => {
        const result = await runLocalTest('public class T {}', 'java-maven', tmpWs, { sandboxBackend: makeMockBackend('local') });
        expect(result.verdict).toBe('sandbox-unavailable');
    });

    it('returns sandbox-unavailable for dotnet with local backend', async () => {
        const result = await runLocalTest('class T {}', 'dotnet', tmpWs, { sandboxBackend: makeMockBackend('local') });
        expect(result.verdict).toBe('sandbox-unavailable');
    });

    it('allows go with docker backend (mocked)', async () => {
        const result = await runLocalTest(
            'package main_test\nimport "testing"\nfunc TestSecureCodeProof(t *testing.T) { t.Log("ok") }',
            'go', tmpWs, { sandboxBackend: makeMockBackend('docker') },
        );
        expect(result.verdict).toBe('pass');
    });

    it('allows JS with local backend (unchanged behavior)', async () => {
        const result = await runLocalTest('console.log("PASS: ok");', 'node', tmpWs, { sandboxBackend: makeMockBackend('local') });
        expect(result.verdict).toBe('pass');
    });

    it('allows Python with local backend (unchanged behavior)', async () => {
        const result = await runLocalTest('print("PASS: ok")', 'python', tmpWs, { sandboxBackend: makeMockBackend('local') });
        expect(result.verdict).toBe('pass');
    });
});

describe('offline deps failure → "couldn\'t test" mapping', () => {
    function makeMockBackendWithOutput(output: string): SandboxBackend {
        return {
            name: 'docker',
            available: true,
            async execute(): Promise<SandboxExecuteResult> {
                return { verdict: 'fail', output, exitCode: 1, backend: 'docker' };
            },
        };
    }

    let tmpWs: string;
    beforeEach(() => { tmpWs = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-offln-')); });
    afterEach(() => { try { fs.rmSync(tmpWs, { recursive: true, force: true }); } catch {} });

    it('go: "cannot find module" → "couldn\'t test: dependencies not available offline"', async () => {
        const result = await runLocalTest(
            'package main_test', 'go', tmpWs,
            { sandboxBackend: makeMockBackendWithOutput('go: cannot find module providing package github.com/gin-gonic/gin: no network') },
        );
        expect(result.verdict).toBe('error');
        expect(result.output).toContain("couldn't test: dependencies not available offline");
        expect(result.output).toContain('cannot find module');
    });

    it('maven: "Could not resolve dependencies" → "couldn\'t test"', async () => {
        const result = await runLocalTest(
            'public class T {}', 'java-maven', tmpWs,
            { sandboxBackend: makeMockBackendWithOutput('Could not resolve dependencies for project com.example:app') },
        );
        expect(result.verdict).toBe('error');
        expect(result.output).toContain("couldn't test");
    });

    it('dotnet: NU1101 → "couldn\'t test"', async () => {
        const result = await runLocalTest(
            'class T {}', 'dotnet', tmpWs,
            { sandboxBackend: makeMockBackendWithOutput('error NU1101: Unable to find package xunit') },
        );
        expect(result.verdict).toBe('error');
        expect(result.output).toContain("couldn't test");
    });

    it('bundler: "Could not find gem" → "couldn\'t test" with vendor hint', async () => {
        const result = await runLocalTest(
            'puts "hi"', 'ruby', tmpWs,
            { sandboxBackend: makeMockBackendWithOutput('Could not find gem rails in locally installed gems') },
        );
        expect(result.verdict).toBe('error');
        expect(result.output).toContain("couldn't test");
        expect(result.output).toContain('vendor/bundle');
    });

    it('php: vendor/autoload.php missing → "couldn\'t test" with composer hint', async () => {
        const result = await runLocalTest(
            '<?php', 'php', tmpWs,
            { sandboxBackend: makeMockBackendWithOutput("Failed opening required 'vendor/autoload.php'") },
        );
        expect(result.verdict).toBe('error');
        expect(result.output).toContain("couldn't test");
        expect(result.output).toContain('composer install');
    });

    it('real test failure does NOT get the offline mapping', async () => {
        const result = await runLocalTest(
            'package main_test', 'go', tmpWs,
            { sandboxBackend: makeMockBackendWithOutput('FAIL: expected 200, got 403') },
        );
        expect(result.verdict).toBe('fail');
        expect(result.output).not.toContain("couldn't test");
    });
});

describe('targetFilePath threading — mock captures it', () => {
    let tmpWs: string;
    beforeEach(() => { tmpWs = fs.mkdtempSync(path.join(os.tmpdir(), 'ml-target-')); });
    afterEach(() => { try { fs.rmSync(tmpWs, { recursive: true, force: true }); } catch {} });

    it('passes targetFilePath through to the sandbox backend', async () => {
        let capturedOpts: SandboxExecuteOptions | null = null;
        const backend: SandboxBackend = {
            name: 'docker',
            available: true,
            async execute(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
                capturedOpts = opts;
                return { verdict: 'pass', output: 'PASS: ok', exitCode: 0, backend: 'docker' };
            },
        };
        await runLocalTest(
            'package main_test', 'go', tmpWs,
            { sandboxBackend: backend, targetFilePath: 'cmd/server/main.go' },
        );
        expect(capturedOpts).not.toBeNull();
        expect(capturedOpts!.targetFilePath).toBe('cmd/server/main.go');
    });
});

describe('JS/Python unchanged behavior', () => {
    let root: string;
    beforeEach(() => { root = mkdtempRoot(); });
    afterEach(() => { try { fs.rmSync(root, { recursive: true, force: true }); } catch {} });

    it('still detects express for JS', () => {
        write(root, 'package.json', JSON.stringify({ dependencies: { express: '4.18.0' } }));
        const info = detectRuntime(root);
        expect(info.runtime).toBe('node');
        expect(info.framework).toBe('express');
        expect(info.suggestedRunner).toBe(info.runner);
    });

    it('still detects flask for Python', () => {
        write(root, 'requirements.txt', 'flask==3.0.0\n');
        const info = detectRuntime(root, 'app.py');
        expect(info.runtime).toBe('python');
        expect(info.framework).toBe('flask');
        expect(info.suggestedRunner).toBe(info.runner);
    });

    it('JS safety check still works without language param', () => {
        const script = `import { readFileSync } from "node:fs";`;
        const result = checkTestSafety(script, '/ws');
        expect(result.allowed).toBe(false);
    });
});

describe('SECURECODE_PROOF_OUT and runner-specific adjustments', () => {
    function captureDockerArgs(): { captured: string[][]; backend: SandboxBackend } {
        const captured: string[][] = [];
        const backend: SandboxBackend = {
            name: 'docker',
            available: true,
            async execute(opts: SandboxExecuteOptions): Promise<SandboxExecuteResult> {
                captured.push([opts.runner || '', opts.script || '', JSON.stringify(opts)]);
                return { verdict: 'pass', output: 'PASS: ok', exitCode: 0, backend: 'docker' };
            },
        };
        return { captured, backend };
    }

    it('SECURECODE_PROOF_OUT env var is set for all compiled-lang runners', () => {
        for (const runner of ['go', 'ruby', 'php', 'java-maven', 'java-gradle', 'dotnet']) {
            const placement = buildCompiledLangPlacement(runner, 'test', 'target.go');
            expect(placement).toBeDefined();
        }
    });

    it('buildCompiledLangPlacement: gradle runCmd includes --no-daemon', () => {
        const p = buildCompiledLangPlacement('java-gradle', 'package com.ex;\npublic class ScProofTest {}');
        expect(p.runCmd).toContain('--no-daemon');
    });

    it('buildCompiledLangPlacement: dotnet runCmd targets ScProof subdir', () => {
        const p = buildCompiledLangPlacement('dotnet', 'using Xunit;');
        expect(p.runCmd).toContain('dotnet test ScProof');
        expect(p.runCmd).toContain('--no-restore');
    });
});

describe('effectMock guard — does not write into bare temp or root dirs', () => {
    it('refuses to write into os.tmpdir()', () => {
        const tmpDir = os.tmpdir();
        createEffectMock(tmpDir);
        expect(fs.existsSync(path.join(tmpDir, 'node_modules', 'effect'))).toBe(false);
    });

    it('refuses to write into a filesystem root', () => {
        createEffectMock('/');
        createEffectMock('C:\\');
    });

    it('refuses when no package.json exists', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'effect-guard-'));
        try {
            createEffectMock(dir);
            expect(fs.existsSync(path.join(dir, 'node_modules', 'effect'))).toBe(false);
        } finally {
            try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
        }
    });

    it('writes when package.json exists', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'effect-guard-'));
        try {
            fs.writeFileSync(path.join(dir, 'package.json'), '{}', 'utf8');
            createEffectMock(dir);
            expect(fs.existsSync(path.join(dir, 'node_modules', 'effect', 'index.js'))).toBe(true);
        } finally {
            try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
        }
    });
});

const path = require("path");
const { toolMap } = require("./dist/tools/map");
const { toolAgentScan } = require("./dist/tools/agentScan");

const WORKSPACE = path.resolve(__dirname, "..", "test_lab", "synara");
const API_TOKEN = process.env.SECURECODE_API_TOKEN;
if (!API_TOKEN) { console.error("SECURECODE_API_TOKEN not set"); process.exit(1); }

const ctx = {
    apiUrl: "https://api.usesecurecode.tech",
    apiToken: API_TOKEN,
    workspaceRoot: WORKSPACE,
};

function logProgress(p, total, msg) {
    console.log(`  [${p}/${total}] ${msg}`);
}

async function main() {
    console.log("=== Step 1: Architecture Scout (map action:architecture) ===");
    console.log(`Workspace: ${WORKSPACE}`);
    console.log("");

    const archResult = await toolMap(ctx, {
        action: "architecture",
        depth: "standard",
        _progress: logProgress,
    });

    if (archResult.cached) {
        console.log("Architecture context loaded from cache.");
    }

    console.log("");
    console.log("Architecture Scout Result:");
    console.log("  Status:", archResult.status || "completed");
    console.log("  Steps used:", archResult.stepsUsed);
    console.log("  Cost: $", archResult.costSpentUsd?.toFixed(4));
    console.log("");

    if (!archResult.architecture) {
        console.error("ERROR: No architecture context returned.");
        console.error("Full result:", JSON.stringify(archResult, null, 2));
        process.exit(1);
    }

    const arch = archResult.architecture;
    console.log("Project type:", arch.project?.type);
    console.log("Frameworks:", arch.project?.frameworks?.join(", "));
    console.log("Runtimes:", arch.project?.runtimes?.join(", "));
    console.log("Package manager:", arch.project?.packageManager);
    console.log("Summary:", arch.summary);
    console.log("Completeness:", arch.completeness);
    console.log("");

    console.log("=== Important Files (ranked by security importance) ===");
    if (arch.importantFiles && arch.importantFiles.length > 0) {
        for (const f of arch.importantFiles) {
            console.log(`  [${f.importance}] ${f.file} (${f.role}) — ${f.reasons.join("; ")}`);
        }
    } else {
        console.log("  (none)");
    }
    console.log("");

    console.log("=== Trust Boundaries ===");
    if (arch.trustBoundaries && arch.trustBoundaries.length > 0) {
        for (const tb of arch.trustBoundaries) {
            console.log(`  ${tb.entry} — input: ${tb.inputType} — guard: ${tb.guard || "NONE"}`);
        }
    } else {
        console.log("  (none)");
    }
    console.log("");

    console.log("=== Security Controls ===");
    if (arch.securityControls && arch.securityControls.length > 0) {
        for (const sc of arch.securityControls) {
            console.log(`  [${sc.coverage}] ${sc.kind} at ${sc.location}${sc.notes ? " — " + sc.notes : ""}`);
        }
    } else {
        console.log("  (none)");
    }
    console.log("");

    console.log("=== Architecture Risks ===");
    if (arch.architectureRisks && arch.architectureRisks.length > 0) {
        for (const r of arch.architectureRisks) {
            console.log(`  [${r.severity}] ${r.title}: ${r.description} (${r.files.join(", ")})`);
        }
    } else {
        console.log("  (none)");
    }
    console.log("");

    console.log("=== Recommended Scan Order ===");
    if (arch.recommendedScanOrder && arch.recommendedScanOrder.length > 0) {
        for (const f of arch.recommendedScanOrder) {
            console.log(`  ${f}`);
        }
    } else {
        console.log("  (none)");
    }
    console.log("");

    // Step 2: Agent scan on top 3 important files
    const topFiles = (arch.importantFiles || []).slice(0, 3);
    if (topFiles.length === 0) {
        console.log("No important files to scan. Exiting.");
        process.exit(0);
    }

    console.log("=== Step 2: Agent Scan on top 3 important files ===");
    console.log("");

    for (const f of topFiles) {
        console.log(`--- Scanning: ${f.file} (${f.role}) ---`);
        try {
            const scanResult = await toolAgentScan(ctx, {
                filePath: f.file,
                _progress: logProgress,
            });

            console.log("  Status:", scanResult.status);
            console.log("  Steps used:", scanResult.stepsUsed);
            console.log("  Cost: $", scanResult.costSpentUsd?.toFixed(4));
            console.log("");

            const agentFindings = scanResult.agentFindings || [];
            console.log("  Findings (verified):", agentFindings.length);
            for (const finding of agentFindings) {
                console.log(`    [${finding.severity}] ${finding.type} at line ${finding.line}`);
                console.log(`      proven: ${finding.proven}, verificationLevel: ${finding.verificationLevel || 'unspecified'}`);
                if (finding.provenReason) console.log(`      reason: ${finding.provenReason.slice(0, 120)}`);
            }
            console.log("");

            const notes = scanResult.investigationNotes || [];
            console.log("  Investigation Notes (unproven):", notes.length);
            for (const note of notes) {
                console.log(`    [${note.priority}] ${note.title}`);
                console.log(`      file: ${note.file}${note.line ? ':' + note.line : ''}`);
                console.log(`      verificationLevel: ${note.verificationLevel}`);
                if (note.requiredEvidence && note.requiredEvidence.length > 0) {
                    console.log(`      requiredEvidence: ${note.requiredEvidence.join('; ')}`);
                }
            }
            console.log("");

            const gaps = scanResult.coverageGaps || [];
            console.log("  Coverage Gaps (incomplete):", gaps.length);
            for (const gap of gaps) {
                console.log(`    [${gap.priority}] ${gap.title}`);
                console.log(`      detail: ${gap.detail.slice(0, 150)}`);
                if (gap.suggestedNextAction) console.log(`      nextAction: ${gap.suggestedNextAction}`);
            }
            console.log("");
        } catch (err) {
            console.error(`  Scan failed for ${f.file}:`, err.message);
            console.error("");
        }
    }

    console.log("=== Done ===");
}

main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});

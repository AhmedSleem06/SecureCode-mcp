const path = require("path");
const { toolAgentScanBatch } = require("./dist/tools/agentScanBatch");

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
    console.log("=== Agent Scan Batch (map + architecture + sequential scan) ===");
    console.log(`Workspace: ${WORKSPACE}`);
    console.log("");

    const result = await toolAgentScanBatch(ctx, {
        topN: 3,
        architectureDepth: "standard",
        _progress: logProgress,
    });

    console.log("");
    console.log("=== Batch Result ===");
    console.log("  Status:", result.status);
    console.log("  Stop Reason:", result.stopReason);
    console.log("  Requested topN:", result.requestedTopN);
    console.log("  Selected files:", result.selectedFiles.join(", ") || "(none)");
    console.log("");

    console.log("=== Totals ===");
    console.log("  Completed:", result.totals.completed);
    console.log("  Incomplete:", result.totals.incomplete);
    console.log("  Failed:", result.totals.failed);
    console.log("  Not Started:", result.totals.notStarted);
    console.log("  Total findings:", result.totals.findings);
    console.log("  Total steps:", result.totals.stepsUsed);
    console.log("  Total cost: $", result.totals.costSpentUsd.toFixed(4));
    console.log("");

    for (const file of [...result.completed, ...result.incomplete, ...result.failed, ...result.notStarted]) {
        console.log(`--- ${file.filePath} (rank ${file.rank}, status: ${file.status}) ---`);
        if (file.cached) console.log("  (cached)");
        if (file.scanStatus) console.log("  Scan status:", file.scanStatus);
        if (file.terminationReason) console.log("  Termination:", file.terminationReason);
        if (file.error) console.log("  Error:", file.error.message);
        console.log("  Steps:", file.stepsUsed, "| Cost: $", file.costSpentUsd.toFixed(4));
        console.log("  Findings:", file.findings.length);
        for (const f of file.findings) {
            console.log(`    [${f.severity}] ${f.type} at line ${f.line}`);
        }
        console.log("  Investigation Notes:", file.investigationNotes.length);
        for (const n of file.investigationNotes) {
            console.log(`    [${n.priority}] ${n.title}`);
        }
        console.log("  Coverage Gaps:", file.coverageGaps.length);
        for (const g of file.coverageGaps) {
            console.log(`    [${g.priority}] ${g.title}`);
        }
        console.log("");
    }

    console.log("=== Done ===");
}

main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});

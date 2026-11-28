# Changelog

## 0.13.0

- The agent scan is the only scanner. Removed: `securecode.scan`, `securecode.scan-batch`, `securecode.attack`, runtime probes, the server prove fallback, and the VS Code extension integration.
- Modes: `standard` (default) and `deep` (beta: threat checklist, red-team rounds and attack tests after one approval at the start of the scan).
- The finish checklist no longer rejects the agent's finish for missing evidence. Open questions are attached to the finding (`openQuestions`) and dropped once a proof answers them; who the attacker is and what they gain is judged by the AI reviewer. Source evidence follows the lines actually shown to the agent.
- Each finding reports whether the AI reviewer checked it (`aiReview`, plus `reviewCounts` on the result), including in cached results.
- Attack-test findings merge into an existing finding only when the analyst AI says it is the same issue; a merge never replaces the finding's own proof file.
- Framework-aware proofs: Express (full); Fastify, NestJS, Next.js, Koa, Hono, FastAPI, Flask, Django (beta); Docker sandboxes for Go, Ruby, PHP, Java (Maven, Gradle) and .NET.
- `securecode.memory` replaces the four memory tools; `decide-finding` gains decision `clear` (replaces `clear-finding-reviews`).
- `scan-dependencies`: full advisories (real severities, smallest safe upgrade), 13 lockfile formats. `scan-secrets`: rebuilt detector.
- CLI: `securecode-mcp scan --mode <standard|deep>`; `--depth` was removed.

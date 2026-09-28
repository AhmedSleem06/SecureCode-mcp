/**
 * Observation size limits shared by the scan executor and the
 * investigation state.
 *
 * Lives in a leaf module (not the executor) so pure state code can import
 * the cap without pulling in the executor's tool-dependency graph — and so
 * test suites that mock the executor don't have to re-export it.
 */

/** Hard cap on a single tool observation's character count. */
export const MAX_OBSERVATION_CHARS = 16000;

/** Files above this line count return a function map instead of raw content. */
export const LARGE_FILE_THRESHOLD = 300;

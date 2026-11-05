// Shared scratch root for the test suite.
//
// Every test directory lives under the workspace `.dsh-tmp/` (git-ignored and
// oxlint-ignored) instead of the OS temp dir: a run then leaves no ACL
// artifacts, hardened dirs or temp trees outside the project.

import { mkdirSync } from 'node:fs'
import path from 'node:path'

/** Absolute scratch root: `<cwd>/.dsh-tmp`. Created on import so
 * mkdtempSync/mkdirSync callers only need to add their own subdirectory. */
export const SCRATCH_ROOT = path.join(process.cwd(), '.dsh-tmp')

mkdirSync(SCRATCH_ROOT, { recursive: true })
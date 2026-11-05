// FFI patch installation (dsh-acl-sandbox-patch scheme, lib/preload.cjs).
//
// Loads the compiled preload core and arranges for this process (and every
// node child it spawns) to preload it, so the sandbox's own SetNamedSecurityInfoW
// grantWrite call degrades to DACL-only instead of failing on a workspace whose
// DACL cannot take the Low-integrity label.

import { copyFileSync, mkdirSync, readdirSync, rmSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

/** Minimal projection of lib/preload.cjs exports used by the host entry. */
export interface PreloadExports {
	install(): void
	clearDegradedState(): void
	isDegraded(): boolean
	workspaceHasLowLabel(dir: string): boolean | null
	markDegraded(): void
	stateFilePaths(): string[]
	[key: string]: unknown
}

const PRELOAD = fileURLToPath(new URL('./preload.cjs', import.meta.url))
let preloadRef: PreloadExports | null = null

/** Load the compiled preload core once. Returns null when it cannot be required. */
export function loadPreload(): PreloadExports | null {
	if (preloadRef) {
		return preloadRef
	}
	try {
		preloadRef = createRequire(import.meta.url)('./preload.cjs') as PreloadExports
	} catch {
		preloadRef = null
	}
	return preloadRef
}

/** Directory this plugin owns inside a scratch root. The root itself
 * (`.dsh-tmp`, or `%TEMP%` on the fallback path) is shared with other tooling
 * and is never removed. */
const SCRATCH_NAME = 'dsh-grantwrite-patch'

/** Scratch roots in preference order: the workspace `.dsh-tmp` first (nothing
 * written outside the project tree), the OS temp dir as the fallback. */
function scratchRoots(base?: string): string[] {
	const workspace = path.join(base ?? process.cwd(), '.dsh-tmp', SCRATCH_NAME)
	const temp = path.join(os.tmpdir(), SCRATCH_NAME)
	return workspace === temp ? [workspace] : [workspace, temp]
}

/** Paths a previous run may have used for this plugin's preload copy. */
function ownPreloadCopies(base?: string): string[] {
	return scratchRoots(base).map((root) => path.join(root, 'preload.cjs'))
}

/**
 * NODE_OPTIONS is split on whitespace: the preload path must not contain
 * spaces. When the plugin path does, copy preload.cjs into the workspace
 * scratch dir (`<cwd>/.dsh-tmp/dsh-grantwrite-patch`); fall back to the OS temp
 * dir when that path has spaces or is not writable.
 */
export function pickPreloadPath(base?: string): string {
	if (!/\s/.test(PRELOAD)) {
		return PRELOAD
	}
	for (const root of scratchRoots(base)) {
		if (/\s/.test(root)) {
			continue
		}
		try {
			mkdirSync(root, { recursive: true })
			const copy = path.join(root, 'preload.cjs')
			copyFileSync(PRELOAD, copy)
			return copy
		} catch {
			/* try the next root */
		}
	}
	return PRELOAD
}

/**
 * Remove this plugin's own scratch copies once they are stale.
 *
 * The only artifact the plugin ever writes to a scratch root is the space-free
 * copy of preload.cjs (see pickPreloadPath) and it is rewritten on demand, so a
 * copy whose newest mtime is older than `maxAgeDays` is dead weight. A root is
 * skipped entirely while NODE_OPTIONS still points at it, because a live runner
 * would lose its preload on the next spawn.
 *
 * @param maxAgeDays whole days a copy may stay unused before it is removed
 * @param base workspace root holding `.dsh-tmp` (default: process.cwd())
 * @returns the number of directories reclaimed
 */
export function sweepStaleTempArtifacts(maxAgeDays = 7, base?: string): number {
	const live = process.env.NODE_OPTIONS ?? ''
	let reclaimed = 0
	for (const dir of scratchRoots(base)) {
		if (live.includes(dir)) {
			continue
		}
		let newest: number
		try {
			newest = statSync(dir).mtimeMs
		} catch {
			continue
		}
		try {
			for (const name of readdirSync(dir)) {
				newest = Math.max(newest, statSync(path.join(dir, name)).mtimeMs)
			}
		} catch {
			continue
		}
		if (Date.now() - newest < maxAgeDays * 86_400_000) {
			continue
		}
		try {
			rmSync(dir, { force: true, maxRetries: 2, recursive: true, retryDelay: 100 })
			reclaimed++
		} catch {
			/* best-effort: try the next root */
		}
	}
	return reclaimed
}

/** Make every node child process spawned from here preload the patch. Idempotent. */
export function ensureNodeOptions(base?: string): void {
	const arg = `--require=${pickPreloadPath(base)}`
	// Drop an earlier copy of this plugin's require (the scratch dir may have
	// moved between the workspace and the temp fallback) before appending the
	// current one, so repeated calls never stack.
	const own = new Set([PRELOAD, ...ownPreloadCopies(base)])
	const kept = (process.env.NODE_OPTIONS ?? '')
		.split(/\s+/)
		.filter((part) => part !== '' && !(part.startsWith('--require=') && own.has(part.slice('--require='.length))))
	kept.push(arg)
	process.env.NODE_OPTIONS = kept.join(' ')
}

/** Install the FFI patch into this process and its children. Never throws. */
export function installPatch(base?: string): boolean {
	const preload = loadPreload()
	if (!preload) {
		return false
	}
	try {
		preload.clearDegradedState()
		preload.install() // idempotent (guarded); koffi hook + shared api-table wrap
		ensureNodeOptions(base)
		return true
	} catch {
		return false
	}
}

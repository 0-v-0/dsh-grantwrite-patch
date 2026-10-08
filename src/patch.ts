// FFI patch installation (dsh-acl-sandbox-patch scheme, lib/preload.cjs).
//
// Loads the compiled preload core and arranges for this process (and every
// node child it spawns) to preload it, so the sandbox's own SetNamedSecurityInfoW
// grantWrite call degrades to DACL-only instead of failing on a workspace whose
// DACL cannot take the Low-integrity label.

import { copyFileSync, mkdirSync } from 'node:fs'
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
	if (preloadRef) {return preloadRef}
	try {
		preloadRef = createRequire(import.meta.url)('./preload.cjs') as PreloadExports
	} catch {
		preloadRef = null
	}
	return preloadRef
}

/**
 * NODE_OPTIONS is split on whitespace: the preload path must not contain
 * spaces. When the plugin path does, copy preload.cjs to a temp dir.
 */
export function pickPreloadPath(): string {
	if (!/\s/.test(PRELOAD)) {return PRELOAD}
	try {
		const dir = path.join(os.tmpdir(), 'dsh-grantwrite-patch')
		mkdirSync(dir, { recursive: true })
		const copy = path.join(dir, 'preload.cjs')
		copyFileSync(PRELOAD, copy)
		return copy
	} catch {
		return PRELOAD
	}
}

/** Make every node child process spawned from here preload the patch. Idempotent. */
export function ensureNodeOptions(): void {
	const arg = `--require=${pickPreloadPath()}`
	const current = (process.env.NODE_OPTIONS ?? '').trim()
	if (current.includes(arg)) {return}
	process.env.NODE_OPTIONS = current ? `${current} ${arg}` : arg
}

/** Install the FFI patch into this process and its children. Never throws. */
export function installPatch(): boolean {
	const preload = loadPreload()
	if (!preload) {return false}
	try {
		preload.clearDegradedState()
		preload.install() // idempotent (guarded); koffi hook + shared api-table wrap
		ensureNodeOptions()
		return true
	} catch {
		return false
	}
}

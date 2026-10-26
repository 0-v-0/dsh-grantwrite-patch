/**
 * Fire-and-forget repair passes scheduled from the command path.
 *
 * Everything here runs BESIDE the confined command, never before it: the
 * command path may not pay for an `icacls /T` walk, a `fsutil hardlink list`
 * round-trip or a pnpm store scan. Each pass therefore either fires once per
 * cooldown window and is tracked in {@link RecoveryState}, or (the capability
 * SID back-fill) runs inline but is bounded to a single root DACL edit.
 *
 * All four entry points are best-effort: a failure is logged at most once and
 * never rejects, because the FFI patch carries the command either way.
 *
 * Kept out of `index.ts` so that `apply()` / `decideWorkspace()` stay small
 * enough to own one change each (see the size limits in .oxlintrc.json).
 */
import { existsSync } from 'node:fs'
import path from 'node:path'
import type { ApplyDeps, RecoveryState } from './index.ts'
import type { ResolvedConfig } from './types.ts'
import { repairCapabilityTree, repairCapabilityTreeDeep } from './capability-repair.ts'
import { relinkNodeModules, repairStore } from './low-label-repair.ts'

// One background store repair per plugin start (see apply()).
let storeRepairStarted = false

/**
 * Capability-SID back-fill for pre-existing hardened subdirs (dsh #423/#9559).
 *
 * The delete/write deny is a DACL artifact (world Deny FILE_DELETE_CHILD),
 * unrelated to the Low label — so it must run even in a strict environment
 * where grantWrite succeeds with the label. Own cooldown; never throws.
 */
export function backfillCapabilitySids(
	root: string,
	opts: ResolvedConfig,
	state: RecoveryState,
	now: number,
): void {
	try {
		const last = state.capabilityRepaired.get(root)
		if (last === undefined || now - last >= opts.probeCooldownMs) {
			repairCapabilityTree(root, { timeoutMs: opts.repairTimeoutMs })
			state.capabilityRepaired.set(root, Date.now())
		}
	} catch {
		// best-effort: the FFI patch still carries the command either way
	}
}

/**
 * Background deep scan (fix-delete-acl.ts --all equivalent): walk the whole
 * tree with icacls /T (async) and back-fill hardened subdirs at any depth —
 * node_modules/.git internals included. Fire-and-forget so the command path is
 * never blocked by the /T walk; one run per root per probeCooldownMs.
 */
export function scheduleDeepScan(
	root: string,
	opts: ResolvedConfig,
	state: RecoveryState,
	hooks: ApplyDeps,
	now: number,
): void {
	if (!opts.deepScan) {
		return
	}
	const last = state.deepScanned.get(root)
	if (state.deepInFlight.has(root) || (last !== undefined && now - last < opts.probeCooldownMs)) {
		return
	}
	const deep = (hooks.deepRunner ?? repairCapabilityTreeDeep)(root, {
		timeoutMs: opts.repairTimeoutMs,
	})
		.then((outcome) => {
			state.deepScanned.set(root, Date.now())
			if (outcome.error) {
				console.warn(
					`[dsh-grantwrite-patch] deep capability backfill ${root} failed: ${outcome.error}`,
				)
			} else if (outcome.fixed.length > 0) {
				console.log(
					`[dsh-grantwrite-patch] deep capability backfill ${root}: fixed ${outcome.fixed.length} dir(s), skipped ${outcome.skipped}`,
				)
			}
		})
		.catch(() => {
			// best-effort: never let the background scan surface
		})
		.finally(() => {
			state.deepInFlight.delete(root)
		})
	state.deepInFlight.set(root, deep)
}

/**
 * Low-label node_modules relink (TS5033 family): re-link labeled native
 * binaries under <workspace>/node_modules to their clean store inode, so
 * native build tools (tsgo, esbuild) run at Medium integrity again. Own
 * cooldown (relinkCooldownMs); fire-and-forget — the command path must not
 * wait for the fsutil/icacls round-trips. Never throws. Skipped entirely when
 * the workspace has no node_modules (cheap, keeps tests inert).
 */
export function scheduleRelink(
	root: string,
	opts: ResolvedConfig,
	state: RecoveryState,
	hooks: ApplyDeps,
	now: number,
): void {
	if (
		!opts.lowLabelRepair ||
		!existsSync(path.join(root, 'node_modules')) ||
		state.relinkInFlight.has(root)
	) {
		return
	}
	const last = state.relinked.get(root)
	if (last !== undefined && now - last < opts.relinkCooldownMs) {
		return
	}
	const relink = (hooks.relinker ?? relinkNodeModules)(root)
		.then((outcome) => {
			state.relinked.set(root, Date.now())
			if (outcome.blocked) {
				console.warn(
					`[dsh-grantwrite-patch] node_modules carries the Low label (strict workspace); relink cannot help ${root}`,
				)
			} else if (outcome.error) {
				console.warn(
					`[dsh-grantwrite-patch] node_modules relink ${root} failed: ${outcome.error}`,
				)
			} else if (outcome.fixed.length > 0) {
				console.log(
					`[dsh-grantwrite-patch] relinked ${outcome.fixed.length} Low-labeled native(s) in ${root}/node_modules, skipped ${outcome.skipped}`,
				)
			}
		})
		.catch(() => {
			// best-effort: never let the relink surface
		})
		.finally(() => {
			state.relinkInFlight.delete(root)
		})
	state.relinkInFlight.set(root, relink)
}

/**
 * Background store repair (once per plugin start): reverse-map labeled native
 * binaries in the pnpm store and swap their inodes so future installs link
 * clean files. Fire-and-forget; must never block startup. Windows-only and
 * `lowLabelRepair`-gated: the store paths are meaningless elsewhere.
 */
export function scheduleStoreRepair(opts: ResolvedConfig, deps: ApplyDeps): void {
	if (!opts.lowLabelRepair || process.platform !== 'win32' || storeRepairStarted) {
		return
	}
	storeRepairStarted = true
	const storeRun = (deps.storeRepairer ?? repairStore)({
		fullScan: opts.storeFullScan,
		repoScanRoots: opts.repoScanRoots,
		storeDirs: opts.storeDirs,
	})
		.then((outcome) => {
			if (outcome.error) {
				console.warn(`[dsh-grantwrite-patch] store repair failed: ${outcome.error}`)
			} else if (outcome.fixed.length > 0) {
				console.log(
					`[dsh-grantwrite-patch] store repair: cleaned ${outcome.fixed.length} Low-labeled store inode(s), skipped ${outcome.skipped}`,
				)
			}
		})
		.catch(() => {
			// best-effort: a failed store repair never blocks the plugin
		})
	void storeRun
}
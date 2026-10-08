// Workspace-size probe: count directory-tree objects (files + dirs) up to a
// threshold, so a huge workspace can be detected cheaply and routed to the
// persistent ACL-repair path instead of paying the degraded-mode full-tree
// DACL propagation on every DSH restart.

import { opendir } from 'node:fs/promises'
import path from 'node:path'

export interface ProbeResult {
	/** true when the tree reached `threshold` objects before the walk finished. */
	large: boolean
	/** Objects counted (files + dirs). Capped at `threshold` when large. */
	objects: number
}

/**
 * Count objects under `root` depth-first until `threshold` is reached or the
 * walk finishes. Timeout and unreadable subtrees resolve conservatively:
 * a timed-out walk reports `large` (treat an unknown huge tree as huge),
 * an unreadable root reports `large: false` (let the FFI patch carry it).
 *
 * Note: fs.opendir does not support AbortSignal, so the abort is checked
 * between directory entries — a single huge directory can overrun the
 * timeout by one readdir, which is fine for a size decision.
 */
export async function probeWorkspaceSize(
	root: string,
	threshold: number,
	timeoutMs: number,
): Promise<ProbeResult> {
	let objects = 0
	let timedOut = false
	const walk = async (dir: string): Promise<boolean> => {
		if (timedOut) {return true}
		let handle
		try {
			handle = await opendir(dir)
		} catch {
			return false // unreadable subtree: skip it, not fatal
		}
		try {
			for await (const entry of handle) {
				if (timedOut) {return true}
				objects += 1
				if (objects >= threshold) {return true}
				if (entry.isDirectory()) {
					if (await walk(path.join(dir, entry.name))) {return true}
				}
			}
			return false
		} catch {
			return timedOut
		} finally {
			await handle.close().catch(() => {})
		}
	}

	const timer = setTimeout(() => {
		timedOut = true
	}, timeoutMs)

	try {
		if (await walk(root)) {return { large: true, objects: threshold }}
		return { large: false, objects }
	} finally {
		clearTimeout(timer)
	}
}

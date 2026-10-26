/**
 * Low-integrity label cascade repair (TS5033 / `Access is denied` family).
 *
 * The Windows sandbox's `grantWrite` stamps `Mandatory Label\Low Mandatory
 * Level` onto the workspace root (capability ACE + world deny + label in one
 * SetNamedSecurityInfoW). The label ACE is inheritable, so the full tree —
 * including node_modules natives — is labeled on first provisioning. Because
 * pnpm links packages with hard links, one labeled inode is shared by the pnpm
 * store and every repo that links the same binary; Windows then forces any
 * process launched from a Low-labeled exe to Low integrity, which cannot write
 * to ordinary Medium outputs (`TS5033 ... Access is denied`, esbuild temp
 * removal in dsh #10379).
 *
 * Two repair passes, both idempotent and never throwing:
 *  - {@link repairStore} (background, once per plugin start): reverse-map
 *    labeled native binaries under known repos to their store paths via
 *    `fsutil hardlink list`, verify each candidate is a real PE, then replace
 *    the store inode (copy to a temp sibling + rename) so future installs link
 *    a clean file. Store files are outside any workspace, so the temp sibling
 *    inherits no Low label.
 *  - {@link relinkNodeModules} (before each confined command): re-link labeled
 *    native binaries under `<workspace>/node_modules` to their (now clean)
 *    store inode. Only effective when the node_modules DIRECTORY itself is not
 *    labeled — a directory carrying the label re-labels any new file it
 *    creates, so that case is reported as blocked (needs the dsh side to stop
 *    stamping, or an elevated relabel).
 *
 * Label detection uses batched `icacls` (one spawn for ~50 files, no FFI/koffi
 * dependency); both `icacls` and `fsutil` are injectable for tests.
 */
import { spawnSync } from 'node:child_process'
import { existsSync, linkSync, readdirSync, rmSync, copyFileSync, renameSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { isPeFileSync } from './pe.ts'

export interface LowLabelOutcome {
	fixed: string[]
	skipped: number
	/** True when the workspace node_modules directory itself carries the Low
	 * label, so relinking cannot help (new hard links inherit the dir label). */
	blocked?: boolean
	error?: string
}

export interface LowLabelRepairOptions {
	/** icacls spawn; injectable for tests. Returns stdout. */
	icacls?: (args: string[]) => string
	/** fsutil hardlink list spawn; injectable for tests. */
	fsutil?: (args: string[]) => string
	/** pnpm store content directories (e.g. `<store root>/v11/files`). */
	storeDirs?: string[]
	/** Roots whose node_modules are scanned to reverse-map store pollution. */
	repoScanRoots?: string[]
	/** Also walk every file in every store dir (slow; off by default). */
	fullScan?: boolean
	/** Also repair non-native package files (plain .js/.ts etc. labeled store
	 * inodes) — pnpm hard-links every package file, so a labeled store inode
	 * breaks any later full-tree removal (pnpm layout migration, rm -rf
	 * node_modules) in every repo sharing it. Default true. */
	allFiles?: boolean
}

const NATIVE_RE = /\.(exe|dll|node)$/i
const SKIP_DIR_RE = /^(\.git|target|dist|node_modules\.dsh|\.dsh)$/i
const LOW_LABEL_RE = /Mandatory Label\\Low Mandatory Level|低强制级别/
/** Content-addressed pnpm store file layout: <storeRoot>\files\<xx>\<64-hex>.
 * The same pattern holds for every pnpm store (v3/v11, any root), so hardlink
 * targets can be classified without knowing the store location. */
const STORE_FILE_RE = /[\\/]files[\\/][0-9a-f]{2}[\\/][0-9a-f]{64}$/i

const defaultIcacls = (args: string[]): string => {
	const r = spawnSync('icacls', args, {
		encoding: 'utf8',
		windowsHide: true,
		timeout: 30_000,
		maxBuffer: 64 * 1024 * 1024,
	})
	return r.stdout ?? ''
}

const defaultFsutil = (args: string[]): string => {
	const r = spawnSync('fsutil', args, {
		encoding: 'utf8',
		windowsHide: true,
		timeout: 15_000,
	})
	return r.stdout ?? ''
}

/** Parse batched icacls stdout -> paths carrying the Low integrity label. */
export function parseIcaclsBatch(stdout: string): string[] {
	const hits: string[] = []
	let current: string | undefined
	let low = false
	for (const line of stdout.split(/\r?\n/)) {
		if (/^\S/.test(line)) {
			if (current !== undefined && low) {
				hits.push(current)
			}
			const q = line.match(/^"([^"]+)":\s/)
			const p = q !== null ? q[1] : line.match(/^([A-Za-z]:[\\/].*?):\s/)?.[1]
			current = p
			low = p !== undefined && LOW_LABEL_RE.test(line)
		} else if (current !== undefined && LOW_LABEL_RE.test(line)) {
			low = true
		}
	}
	if (current !== undefined && low) {
		hits.push(current)
	}
	return hits
}

/** All package files under `root` (node_modules trees); nativeOnly skips noise
 * dirs and keeps only native binaries (legacy behaviour). */
export function scanNodeModulesFiles(root: string, nativeOnly: boolean): string[] {
	const out: string[] = []
	const walk = (dir: string): void => {
		let entries
		try {
			entries = readdirSync(dir, { withFileTypes: true })
		} catch {
			return
		}
		for (const e of entries) {
			const p = join(dir, e.name)
			if (e.isDirectory()) {
				if (!SKIP_DIR_RE.test(e.name)) {
					walk(p)
				}
			} else if (!nativeOnly || NATIVE_RE.test(e.name)) {
				out.push(p)
			}
		}
	}
	walk(root)
	return out
}

/** Native binaries under `root` (node_modules trees); skips noise dirs. */
export function scanNativeBinaries(root: string): string[] {
	return scanNodeModulesFiles(root, true)
}

/** Labeled subset of `paths` via batched icacls. */
export function filterLowLabel(paths: string[], icacls: (args: string[]) => string = defaultIcacls): string[] {
	const low: string[] = []
	const BATCH = 50
	for (let i = 0; i < paths.length; i += BATCH) {
		const batch = paths.slice(i, i + BATCH)
		try {
			low.push(...parseIcaclsBatch(icacls(batch)))
		} catch {
			// one bad batch must not abort the pass
		}
	}
	return low
}

/** True when `path` (file or dir) carries the Low integrity label. */
export function hasLowLabelSync(
	path: string,
	icacls: (args: string[]) => string = defaultIcacls,
): boolean {
	try {
		return parseIcaclsBatch(icacls([path])).length > 0
	} catch {
		return false
	}
}

/** Hard-link targets of `file` (fsutil output, relative to the current volume). */
export function hardlinkTargets(
	file: string,
	fsutil: (args: string[]) => string = defaultFsutil,
): string[] {
	try {
		const out = fsutil(['hardlink', 'list', file])
		const drive = process.cwd().slice(0, 2) // e.g. 'D:'
		const targets: string[] = []
		for (const line of out.split(/\r?\n/)) {
			const t = line.trim()
			if (t.length === 0) {
				continue
			}
			if (/^[A-Za-z]:/.test(t)) {
				targets.push(t)
			} else if (t.startsWith('\\')) {
				targets.push(`${drive}${t}`)
			}
		}
		return targets
	} catch {
		return []
	}
}

/** Default pnpm store content dirs (env, `pnpm store path`, common locations). */
export function defaultStoreDirs(): string[] {
	const dirs = new Set<string>()
	const env = process.env.PNPM_STORE_DIR
	if (env !== undefined && env.trim().length > 0) {
		dirs.add(env.trim())
	}
	try {
		const r = spawnSync('pnpm', ['store', 'path'], {
			encoding: 'utf8',
			windowsHide: true,
			timeout: 10_000,
		})
		if (r.status === 0 && r.stdout !== null && r.stdout.trim().length > 0) {
			dirs.add(r.stdout.trim())
		}
	} catch {
		/* no pnpm on PATH */
	}
	const home = homedir()
	dirs.add(join(home, '.pnpm-store', 'v11', 'files'))
	dirs.add(join(home, '.local', 'share', 'pnpm', 'store', 'v3', 'files'))
	const localAppData = process.env.LOCALAPPDATA
	if (localAppData !== undefined) {
		dirs.add(join(localAppData, 'pnpm', 'store', 'v3', 'files'))
	}
	const existing = [...dirs].filter((d) => existsSync(d))
	return existing.length > 0 ? existing : [...dirs]
}

/** Default repo roots whose node_modules are reverse-mapped: conventional
 * dev roots under the home dir (gh/repos/projects/workspace) that exist.
 * Machine-specific roots (e.g. a second drive) are configured explicitly via
 * `repoScanRoots` — no host paths are hard-coded in the source. */
export function defaultRepoRoots(): string[] {
	return ['gh', 'repos', 'projects', 'workspace']
		.map((n) => join(homedir(), n))
		.filter((d) => existsSync(d))
}

/** True when `p` is a pnpm store object: content-addressed layout pattern, or
 * (fallback) under a configured store dir. Pattern match alone covers any
 * store location, so relink/repair need no machine-specific storeDirs. */
export function isStorePath(p: string, storeDirs: string[]): boolean {
	if (STORE_FILE_RE.test(p)) {
		return true
	}
	const lower = p.toLowerCase()
	return storeDirs.some((d) => lower.startsWith(d.toLowerCase()))
}

/** Replace the inode at `path` with a clean copy (temp sibling + rename).
 * The temp inherits the store dir ACL (no Low label), and rename-over
 * (MoveFileEx REPLACE_EXISTING under the hood) swaps the inode atomically. */
function replaceInode(path: string): boolean {
	try {
		const tmp = `${path}.dsh-clean.tmp`
		copyFileSync(path, tmp)
		renameSync(tmp, path)
		return true
	} catch {
		try {
			rmSync(`${path}.dsh-clean.tmp`, { force: true })
		} catch {
			/* best-effort */
		}
		return false
	}
}

/**
 * Background store repair (run once at plugin start).
 *
 * Primary path is reverse mapping: scan known repos' node_modules for labeled
 * native binaries, resolve their store paths via fsutil, verify PE, replace the
 * store inode. `fullScan` additionally walks every store file (slow). Never
 * throws; every candidate is PE-verified before replacement so a mis-detected
 * label can never corrupt a non-executable store object.
 */
export async function repairStore(opts: LowLabelRepairOptions = {}): Promise<LowLabelOutcome> {
	const outcome: LowLabelOutcome = { fixed: [], skipped: 0 }
	const icacls = opts.icacls ?? defaultIcacls
	const fsutil = opts.fsutil ?? defaultFsutil
	const storeDirs = opts.storeDirs ?? defaultStoreDirs()
	const repoRoots = opts.repoScanRoots ?? defaultRepoRoots()
	const allFiles = opts.allFiles ?? true

	const candidates = new Set<string>()
	for (const repo of repoRoots) {
		let entries: import('node:fs').Dirent[]
		try {
			entries = readdirSync(repo, { withFileTypes: true })
		} catch {
			continue
		}
		for (const e of entries) {
			if (!e.isDirectory() || e.name.startsWith('.')) {
				continue
			}
			const nm = join(repo, e.name, 'node_modules')
			if (!existsSync(nm)) {
				continue
			}
			let files: string[]
			try {
				files = scanNodeModulesFiles(nm, !allFiles)
			} catch {
				continue
			}
			for (const f of filterLowLabel(files, icacls)) {
				for (const t of hardlinkTargets(f, fsutil)) {
					if (isStorePath(t, storeDirs)) {
						candidates.add(t)
					}
				}
			}
		}
	}

	if (opts.fullScan === true) {
		for (const dir of storeDirs) {
			let files: string[]
			try {
				files = readdirSync(dir)
			} catch {
				continue
			}
			for (const name of files) {
				const p = join(dir, name)
				if (hasLowLabelSync(p, icacls)) {
					candidates.add(p)
				}
			}
		}
	}

	for (const p of candidates) {
		if (!allFiles && !isPeFileSync(p)) {
			outcome.skipped += 1
			continue
		}
		if (replaceInode(p)) {
			outcome.fixed.push(p)
		} else {
			outcome.skipped += 1
		}
	}
	return outcome
}

/**
 * Before-command relink: re-link labeled native binaries under
 * `<root>/node_modules` to their (clean) store inode. When the node_modules
 * directory itself carries the label, relinking cannot help (a new hard link
 * created in a labeled directory inherits the label) — reported as blocked.
 * Never throws.
 */
export async function relinkNodeModules(
	root: string,
	opts: LowLabelRepairOptions = {},
): Promise<LowLabelOutcome> {
	const outcome: LowLabelOutcome = { fixed: [], skipped: 0 }
	const icacls = opts.icacls ?? defaultIcacls
	const fsutil = opts.fsutil ?? defaultFsutil
	const storeDirs = opts.storeDirs ?? defaultStoreDirs()
	const allFiles = opts.allFiles ?? true
	const nm = join(root, 'node_modules')
	if (!existsSync(nm)) {
		return outcome
	}
	if (hasLowLabelSync(nm, icacls)) {
		outcome.blocked = true
		return outcome
	}
	let files: string[]
	try {
		files = scanNodeModulesFiles(nm, !allFiles)
	} catch {
		outcome.error = 'node_modules scan failed'
		return outcome
	}
	for (const f of filterLowLabel(files, icacls)) {
		const store = hardlinkTargets(f, fsutil).find((t) => isStorePath(t, storeDirs))
		if (store === undefined) {
			// No store hard-link target (file:/link: deps are copied, not
			// linked): swap the inode in place — copy+rename replaces the
			// directory entry, so the new file inherits the parent DACL without
			// the Low label. Only safe for non-shared files; hard-linked store
			// files take the rm+link path below.
			if (replaceInode(f)) {
				outcome.fixed.push(f)
			} else {
				outcome.skipped += 1
			}
			continue
		}
		// Only relink when the store target is already clean (the background
		// store repair may not have converged yet; next command will pick it up).
		if (hasLowLabelSync(store, icacls)) {
			outcome.skipped += 1
			continue
		}
		try {
			rmSync(f, { force: true })
			linkSync(store, f)
			outcome.fixed.push(f)
		} catch {
			outcome.skipped += 1
		}
	}
	return outcome
}

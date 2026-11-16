/**
 * Protected-DACL backfill (upstream dsh #8409 defect A, first reported as #423).
 *
 * `grantWrite` applies the capability Allow + world Deny DC + Low label to the
 * workspace ROOT only and relies on inheritance. A subdirectory whose DACL is
 * protected (`SE_DACL_PROTECTED` — `icacls /inheritance:r`, an ACL-preserving
 * copy, a backup restore) never receives either edit, and the exact-ACE skip
 * means it is never retried: the confined token — Low integrity, restricted to
 * logon + Everyone + the capability SID — is denied inside it forever.
 *
 * Both halves run in the HOST process:
 *  - detection reads the DACL through koffi (`acl-detect.ts`) — no child
 *    process, no temp file, nothing written into the user's workspace;
 *  - the fix goes through the official `AclWriteGrant`, with the same
 *    deterministic workspace SID the sandbox derived, so the three edits land
 *    byte-identical to the root's and the directory keeps its protected DACL.
 */
import { realpathSync } from 'node:fs'
import { createRequire } from 'node:module'
import { pathToFileURL } from 'node:url'
import { capabilitySids } from './capability-repair.ts'
import { walkProtectedDirs, type SddlReader, type WalkOptions } from './acl-detect.ts'

export { isProtectedSddl } from './acl-detect.ts'

/** Outcome of one protected-DACL pass. */
export interface ProtectedDaclOutcome {
	fixed: string[]
	/** Directories found to be protected and missing the capability Allow. */
	seen: number
	errors: string[]
	error?: string
}

/** Options shared by the shallow and the deep passes. */
export interface ProtectedDaclOptions {
	/** Capability SID override (defaults to the workspace root's own SID). */
	sid?: string
	/** Detection roots for the official ACL module; defaults to the DSH install. */
	moduleBases?: string[]
	/** Grant factory override (tests inject a stub instead of the official module). */
	grantFactory?: GrantFactory
	/** DACL reader override (tests inject a stub instead of the FFI one). */
	reader?: SddlReader
}

/**
 * Minimal surface of `@deepseek-ai/dsh-sandbox-windows-acl` this pass needs:
 * derive the workspace write SID, open one grant, add a path to it. Everything
 * else (ACE mask, deny scoping, label ACL, standing bookkeeping) stays inside
 * the official module.
 */
export interface AclGrantLike {
	add(dir: string, standing?: boolean): void
	dispose(): void
}

export interface AclModuleLike {
	AclWriteGrant: { create(writeSid: string): AclGrantLike }
	workspaceWriteSid(workspaceRoot: string): string
}

/** Opened grant plus the SID it was opened for. */
export interface GrantHandle {
	sid: string
	grant: AclGrantLike
}

/** Opens one standing grant for the workspace (official module by default). */
export type GrantFactory = (root: string) => Promise<GrantHandle | undefined>

/** Package that owns the grant implementation. */
const ACL_PACKAGE = '@deepseek-ai/dsh-sandbox-windows-acl'

/** Capability SID to look for: the root's own write SID when it carries one. */
export function workspaceCapabilitySid(root: string): string {
	try {
		return capabilitySids(root)[0] ?? ''
	} catch {
		return ''
	}
}

/** Candidate bases for resolving the official ACL module. */
function defaultBases(): string[] {
	const bases: string[] = []
	const entry = process.argv[1]
	if (typeof entry === 'string' && entry.length > 0) {
		bases.push(entry)
	}
	const override = process.env.DSH_GRANTWRITE_HOST_BASES
	if (override !== undefined && override.trim().length > 0) {
		bases.push(...override.split(process.platform === 'win32' ? ';' : ':').filter(Boolean))
	}
	bases.push(process.cwd())
	return bases
}

/**
 * Resolve the official ACL module from the running DSH installation. The plugin
 * does not depend on it (it is the host's package), so resolution goes through
 * the same base list the diagnose-script lookup uses. Undefined when the host
 * cannot be located (the caller then reports the miss instead of guessing).
 */
export async function loadAclModule(bases: string[] = defaultBases()): Promise<AclModuleLike | undefined> {
	for (const base of bases) {
		try {
			const require = createRequire(base)
			const entry = require.resolve(ACL_PACKAGE)
			// eslint-disable-next-line no-await-in-loop -- candidates are tried in order; the first hit wins
			const mod = (await import(pathToFileURL(entry).href)) as AclModuleLike
			if (typeof mod.workspaceWriteSid === 'function' && typeof mod.AclWriteGrant?.create === 'function') {
				return mod
			}
		} catch {
			/* try the next base */
		}
	}
	return undefined
}

/**
 * Default grant factory: the official module, with the SAME canonical workspace
 * SID the sandbox derived (the module reuses it, so the edits land on the exact
 * identity the confined token carries).
 */
export async function openOfficialGrant(root: string, bases?: string[]): Promise<GrantHandle | undefined> {
	const mod = await loadAclModule(bases)
	if (mod === undefined) {
		return undefined
	}
	const canonical = realpathSync.native(root)
	const sid = mod.workspaceWriteSid(canonical)
	const grant = mod.AclWriteGrant.create(sid)
	return { grant, sid }
}

/** Directories under `root` that are protected and miss the capability Allow. */
export function findProtectedDirs(
	root: string,
	opts: ProtectedDaclOptions & { recurse?: boolean } = {},
): { hits: string[]; errors: string[]; error?: string } {
	const walk: WalkOptions = { recurse: opts.recurse === true }
	if (opts.reader !== undefined) {
		walk.reader = opts.reader
	}
	const sid = opts.sid ?? workspaceCapabilitySid(root)
	if (sid === '') {
		// No capability SID on the root means the sandbox never granted this
		// workspace (read-only mode, or Windows ACL sandbox off): there is
		// nothing to back-fill, so do not walk and do not touch a DACL.
		return { errors: [], hits: [] }
	}
	walk.sid = sid
	return walkProtectedDirs(root, walk)
}

/** Apply the official three edits to each directory; standing ACES are kept. */
export async function grantProtectedDirs(
	root: string,
	dirs: string[],
	opts: ProtectedDaclOptions = {},
): Promise<ProtectedDaclOutcome> {
	const outcome: ProtectedDaclOutcome = { errors: [], fixed: [], seen: dirs.length }
	if (dirs.length === 0) {
		return outcome
	}
	const factory = opts.grantFactory ?? ((workspaceRoot: string) => openOfficialGrant(workspaceRoot, opts.moduleBases))
	const handle = await factory(root)
	if (handle === undefined) {
		outcome.error = `cannot resolve ${ACL_PACKAGE} from the DSH installation`
		return outcome
	}
	try {
		for (const dir of dirs) {
			try {
				handle.grant.add(dir, true)
				outcome.fixed.push(dir)
			} catch (e) {
				outcome.errors.push(`${dir}: ${e instanceof Error ? e.message : String(e)}`)
			}
		}
	} finally {
		try {
			handle.grant.dispose()
		} catch {
			/* the standing edits outlive the grant; dispose only frees SIDs */
		}
	}
	return outcome
}

/**
 * Find and repair protected directories. Shallow by default (the root's direct
 * children); `recurse` walks the whole tree. Never throws.
 */
export async function repairProtectedDaclTree(
	root: string,
	opts: ProtectedDaclOptions & { recurse?: boolean } = {},
): Promise<ProtectedDaclOutcome> {
	const scan = findProtectedDirs(root, opts)
	if (scan.error !== undefined) {
		return { error: scan.error, errors: scan.errors, fixed: [], seen: 0 }
	}
	const outcome = await grantProtectedDirs(root, scan.hits, opts)
	outcome.errors.push(...scan.errors)
	return outcome
}

/** Full-tree pass (background entry point); same semantics as the shallow one. */
export function repairProtectedDaclTreeDeep(
	root: string,
	opts: ProtectedDaclOptions = {},
): Promise<ProtectedDaclOutcome> {
	return repairProtectedDaclTree(root, { ...opts, recurse: true })
}

/**
 * Capability-SID backfill for pre-existing hardened subdirectories.
 *
 * Root cause (upstream deepseek-ai/deepseek-harness discussions #423 / #9559 /
 * #8421): the sandbox's `grantWrite` injects a capability-SID Allow
 * (GRANT_MASK = W,D,DC) plus a world-SID Deny FILE_DELETE_CHILD plus the Low
 * label onto the workspace root only, then relies on inheritance to cover the
 * tree. Windows propagates DACL changes to existing children but never
 * back-fills ACEs onto directories that already existed (or were moved in)
 * before the grant. Such directories keep the inherited Deny and never receive
 * the capability Allow, so the confined token — whose restricted SID list is
 * logon + Everyone + capability SID — can no longer delete inside them.
 *
 * Fix, matching dsh's own design (no broadened grant): explicitly back-fill
 * the root's capability-SID Allow onto every hardened subdirectory. The
 * restricted list contains the capability SID, so the Allow hits and delete /
 * write paths come back; scope stays inside the workspace.
 *
 * Notes:
 *  - icacls cannot name a capability SID ("trust relationship failed") — it
 *    resolves account names through LSA. Set-Acl with a SecurityIdentifier
 *    works, so repair spawns powershell.
 *  - The grant must include Read: after a hardened subdirectory lost its
 *    inherited read ACEs, a confined process gets EPERM on reads otherwise.
 *  - Only the root's own capability SIDs are reused; nothing else is granted
 *    and no deny ACEs are touched, so this is not a confinement bypass.
 */
import { execFile as execFileCb, execFileSync, spawnSync } from 'node:child_process'
import { readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

/** An ACE line carrying the world-SID delete-child deny. */
const WORLD_DENY_DC_RE = /(?:Everyone|S-1-1-0):.*\(DENY\).*\(DC\)/
/** Capability SIDs (write SIDs) as rendered by icacls. */
const CAPABILITY_SID_RE = /S-1-4-[0-9-]+/g

export interface CapabilityRepairOutcome {
	fixed: string[]
	skipped: number
	error?: string
}

function icacls(args: string[], opts?: { maxBuffer?: number }): string {
	// Non-zero exits still carry useful output (e.g. unreadable entries); never throw.
	const r = spawnSync('icacls', args, {
		encoding: 'utf8',
		maxBuffer: opts?.maxBuffer ?? 4 * 1024 * 1024,
		timeout: 20_000,
	})
	return r.stdout ?? ''
}

/** Async icacls (used by the background deep scan). Non-zero exits still
 * carry useful output (e.g. DeletePending entries), so only reject when
 * stdout is empty. */
function execFileAsync(
	file: string,
	args: string[],
	opts: { maxBuffer?: number; timeout?: number },
): Promise<{ stdout: string }> {
	return new Promise((resolve, reject) => {
		execFileCb(
			file,
			args,
			{
				encoding: 'utf8',
				maxBuffer: opts.maxBuffer ?? 256 * 1024 * 1024,
				timeout: opts.timeout ?? 60_000,
				windowsHide: true,
			},
			(err, stdout) => {
				if (err && !(stdout && stdout.length > 0)) {
					reject(
						err instanceof Error
							? err
							: new Error(`icacls ${file} failed: ${err === null ? 'null' : JSON.stringify(err)}`),
					)
				} else {
					resolve({ stdout: stdout ?? '' })
				}
			},
		)
	})
}

/** Extract the directory path from an icacls line ("dir:" or "dir with space:"). */
function dirFromLine(line: string): string | undefined {
	const quoted = line.match(/^"([^"]+)"/)
	const quotedPath = quoted?.[1]
	if (quotedPath !== undefined) {
		return quotedPath.replace(/[\\/]+$/, '')
	}
	const m = line.match(/^(\S+)\s/)
	const token = m?.[1]
	if (token === undefined) {
		return undefined
	}
	return token.replace(/:$/, '').replace(/[\\/]+$/, '')
}

/** Capability SIDs present on the workspace root (the write SIDs to back-fill). */
export function capabilitySids(root: string): string[] {
	const out = icacls([root])
	return [...new Set(out.match(CAPABILITY_SID_RE) ?? [])]
}

/** True when `dir` is hardened: world Deny DC but no capability Allow. */
export function isHardenedDir(dir: string, sids: string[]): boolean {
	const out = icacls([dir])
	if (!WORLD_DENY_DC_RE.test(out)) {
		return false
	}
	if (sids.length > 0 && [...sids].some((s) => out.includes(`${s}:(`))) {
		return false
	}
	return true
}

/** Root-level subdirectories that are hardened: world Deny DC but no capability Allow. */
export function findHardenedDirs(root: string, sids: string[]): string[] {
	const hits: string[] = []
	for (const name of readdirSync(root)) {
		const p = join(root, name)
		try {
			if (!statSync(p).isDirectory()) {
				continue
			}
		} catch {
			continue
		}
		if (isHardenedDir(p, sids)) {
			hits.push(p)
		}
	}
	return hits
}

/**
 * Full-tree scan (`icacls <root> /T`, async): every directory at any depth that
 * carries a world Deny FILE_DELETE_CHILD. The root itself is excluded (its
 * delete path is covered by the write-SID Allow). The /T walk can be slow on a
 * huge tree, which is why this runs in the background, never on the command
 * path. Windows-only by construction.
 */
export async function scanTree(
	root: string,
	opts: { timeoutMs?: number; maxBuffer?: number } = {},
): Promise<string[]> {
	const { stdout } = await execFileAsync('icacls', [root, '/T'], {
		maxBuffer: opts.maxBuffer ?? 256 * 1024 * 1024,
		timeout: opts.timeoutMs ?? 120_000,
	})
	const hits = new Set<string>()
	for (const line of stdout.split(/\r?\n/)) {
		if (!WORLD_DENY_DC_RE.test(line)) {
			continue
		}
		const dir = dirFromLine(line)
		if (dir !== undefined && dir !== root) {
			hits.add(dir)
		}
	}
	return [...hits]
}

/** Back-fill one capability-SID Allow onto `dir`. Returns true on success. */
export function grantCapability(dir: string, sid: string): boolean {
	const ps = [
		'-NoProfile',
		'-NonInteractive',
		'-Command',
		`$sid = New-Object System.Security.Principal.SecurityIdentifier('${sid}');` +
			`$rights = [System.Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,Read';` +
			`$acl = Get-Acl '${dir}';` +
			`$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$rights,'ContainerInherit,ObjectInherit','None','Allow');` +
			`$acl.AddAccessRule($rule);Set-Acl '${dir}' $acl`,
	]
	const r = spawnSync('powershell', ps, {
		encoding: 'utf8',
		stdio: ['ignore', 'ignore', 'ignore'],
		timeout: 30_000,
	})
	return !r.error && r.status === 0
}

/**
 * Back-fill capability SIDs onto hardened root-level subdirectories.
 * Idempotent: dirs that are not hardened (or already carry the capability
 * Allow) are left untouched. Never throws. Windows-only by construction
 * (icacls / S-1-4-* / NTFS); on other platforms this is inert.
 */
export function repairCapabilityTree(
	root: string,
	opts: { timeoutMs?: number; sids?: string[] } = {},
): CapabilityRepairOutcome {
	const outcome: CapabilityRepairOutcome = { fixed: [], skipped: 0 }
	let sids: string[]
	try {
		sids = opts.sids ?? capabilitySids(root)
	} catch (e) {
		outcome.error = e instanceof Error ? e.message : String(e)
		return outcome
	}
	if (sids.length === 0) {
		outcome.skipped = 1
		return outcome
	}
	let hardened: string[]
	try {
		hardened = findHardenedDirs(root, sids)
	} catch (e) {
		outcome.error = e instanceof Error ? e.message : String(e)
		return outcome
	}
	for (const dir of hardened) {
		let ok = true
		for (const sid of sids) {
			ok = grantCapability(dir, sid) && ok
		}
		if (ok) {
			outcome.fixed.push(dir)
		} else {
			outcome.skipped += 1
		}
	}
	return outcome
}

/**
 * Full-tree capability back-fill (background): scan every hardened directory
 * at any depth (`icacls <root> /T`, async — the fix-delete-acl.ts --all
 * equivalent) and re-check each hit before granting, so dirs that already
 * carry the capability Allow (e.g. fixed by the shallow pass) are skipped.
 * Idempotent; never throws. Windows-only by construction.
 */
export async function repairCapabilityTreeDeep(
	root: string,
	opts: { timeoutMs?: number; sids?: string[] } = {},
): Promise<CapabilityRepairOutcome> {
	const outcome: CapabilityRepairOutcome = { fixed: [], skipped: 0 }
	let sids: string[]
	try {
		sids = opts.sids ?? capabilitySids(root)
	} catch (e) {
		outcome.error = e instanceof Error ? e.message : String(e)
		return outcome
	}
	if (sids.length === 0) {
		outcome.skipped = 1
		return outcome
	}
	let hardened: string[]
	try {
		hardened = await scanTree(
			root,
			opts.timeoutMs === undefined ? {} : { timeoutMs: opts.timeoutMs },
		)
	} catch (e) {
		outcome.error = `deep scan failed: ${e instanceof Error ? e.message : String(e)}`
		return outcome
	}
	for (const dir of hardened) {
		if (!isHardenedDir(dir, sids)) {
			outcome.skipped += 1
			continue
		}
		let ok = true
		for (const sid of sids) {
			ok = grantCapability(dir, sid) && ok
		}
		if (ok) {
			outcome.fixed.push(dir)
		} else {
			outcome.skipped += 1
		}
	}
	return outcome
}

/** Read a directory's ACL text (used by tests to assert the back-fill). */
export function readAclText(dir: string): string {
	try {
		return execFileSync('icacls', [dir], { encoding: 'utf8' }) ?? ''
	} catch {
		return ''
	}
}

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
 * This pass finds those directories and gives them the SAME three edits the
 * root carries, through the official `AclWriteGrant` (resolved from the running
 * DSH installation, so the label / deny stay byte-identical and the privilege
 * context is the one DSH itself uses). The directory keeps its protected DACL,
 * so the fix stays scoped to the tree the user protected.
 *
 * Detection needs `AreAccessRulesProtected`, which `icacls` text does not show,
 * so one PowerShell process walks the tree with `Get-Acl` (read-only — no
 * Add-Type, no Set-Acl: a confined shell cannot do either). The walk is the
 * expensive part on a big workspace, which is why it only ever runs in the
 * background (background.ts) — never on the command path.
 */
import { spawnSync } from 'node:child_process'
import { mkdirSync, realpathSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { capabilitySids } from './capability-repair.ts'

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
	timeoutMs?: number
	/** Capability SID override (defaults to the workspace root's own SID). */
	sid?: string
	/** Detection roots for the official ACL module; defaults to the DSH install. */
	moduleBases?: string[]
	/** Grant factory override (tests inject a stub instead of the official module). */
	grantFactory?: GrantFactory
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

/** Scratch directory name under the OS temp root (plugin-owned, never removed). */
const SCRATCH_NAME = 'dsh-grantwrite-patch'
/** Script file name inside {@link SCRATCH_NAME}. */
const SCRIPT_NAME = 'protected-dacl.ps1'
/** Package that owns the grant implementation. */
const ACL_PACKAGE = '@deepseek-ai/dsh-sandbox-windows-acl'

/**
 * Pure: does this DACL SDDL form carry `SE_DACL_PROTECTED`? The flag segment
 * sits between `D:` and the first ACE (`D:PAI(...)` = protected + auto-inherit,
 * `D:AI(...)` = inheriting).
 */
export function isProtectedSddl(sddl: string): boolean {
	const flags = /^D:([A-Z]*)/.exec(sddl)?.[1] ?? ''
	return flags.includes('P')
}

/**
 * Read-only PowerShell walk: report every directory whose DACL is protected and
 * which does not carry the capability Allow yet. Deliberately does NOT edit any
 * ACL — a confined shell has neither `SeSecurityPrivilege` (label) nor a writable
 * temp for `Add-Type`, so the edits belong to the official module in-process.
 */
const PS_SCAN = String.raw`param(
  [Parameter(Mandatory = $true)][string]$Root,
  [string]$Sid = '',
  [switch]$Recurse
)

$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$items = @(Get-Item -LiteralPath $Root -ErrorAction Stop)
if ($Recurse) {
	$items += @(Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force -ErrorAction SilentlyContinue)
}

$hits = New-Object System.Collections.Generic.List[string]
$errors = New-Object System.Collections.Generic.List[string]

foreach ($item in $items) {
	$itemPath = $item.FullName
	try {
		$acl = Get-Acl -LiteralPath $itemPath
		$sddl = $acl.GetSecurityDescriptorSddlForm('Access')
		$flags = [regex]::Match($sddl, '^D:([A-Z]*)').Groups[1].Value
		if (-not $flags.Contains('P')) { continue }
		if ($Sid -ne '' -and $sddl.Contains($Sid)) { continue }
		$hits.Add($itemPath)
	} catch {
		$errors.Add(('{0}: {1}' -f $itemPath, $_.Exception.Message))
	}
}

[pscustomobject]@{ hits = @($hits); errors = @($errors) } | ConvertTo-Json -Compress -Depth 3
`

let scriptPath: string | null | undefined

/** Candidate scratch directories, most portable first: the OS temp root, then
 * the workspace-local scratch (`.dsh-tmp`), which a confined shell can still
 * write when the OS temp root is not accessible to it. */
function scratchDirs(): string[] {
	return [join(os.tmpdir(), SCRATCH_NAME), join(process.cwd(), '.dsh-tmp', SCRATCH_NAME)]
}

/** Path to the extracted PowerShell program; extracts once per process. */
function ensureScript(): string | null {
	if (scriptPath !== undefined) {
		return scriptPath
	}
	for (const dir of scratchDirs()) {
		try {
			mkdirSync(dir, { recursive: true })
			const file = join(dir, SCRIPT_NAME)
			writeFileSync(file, PS_SCAN, 'utf8')
			scriptPath = file
			return scriptPath
		} catch {
			/* try the next scratch root */
		}
	}
	scriptPath = null
	return scriptPath
}

/** Windows PowerShell 5.1 first (always present), pwsh as the stripped-env fallback. */
function shells(): string[] {
	return process.platform === 'win32' ? ['powershell', 'pwsh'] : []
}

/** Build the argv for one attempt (script path followed by the switches). */
function scanArgs(file: string, root: string, sid: string, recurse: boolean): string[] {
	const args = ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file, '-Root', root, '-Sid', sid]
	if (recurse) {
		args.push('-Recurse')
	}
	return args
}

/** Parse the script's single JSON line; undefined on anything unexpected. */
export function parseScanOutcome(stdout: string): { hits: string[]; errors: string[] } | undefined {
	const line = stdout.trim().split(/\r?\n/).pop() ?? ''
	const start = line.indexOf('{')
	if (start < 0) {
		return undefined
	}
	try {
		const parsed = JSON.parse(line.slice(start)) as { hits?: unknown; errors?: unknown }
		const hits = Array.isArray(parsed.hits) ? parsed.hits.filter((p): p is string => typeof p === 'string') : []
		const errors = Array.isArray(parsed.errors) ? parsed.errors.filter((p): p is string => typeof p === 'string') : []
		return { errors, hits }
	} catch {
		return undefined
	}
}

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
	opts: ProtectedDaclOptions & { recurse?: boolean; sid?: string } = {},
): { hits: string[]; errors: string[]; error?: string } {
	const file = ensureScript()
	if (file === null) {
		return { error: 'cannot extract the PowerShell helper', errors: [], hits: [] }
	}
	const sid = opts.sid ?? workspaceCapabilitySid(root)
	const args = scanArgs(file, root, sid, opts.recurse === true)
	let lastError = ''
	for (const shell of shells()) {
		const r = spawnSync(shell, args, {
			encoding: 'utf8',
			maxBuffer: 16 * 1024 * 1024,
			timeout: opts.timeoutMs ?? 300_000,
			windowsHide: true,
		})
		const outcome = parseScanOutcome(r.stdout ?? '')
		if (outcome !== undefined) {
			return outcome
		}
		lastError = r.error?.message ?? r.stderr?.trim() ?? `${shell} exited ${r.status ?? 'signal'}`
	}
	return { error: lastError || 'no PowerShell available', errors: [], hits: [] }
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

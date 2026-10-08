// dsh-grantwrite-patch — auto-repair the Windows sandbox ACL failure
// `SetNamedSecurityInfoW failed (Win32 5): grantWrite` and retry the command.
//
// Default strategy (mode "auto"): install the FFI-level patch from the
// dsh-acl-sandbox-patch scheme (koffi hook + shared api-table wrap, shipped as
// lib/preload.cjs, MIT), so the grantWrite call succeeds in degraded mode
// without touching any ACL. Large workspaces are probed once and routed to the
// persistent ACL repair instead, because the degraded-mode full-tree DACL
// propagation would otherwise be paid on every DSH restart (44k objects ≈ 20s).
//
// The stock Windows shell tool provisions its workspace write grant by editing
// the workspace root DACL (AclWriteGrant.add -> grantWrite). When a directory on
// the chain lacks effective WRITE_DAC/WRITE_OWNER, SetNamedSecurityInfoW fails
// with Win32 5 (ERROR_ACCESS_DENIED) and every confined command on that
// workspace fails before spawn. The error-path wrapper stays as a fallback:
//
//   1. runs the diagnose-windows-sandbox-acl.ps1 resolved from the
//      @deepseek-ai/dsh-sandbox-windows-acl package assets (DSH >= 0.2.x),
//      against the workspace root (adds the signed-in user's full-control ACE where a right is
//      missing, removes foreign AppContainer package ACEs, verifies every
//      change, backs up each DACL);
//   2. if the repair verified, retries the original command once.
//
// The retry succeeds invisibly: the model sees the same result shape as a
// healthy run. If the repair is refused/failed, or the retry still throws, the
// original error propagates (optionally annotated with the RECAP summary), so a
// persistent ACL problem is never masked.

import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, statSync } from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import { installPatch, loadPreload } from './patch.ts'
import type {
	CtxLike,
	RepairConfig,
	RepairOutcome,
	RepairRunner,
	ResolvedConfig,
	ShellSpec,
} from './types.ts'
import { probeWorkspaceSize, type ProbeResult } from './size-probe.ts'

export const name = 'dsh-grantwrite-patch'
export const inject = { shell: null } // optional: no shell composition -> inert

// `SetNamedSecurityInfoW failed (Win32 5): grantWrite` — thrown by
// AclWriteGrant.add when the workspace DACL cannot take the write grant.
export const GRANT_WRITE_RE = /SetNamedSecurityInfoW failed \(Win32 \d+\): grantWrite/
// RECAP JSON contains `"nextAction":"verify_original_confined_operation"` when
// the repair verified. Match the token, not the exact layout.
export const VERIFY_ACTION_RE = /verify_original_confined_operation/

/** Directory name of the default DeepSeek Harness home under the OS home. */
const DSH_HOME_DIR_NAME = '.dsh'
/** Environment variable that overrides the default DeepSeek Harness home. */
const DSH_HOME_ENV = 'DSH_HOME'
/** Environment variable naming this DSH installation instance (state-file scoping). */

/** Expand supported tilde prefixes against the OS home (host `expandHomePath` equivalent). */
function expandHomePath(p: string): string {
	if (p === '~') {return os.homedir()}
	if (p.startsWith('~/') || p.startsWith('~\\')) {return path.join(os.homedir(), p.slice(2))}
	return p
}

/**
 * Resolve the single-root DeepSeek Harness home: an explicit configured path,
 * then `$DSH_HOME` (blank is treated as unset), then `~/.dsh`. Mirrors
 * @deepseek-ai/dsh-home-paths without depending on the host.
 */
export function resolveDshHome(env: Record<string, string | undefined> = process.env): string {
	const fromEnv = env[DSH_HOME_ENV]
	const base =
		fromEnv !== void 0 && fromEnv.trim().length > 0
			? fromEnv
			: path.join(os.homedir(), DSH_HOME_DIR_NAME)
	return path.resolve(expandHomePath(base))
}

/**
 * Resolve bases for Node package resolution: the DSH server entry, then cwd.
 */
function defaultBases(): string[] {
	const bases: string[] = []
	if (typeof process.argv[1] === 'string' && process.argv[1]) {bases.push(process.argv[1])}
	try {
		bases.push(process.cwd())
	} catch {
		/* cwd may be deleted */
	}
	return bases
}

/** createRequire for a file path or a directory. */
function makeRequire(base: string) {
	try {
		if (statSync(base).isDirectory())
			{return createRequire(path.join(base, '__plugin_resolve__.cjs'))}
	} catch {
		/* treat as a file path */
	}
	return createRequire(base)
}

/**
 * Resolve the bundled diagnose script from the sandbox package assets
 * (@deepseek-ai/dsh-sandbox-windows-acl ships assets/diagnose-windows-sandbox-acl
 * since 0.2.x). Returns null when the package (or its assets) is absent — the
 * repair path then fails closed and the FFI patch carries the command.
 */
export function resolveSandboxScript(bases: string[] = defaultBases()): string | null {
	for (const base of bases) {
		try {
			const req = makeRequire(base)
			const entry = req.resolve('@deepseek-ai/dsh-sandbox-windows-acl')
			const pkgRoot = path.dirname(path.dirname(entry)) // packageRoot/lib/index.js
			const script = path.join(
				pkgRoot,
				'assets',
				'diagnose-windows-sandbox-acl',
				'scripts',
				'diagnose-windows-sandbox-acl.ps1',
			)
			if (existsSync(script)) {return script}
		} catch {
			/* try next base */
		}
	}
	return null
}

export function resolveConfig(config: RepairConfig = {}): ResolvedConfig {
	return {
		appendDiagnostics: true,
		cooldownMs: 60000,
		enable: true,
		maxRetries: 1,
		mode: 'auto',
		objectThreshold: 20000,
		// Recovery/report data lives under the Harness home like every other user
		// directory, not as a stray sibling of it.
		outDir: path.join(resolveDshHome(), 'grantwrite-patch'),
		probeCooldownMs: 3600000,
		probeTimeoutMs: 10000,
		repairTimeoutMs: 120000,
		scriptPath: resolveSandboxScript() ?? '',
		...config,
	}
}

/** The Win32Error may arrive bare or wrapped (AggregateError with cleanup). */
export function isGrantWriteError(err: unknown): boolean {
	if (err instanceof Error) {
		if (GRANT_WRITE_RE.test(err.message)) {return true}
		if (err instanceof AggregateError) {
			for (const sub of err.errors) {if (isGrantWriteError(sub)) {return true}}
		}
		if (isGrantWriteError(err.cause)) {return true}
	}
	return false
}

/** Workspace root from the spec; fall back to workdir when policy is absent. */
export function resolveRoot(spec: ShellSpec | undefined): string | undefined {
	if (!spec) {return undefined}
	return spec.sandboxPolicy?.workspaceRoot ?? spec.workdir
}

/** Run the repair script; resolves the outcome, never rejects (caller retries). */
export function runRepairScript(root: string, opts: ResolvedConfig): Promise<RepairOutcome> {
	if (!opts.scriptPath) {
		// No bundled script available (e.g. DSH < 0.2.x sandbox package without
		// assets): fail closed; the FFI patch still carries the command.
		return Promise.resolve({
			ok: false,
			stderr: 'repair script not found: @deepseek-ai/dsh-sandbox-windows-acl assets missing',
		})
	}
	return new Promise((resolve) => {
		mkdirSync(opts.outDir, { recursive: true })
		const child = spawn(
			'pwsh',
			[
				'-NoLogo',
				'-NoProfile',
				'-NonInteractive',
				'-ExecutionPolicy',
				'Bypass',
				'-File',
				opts.scriptPath,
				'-Path',
				root,
				'-AllowRoot',
				root,
				'-Out',
				opts.outDir,
			],
			{ stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true },
		)
		let stdout = ''
		let stderr = ''
		child.stdout.on('data', (d: Buffer) => (stdout += d.toString()))
		child.stderr.on('data', (d: Buffer) => (stderr += d.toString()))
		const timer = setTimeout(() => child.kill(), opts.repairTimeoutMs)
		child.on('error', (e) => {
			clearTimeout(timer)
			resolve({ ok: false, stderr: `spawn pwsh failed: ${e.message}` })
		})
		child.on('close', (code) => {
			clearTimeout(timer)
			const recapLine = lastRecapLine(stdout)
			const trimmedStderr = stderr.trim()
			resolve({
				ok: isVerifiedRepair(stdout, code),
				...(recapLine === undefined ? {} : { recap: recapLine }),
				...(trimmedStderr === '' ? {} : { stderr: trimmedStderr }),
			})
		})
	})
}

/**
 * A verified repair: exit 0 plus evidence in stdout. The RECAP line carries
 * no nextAction (that lives in the full REPORT summary), so accept any of:
 * a verified verification record, a FIXED>0 SUMMARY count, or the
 * verify_original_confined_operation token.
 */
export function isVerifiedRepair(stdout: string, code: number | null): boolean {
	return (
		code === 0 &&
		(VERIFY_ACTION_RE.test(stdout) ||
			/"status":"verified"/.test(stdout) ||
			/FIXED=[1-9]\d*/.test(stdout))
	)
}

function lastRecapLine(stdout: string): string | undefined {
	const lines = stdout.split(/\r?\n/)
	for (let i = lines.length - 1; i >= 0; i--) {
		const line = lines[i]
		if (line === undefined) {continue}
		if (line.startsWith('RECAP ')) {return line.slice('RECAP '.length).trim()}
	}
	return undefined
}

export interface RecoveryState {
	// One in-flight repair per root; concurrent calls share it.
	inflight: Map<string, Promise<boolean>>
	// Last successful repair timestamp per root; cools down repeat repairs.
	lastRepair: Map<string, number>
	// Last probe/decision timestamp per root; avoids re-probing every command.
	decided: Map<string, number>
}

export function makeRecoveryState(): RecoveryState {
	return { decided: new Map(), inflight: new Map(), lastRepair: new Map() }
}

/**
 * Repair the ACL once per root (concurrent calls coalesce, cooldown applies).
 * Returns whether the repair verified.
 */
export function repairAcl(
	root: string,
	opts: ResolvedConfig,
	state: RecoveryState,
	runner: RepairRunner = runRepairScript,
): Promise<boolean> {
	const now = Date.now()
	const last = state.lastRepair.get(root)
	if (last !== undefined && now - last < opts.cooldownMs) {return Promise.resolve(false)}
	const existing = state.inflight.get(root)
	if (existing !== undefined) {return existing}
	const p = runner(root, opts)
		.then((outcome) => {
			if (outcome.ok) {state.lastRepair.set(root, Date.now())}
			return outcome.ok
		})
		.finally(() => state.inflight.delete(root))
	state.inflight.set(root, p)
	return p
}

/** Size probe signature; tests inject a stub. */
export type SizeProbe = (root: string, threshold: number, timeoutMs: number) => Promise<ProbeResult>
/** Label probe signature; tests inject a stub. Returns null when unknown. */
export type LabelProbe = (root: string) => boolean | null

/** Injectable collaborators for the workspace decision / command retry paths. */
export interface ApplyDeps {
	runner?: RepairRunner
	probe?: SizeProbe
	labelProbe?: LabelProbe
}

/**
 * Decide once per workspace (cached for probeCooldownMs): a strict environment
 * (Low label already present) needs nothing; a degraded large workspace gets a
 * proactive persistent ACL repair so it does not pay the full-tree DACL
 * propagation on every restart. Failures never throw — the FFI patch carries
 * the command either way.
 */
export async function decideWorkspace(
	root: string,
	opts: ResolvedConfig,
	state: RecoveryState,
	hooks: ApplyDeps = {},
): Promise<void> {
	const probe = hooks.probe ?? probeWorkspaceSize
	const labelProbe = hooks.labelProbe ?? (() => null)
	const runner = hooks.runner ?? runRepairScript
	const now = Date.now()
	const last = state.decided.get(root)
	if (last !== undefined && now - last < opts.probeCooldownMs) {return}

	let label: boolean | null = null
	try {
		label = labelProbe(root)
	} catch {
		label = null
	}
	if (label === true) {
		// Strict environment: grantWrite succeeds with the label, skip stays hot.
		state.decided.set(root, now)
		return
	}

	let large = false
	try {
		({ large } = await probe(root, opts.objectThreshold, opts.probeTimeoutMs))
	} catch {
		large = false
	}

	if (large) {
		// Persistent repair (user FullControl ACE) turns the workspace strict, so
		// later restarts skip the full-tree propagation. Best-effort: a failed
		// repair leaves the FFI patch to carry the degraded path.
		await repairAcl(root, opts, state, runner)
	}
	state.decided.set(root, Date.now())
}

/** Annotate a Win32Error with the repair summary for a persistent failure. */
export function annotateError(err: unknown, root: string, recap: string | undefined): unknown {
	if (!(err instanceof Error)) {return err}
	if (recap === undefined) {return err}
	const note = `; dsh-grantwrite-patch: ACL repair of ${root} did not help (recap: ${recap})`
	try {
		const copy = Object.assign(Object.create(Object.getPrototypeOf(err)), err)
		copy.message = `${err.message}${note}`
		return copy
	} catch {
		return err
	}
}

// ---------------------------------------------------------------------------
// FFI patch installation lives in ./patch.ts; re-exported for the host surface.

export { ensureNodeOptions, pickPreloadPath } from './patch.ts'

/**
 * Repair the ACL then retry `run`, once per attempt. Sequential by design — each
 * retry depends on the previous failure — so this recurses instead of looping.
 * Returns the command result on success, or the last grantWrite error once the
 * attempts are exhausted. Non-grantWrite errors propagate immediately, untouched.
 */
async function repairAndRetry(
	run: () => Promise<unknown>,
	repair: () => Promise<boolean>,
	attemptsLeft: number,
	lastErr: unknown,
): Promise<{ value: unknown } | { err: unknown }> {
	const repaired = await repair()
	if (!repaired) {return { err: lastErr }}
	try {
		return { value: await run() }
	} catch (err) {
		if (!isGrantWriteError(err)) {throw err}
		if (attemptsLeft <= 1) {return { err }}
		return repairAndRetry(run, repair, attemptsLeft - 1, err)
	}
}

export function apply(ctx: CtxLike, config: RepairConfig = {}, deps: ApplyDeps = {}): void {
	const {shell} = ctx
	if (!shell) {return}
	// Native hosts (dsh-pwsh-local/-sandbox, dsh-bash-local/-sandbox) expose
	// execute() and provisioning failures reject it; older compositions may
	// expose a run() convenience instead. Wrap whichever exists.
	const method: 'execute' | 'run' | undefined =
		typeof shell.execute === 'function'
			? 'execute'
			: (typeof shell.run === 'function'
				? 'run'
				: undefined)
	if (method === undefined) {return}
	const opts = resolveConfig(config)
	if (!opts.enable) {return}
	const orig = (shell[method] as (spec: ShellSpec) => Promise<unknown>).bind(shell)
	const state = makeRecoveryState()
	const runner = deps.runner ?? runRepairScript
	const probe = deps.probe ?? probeWorkspaceSize
	const labelProbe =
		deps.labelProbe ??
		((root: string) =>
			process.platform === 'win32' ? (loadPreload()?.workspaceHasLowLabel(root) ?? null) : null)

	if (opts.mode !== 'repair') {
		if (process.platform === 'win32') {installPatch()}
	}

	shell[method] = async (spec: ShellSpec): Promise<unknown> => {
		if (opts.mode === 'auto') {
			const root = resolveRoot(spec)
			if (root !== undefined) {
				await decideWorkspace(root, opts, state, { labelProbe, probe, runner })
			}
		}
		try {
			return await orig(spec)
		} catch (err) {
			if (!isGrantWriteError(err)) {throw err}
			const root = resolveRoot(spec)
			if (root === undefined) {throw err}

			const maxRetries = Math.max(0, Math.min(3, opts.maxRetries))
			const outcome =
				maxRetries > 0
					? await repairAndRetry(
							() => orig(spec),
							() => repairAcl(root, opts, state, runner),
							maxRetries,
							err,
						)
					: { err }
			if ('value' in outcome) {return outcome.value}
			// Persistent grantWrite failure: report it, optionally annotated.
			if (opts.appendDiagnostics) {
				const recap = state.lastRepair.has(root)
					? 'repaired but retry still fails'
					: 'repair not verified'
				throw annotateError(outcome.err, root, recap)
			}
			throw outcome.err
		}
	}
}

// Shared types. `ShellSpec` is a loose projection of dsh-shell's ShellExecSpec;
// the plugin only reads the fields it needs to locate the workspace root.

export interface ShellSandboxPolicy {
	mode?: string
	workspaceRoot?: string
}

export interface ShellSpec {
	command: string
	workdir?: string
	timeoutMs?: number
	signal?: AbortSignal
	dshEnv?: Record<string, string>
	sandboxPolicy?: ShellSandboxPolicy
	[key: string]: unknown
}

export interface RepairConfig {
	enable?: boolean
	/**
	 * auto (default): FFI patch (dsh-acl-sandbox-patch scheme) for normal workspaces,
	 *   persistent ACL repair for large ones (probed once, cached).
	 * patch: FFI patch only — never run the repair script proactively;
	 *   the error-path repair+retry is still kept as a fallback.
	 * repair: legacy behaviour — FFI patch disabled, repair only on error.
	 */
	mode?: 'auto' | 'patch' | 'repair'
	/** Workspace object count (files+dirs) at or above which a proactive repair is triggered. Default 20000. */
	objectThreshold?: number
	/** Size-probe timeout (ms); a timed-out probe counts as large. Default 10000. */
	probeTimeoutMs?: number
	/** How long a per-workspace probe/decision stays cached (ms). Default 3600000. */
	probeCooldownMs?: number
	/** Path to diagnose-windows-sandbox-acl.ps1. Default: resolved from
	 * @deepseek-ai/dsh-sandbox-windows-acl package assets (DSH >= 0.2.x). */
	scriptPath?: string
	/** Recovery/report directory (-Out). Default: $DSH_HOME/grantwrite-patch (~/.dsh/grantwrite-patch). */
	outDir?: string
	/** Repair-script timeout. Default 120000. */
	repairTimeoutMs?: number
	/** How many repair+retry rounds after the first grantWrite failure. Default 1. */
	maxRetries?: number
	/** Skip a second repair of the same root within this window (ms). Default 60000. */
	cooldownMs?: number
	/** Low-label node_modules relink cooldown per workspace (ms). Default 60000. */
	relinkCooldownMs?: number
	/** Append a short diagnosis to the thrown error when the retry still fails. Default true. */
	appendDiagnostics?: boolean
	/** When the diagnose script is unavailable (DSH 0.1.7) or fails, fall back to
	 * a bare `icacls <root> /grant "<user>:(OI)(CI)F"` so the repair path is not
	 * dead on 0.1.7. The fallback refuses drive roots (D:\) for safety. Default true. */
	grantFallback?: boolean
	/** Background full-tree capability back-fill (icacls <root> /T, async):
	 * after the shallow root-level pass, repair hardened subdirectories at any
	 * depth (the fix-delete-acl.ts --all equivalent) so no manual script is
	 * needed. Fire-and-forget, per-workspace probeCooldownMs cache. Default true. */
	deepScan?: boolean
	/**
	 * Low-integrity label cascade repair (TS5033 family): at plugin start,
	 * background-repair labeled native binaries in the pnpm store (reverse
	 * mapped from repo node_modules via fsutil hardlink list, PE-verified,
	 * inode-swapped); before each confined command, relink labeled node_modules
	 * natives to their clean store inode. Default true.
	 */
	lowLabelRepair?: boolean
	/** pnpm store content directories; default: env/`pnpm store path`/common paths. */
	storeDirs?: string[]
	/** Roots whose node_modules are reverse-mapped to find store pollution.
	 * Default: the `repos` sibling convention (a `gh` dir next to the DSH
	 * install) when present. */
	repoScanRoots?: string[]
	/** Also walk every store file (slow); off by default. */
	storeFullScan?: boolean
}

export interface ResolvedConfig extends RepairConfig {
	enable: boolean
	mode: 'auto' | 'patch' | 'repair'
	objectThreshold: number
	probeTimeoutMs: number
	probeCooldownMs: number
	scriptPath: string
	outDir: string
	repairTimeoutMs: number
	maxRetries: number
	cooldownMs: number
	relinkCooldownMs: number
	appendDiagnostics: boolean
	grantFallback: boolean
	deepScan: boolean
	lowLabelRepair: boolean
	storeFullScan: boolean
	storeDirs: string[]
	repoScanRoots: string[]
}

export interface RepairOutcome {
	ok: boolean
	recap?: string
	stderr?: string
}

/** Injectable repair runner; tests replace the real script with a stub. */
export type RepairRunner = (root: string, opts: ResolvedConfig) => Promise<RepairOutcome>

export interface CtxLike {
	shell?: {
		/** Native hosts expose execute() (returns a process handle; provisioning
		 * failures reject it). Older compositions may expose a run() convenience
		 * that resolves with the final result.
		 */
		execute?: (spec: ShellSpec) => Promise<unknown>
		run?: (spec: ShellSpec) => Promise<unknown>
		[key: string]: unknown
	}
	[key: string]: unknown
}

/**
 * In-process ACL reading for the protected-DACL pass.
 *
 * Detection needs `SE_DACL_PROTECTED`, which `icacls` text does not print, and a
 * confined shell cannot spawn `Set-Acl`/`Add-Type` at all. Both problems go away
 * by reading the security descriptor in the host process through `koffi` — the
 * same FFI the sandbox itself uses: `GetNamedSecurityInfoW` +
 * `ConvertSecurityDescriptorToStringSecurityDescriptorW`, then a pure-JS check of
 * the SDDL string. No child process, no temp file, no workspace write.
 */
import { readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { join } from 'node:path'

/** Minimal `koffi` surface used here. */
export interface KoffiLike {
	load(lib: string): { func(signature: string): (...args: unknown[]) => unknown }
	alloc(type: unknown, count: number): unknown
	decode(value: unknown, type: unknown, offset?: number): unknown
	pointer(type: unknown): unknown
}

/** Pointer helpers re-exported by the host's win32-process package. */
export interface Win32HelpersLike {
	allocPtrSlot(): unknown
	decodePtr(slot: unknown): unknown
	isNullPtr(value: unknown): boolean
}

/** The two host packages the reader needs. */
export interface HostFfi {
	koffi: KoffiLike
	win32: Win32HelpersLike
}

/** Cached host modules (one resolution per process). */
let cached: HostFfi | null | undefined

/** Candidate bases for resolving the host packages. */
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
 * Resolve `koffi` and the host's `win32-process` pointer helpers from the DSH
 * installation. Undefined on non-Windows hosts, or when the host cannot be
 * located — the caller then reports the miss instead of pretending it scanned.
 */
export function loadHostFfi(bases: string[] = defaultBases()): HostFfi | undefined {
	if (cached !== undefined) {
		return cached ?? undefined
	}
	if (process.platform !== 'win32') {
		cached = null
		return undefined
	}
	for (const base of bases) {
		try {
			const require = createRequire(base)
			const koffi = require('koffi') as KoffiLike
			const win32 = require('@deepseek-ai/dsh-win32-process') as Win32HelpersLike
			if (typeof koffi?.load === 'function' && typeof win32?.allocPtrSlot === 'function') {
				cached = { koffi, win32 }
				return cached
			}
		} catch {
			/* try the next base */
		}
	}
	cached = null
	return undefined
}

/** Reset the cached host modules (tests). */
export function resetHostFfi(): void {
	cached = undefined
}

/** Reads one directory's DACL as an SDDL string. */
export type SddlReader = (dir: string) => string

const SE_FILE_OBJECT = 1
const DACL_SECURITY_INFORMATION = 0x4
const SDDL_REVISION_1 = 1

/**
 * Build the SDDL reader: two FFI calls per directory, both read-only. Throws on
 * a Win32 error so the walker can attribute it to the path.
 */
/** Untyped native call: arguments are passed through, the return is a number. */
type NativeFn = (...args: unknown[]) => number

export function createSddlReader(ffi: HostFfi): SddlReader {
	const { koffi, win32 } = ffi
	const advapi32 = koffi.load('advapi32.dll')
	const kernel32 = koffi.load('kernel32.dll')
	const getNamed = (advapi32.func(
		'uint32 GetNamedSecurityInfoW(str16, int, uint32, void **, void **, void **, void **, void **)',
	) as unknown) as NativeFn
	const convert = (advapi32.func(
		'int ConvertSecurityDescriptorToStringSecurityDescriptorW(void *, uint32, uint32, void **, uint32 *)',
	) as unknown) as NativeFn
	const localFree = kernel32.func('void *LocalFree(void *)')

	return (dir: string): string => {
		const owner = win32.allocPtrSlot()
		const group = win32.allocPtrSlot()
		const dacl = win32.allocPtrSlot()
		const sacl = win32.allocPtrSlot()
		const sdSlot = win32.allocPtrSlot()
		const rc = getNamed(dir, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, owner, group, dacl, sacl, sdSlot)
		if (rc !== 0) {
			throw new Error(`GetNamedSecurityInfoW(${dir}) failed: Win32 ${rc}`)
		}
		const sd = win32.decodePtr(sdSlot)
		if (sd === null) {
			throw new Error(`GetNamedSecurityInfoW(${dir}) returned no descriptor`)
		}
		const strSlot = win32.allocPtrSlot()
		const lenSlot = koffi.alloc('uint32', 1)
		try {
			const ok = convert(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, strSlot, lenSlot)
			if (ok === 0) {
				throw new Error(`ConvertSecurityDescriptorToStringSecurityDescriptorW(${dir}) failed`)
			}
			const len = koffi.decode(lenSlot, 'uint32') as number
			const str = win32.decodePtr(strSlot)
			if (str === null) {
				throw new Error(`ConvertSecurityDescriptorToStringSecurityDescriptorW(${dir}) returned no string`)
			}
			try {
				// The pointer is a raw address (bigint): read its bytes and decode
				// them as UTF-16LE, dropping the terminator. `koffi.decode(ptr,
				// 'str16')` segfaults on a bigint pointer here.
				const bytes = koffi.decode(str, 'uint8', len) as number[]
				return Buffer.from(bytes).toString('utf16le').replace(/\0+$/u, '')
			} finally {
				localFree(str)
			}
		} finally {
			localFree(sd)
		}
	}
}

/**
 * Pure: does this DACL SDDL form carry `SE_DACL_PROTECTED`? The flag segment
 * sits between `D:` and the first ACE (`D:PAI(...)` = protected + auto-inherit,
 * `D:AI(...)` = inheriting).
 */
export function isProtectedSddl(sddl: string): boolean {
	const flags = /^D:([A-Z]*)/.exec(sddl)?.[1] ?? ''
	return flags.includes('P')
}

/** Result of one walk. */
export interface ProtectedWalk {
	hits: string[]
	errors: string[]
	error?: string
}

/** Options for {@link walkProtectedDirs}. */
export interface WalkOptions {
	/** Walk the whole tree instead of the root's direct children. */
	recurse?: boolean
	/** Capability SID that must be absent for a directory to count as missed. */
	sid?: string
	/** Reader override (tests inject a stub instead of the FFI one). */
	reader?: SddlReader
}

/**
 * Walk `root` and collect every directory whose DACL is protected and does not
 * carry the capability Allow yet. Never throws; junction/symlink children are
 * skipped so the walk cannot escape the workspace.
 */
export function walkProtectedDirs(root: string, opts: WalkOptions = {}): ProtectedWalk {
	const errors: string[] = []
	let { reader } = opts
	if (reader === undefined) {
		const ffi = loadHostFfi()
		if (ffi === undefined) {
			return { error: 'cannot resolve koffi / @deepseek-ai/dsh-win32-process from the DSH installation', errors, hits: [] }
		}
		reader = createSddlReader(ffi)
	}
	const hits: string[] = []
	const check = (dir: string): void => {
		let sddl: string
		try {
			sddl = reader(dir)
		} catch (e) {
			errors.push(`${dir}: ${e instanceof Error ? e.message : String(e)}`)
			return
		}
		if (!isProtectedSddl(sddl)) {
			return
		}
		if (opts.sid !== undefined && opts.sid !== '' && sddl.includes(opts.sid)) {
			return
		}
		hits.push(dir)
	}
	if (opts.recurse !== true) {
		let entries: { name: string; isDirectory(): boolean; isSymbolicLink(): boolean }[]
		try {
			entries = readdirSync(root, { withFileTypes: true })
		} catch (e) {
			return { error: e instanceof Error ? e.message : String(e), errors, hits }
		}
		for (const entry of entries) {
			if (entry.isDirectory() && !entry.isSymbolicLink()) {
				check(join(root, entry.name))
			}
		}
		return { errors, hits }
	}
	const stack = [root]
	while (stack.length > 0) {
		const dir = stack.pop() as string
		check(dir)
		let entries: { name: string; isDirectory(): boolean; isSymbolicLink(): boolean }[]
		try {
			entries = readdirSync(dir, { withFileTypes: true })
		} catch {
			continue
		}
		for (const entry of entries) {
			if (entry.isDirectory() && !entry.isSymbolicLink()) {
				stack.push(join(dir, entry.name))
			}
		}
	}
	return { errors, hits }
}

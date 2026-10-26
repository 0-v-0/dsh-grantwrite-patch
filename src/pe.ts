/**
 * Minimal PE (portable executable) signature validation.
 *
 * pnpm store files carry no extension, so a store-wide scan cannot filter by
 * name. Two bytes ("MZ") are not enough: DOS executables, self-extractors and
 * corrupt files also start with MZ. This parses the three structural markers
 * that are cheap to read in one open: the "MZ" DOS header, the e_lfanew offset,
 * and the "PE\0\0" signature plus the Machine field.
 *
 * The 512-byte first-read covers every ordinary PE (e_lfanew is almost always
 * < 0x200). When the DOS stub is oversized (self-extractors), the caller re-reads
 * the header at the parsed offset. Read and write paths are separated so the
 * sync variant is trivially testable and the async variant (used by the
 * background scan) shares the same logic.
 */

/** Machine types that are definitely Windows-native executables. */
import fs from 'node:fs'
import fsPromises from 'node:fs/promises'

const KNOWN_MACHINES = new Set([
	0x014c, // IMAGE_FILE_MACHINE_I386
	0x01c0, // IMAGE_FILE_MACHINE_ARM
	0x8664, // IMAGE_FILE_MACHINE_AMD64
	0xaa64, // IMAGE_FILE_MACHINE_ARM64
])

/** Validate a PE header already read into `buf` (at least peOff+24 bytes). */
export function isPeHeader(buf: Buffer, peOff: number): boolean {
	if (buf.length < peOff + 24) {
		return false
	}
	// "PE\0\0"
	if (buf.readUInt32LE(peOff) !== 0x0000_4550) {
		return false
	}
	const machine = buf.readUInt16LE(peOff + 4)
	return KNOWN_MACHINES.has(machine)
}

/** Parse a buffer read from the start of a file into the PE signature offset.
 * Returns -1 when the buffer does not start with a DOS header. */
export function peOffset(buf: Buffer): number {
	if (buf.length < 64) {
		return -1
	}
	if (buf.readUInt16LE(0) !== 0x5a4d) {
		// 'MZ'
		return -1
	}
	const off = buf.readUInt32LE(0x3c) // e_lfanew
	if (off === 0) {
		return -1
	}
	return off
}

/** True when `path` is a Windows PE image (exe/dll/sys) with a known machine. */
export function isPeFileSync(path: string, fsModule: typeof fs = fs): boolean {
	try {
		const fd = fsModule.openSync(path, 'r')
		try {
			const first = Buffer.alloc(512)
			const n = fsModule.readSync(fd, first, 0, first.length, 0)
			if (n < 64) {
				return false
			}
			const off = peOffset(first)
			if (off < 0) {
				return false
			}
			if (off + 24 <= n) {
				return isPeHeader(first, off)
			}
			// Oversized DOS stub: re-read at e_lfanew.
			const head = Buffer.alloc(off + 24)
			const got = fsModule.readSync(fd, head, 0, head.length, 0)
			if (got < off + 24) {
				return false
			}
			return isPeHeader(head, off)
		} finally {
			fsModule.closeSync(fd)
		}
	} catch {
		return false
	}
}

/** Async variant for background scans; same semantics. */
export async function isPeFile(
	path: string,
	fsModule: typeof fsPromises = fsPromises,
): Promise<boolean> {
	try {
		const fd = await fsModule.open(path, 'r')
		try {
			const first = Buffer.alloc(512)
			const { bytesRead: n } = await fd.read(first, 0, first.length, 0)
			if (n < 64) {
				return false
			}
			const off = peOffset(first)
			if (off < 0) {
				return false
			}
			if (off + 24 <= n) {
				return isPeHeader(first, off)
			}
			const head = Buffer.alloc(off + 24)
			const { bytesRead: got } = await fd.read(head, 0, head.length, 0)
			if (got < off + 24) {
				return false
			}
			return isPeHeader(head, off)
		} finally {
			await fd.close()
		}
	} catch {
		return false
	}
}

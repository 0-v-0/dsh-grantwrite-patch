import assert from 'node:assert/strict'
import test from 'node:test'
import { existsSync, mkdirSync, mkdtempSync, statSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
	filterLowLabel,
	hardlinkTargets,
	isStorePath,
	parseIcaclsBatch,
	relinkNodeModules,
	repairStore,
} from '../src/low-label-repair.ts'

/** A real PE-ish payload so repairStore's PE gate passes. */
function pePayload(): Buffer {
	const buf = Buffer.alloc(0x80 + 24)
	buf.writeUInt16LE(0x5a4d, 0)
	buf.writeUInt32LE(0x80, 0x3c)
	buf.writeUInt32LE(0x0000_4550, 0x80)
	buf.writeUInt16LE(0x8664, 0x84)
	return buf
}

test('parseIcaclsBatch: path line + Low label line', () => {
	const out = [
		'D:\\store\\obj1: Everyone:(R,W,D,DC)',
		'D:\\repo\\nm\\tool.exe: Everyone:(R,W,D,DC)',
		'    Mandatory Label\\Low Mandatory Level:(I)(NW)',
		'D:\\repo\\nm\\clean.dll: Everyone:(R,W,D,DC)',
		'Successfully processed 3 files; Failed processing 0 files',
	].join('\r\n')
	const hits = parseIcaclsBatch(out)
	assert.deepEqual(hits, ['D:\\repo\\nm\\tool.exe'])
})

test('filterLowLabel: batched icacls stub, only labeled paths returned', () => {
	const icacls = (args: string[]): string =>
		args
			.map((p) =>
				p.includes('low.exe')
					? `${p}: Everyone:(R,W,D,DC)\r\n    Mandatory Label\\Low Mandatory Level:(I)(NW)`
					: `${p}: Everyone:(R,W,D,DC)`,
			)
			.join('\r\n')
	assert.deepEqual(
		filterLowLabel(['D:\\a.exe', 'D:\\b.dll', 'D:\\x\\low.exe'], icacls),
		['D:\\x\\low.exe'],
	)
	assert.deepEqual(filterLowLabel([], icacls), [])
})

test('hardlinkTargets: fsutil volume-relative lines resolved to drive paths', () => {
	const fsutil = (): string =>
		'\\repo\\nm\\tool.exe\r\n\\dev\\pnpm\\store\\obj1\r\nD:\\absolute\\other.exe\r\n'
	// patch process.cwd drive for the relative lines
	const drive = process.cwd().slice(0, 2)
	assert.deepEqual(hardlinkTargets('x', fsutil), [
		`${drive}\\repo\\nm\\tool.exe`,
		`${drive}\\dev\\pnpm\\store\\obj1`,
		'D:\\absolute\\other.exe',
	])
})

test('relinkNodeModules: labeled native re-linked to clean store inode', async () => {
	const dir = mkdtempSync(join(tmpdir(), 'dsh-ll-'))
	try {
		const storeDir = join(dir, 'store')
		const storeFile = join(storeDir, 'obj1')
		mkdirSync(storeDir, { recursive: true })
		writeFileSync(storeFile, pePayload())

		const repo = join(dir, 'repo')
		const nm = join(repo, 'node_modules')
		const nmExe = join(nm, 'tool.exe')
		mkdirSync(nm, { recursive: true })
		writeFileSync(nmExe, pePayload())

		const icacls = (args: string[]): string => {
			const p = args[0]
			if (p === storeFile || p === nm) {
				return `${p}: Everyone:(R,W,D,DC)\r\nSuccessfully processed 1 files`
			}
			// node_modules natives: labeled
			return `${p}: Everyone:(R,W,D,DC)\r\n    Mandatory Label\\Low Mandatory Level:(I)(NW)`
		}
		const fsutil = (): string => `${storeFile}\r\n`

		const before = statSync(nmExe).ino
		const outcome = await relinkNodeModules(repo, {
			icacls,
			fsutil,
			storeDirs: [storeDir],
		})
		assert.deepEqual(outcome.fixed, [nmExe])
		assert.equal(outcome.skipped, 0)
		// hard link shares the store inode
		assert.equal(statSync(nmExe).ino, statSync(storeFile).ino)
		assert.notEqual(statSync(nmExe).ino, before)
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
})

test('relinkNodeModules: store target still labeled -> skipped, next pass converges', async () => {
	const dir = mkdtempSync(join(tmpdir(), 'dsh-ll-'))
	try {
		const storeDir = join(dir, 'store')
		const storeFile = join(storeDir, 'obj1')
		mkdirSync(storeDir, { recursive: true })
		writeFileSync(storeFile, pePayload())

		const repo = join(dir, 'repo')
		const nm = join(repo, 'node_modules')
		mkdirSync(nm, { recursive: true })
		writeFileSync(join(nm, 'tool.exe'), pePayload())

		const icacls = (args: string[]): string => {
			const p = args[0]
			if (p === nm) {
				return `${p}: Everyone:(R,W,D,DC)\r\nSuccessfully processed 1 files`
			}
			// both the node_modules native AND the store target labeled
			return `${p}: Everyone:(R,W,D,DC)\r\n    Mandatory Label\\Low Mandatory Level:(I)(NW)`
		}
		const fsutil = (): string => `${storeFile}\r\n`

		const outcome = await relinkNodeModules(repo, {
			icacls,
			fsutil,
			storeDirs: [storeDir],
		})
		assert.deepEqual(outcome.fixed, [])
		assert.equal(outcome.skipped, 1)
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
})

test('relinkNodeModules: labeled node_modules dir -> blocked, no relink', async () => {
	const dir = mkdtempSync(join(tmpdir(), 'dsh-ll-'))
	try {
		const nm = join(dir, 'repo', 'node_modules')
		mkdirSync(nm, { recursive: true })
		writeFileSync(join(nm, 'tool.exe'), 'x')
		const icacls = (): string =>
			`${nm}: Everyone:(R,W,D,DC)\r\n    Mandatory Label\\Low Mandatory Level:(I)(OI)(CI)(NW)`
		const outcome = await relinkNodeModules(join(dir, 'repo'), { icacls })
		assert.equal(outcome.blocked, true)
		assert.deepEqual(outcome.fixed, [])
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
})

test('relinkNodeModules: store located by content-addressed pattern, no storeDirs needed', async () => {
	const dir = mkdtempSync(join(tmpdir(), 'dsh-ll-'))
	try {
		// Simulated pnpm store layout on an arbitrary volume (64-hex content id).
		const storeFile =
			'D:\\dev\\pnpm\\store\\v11\\files\\90\\71d3a6b39fc64a5883133e2a32fe847ae17ee26b83a2603f35f62cb35b369064'
		const repo = join(dir, 'repo')
		const nm = join(repo, 'node_modules')
		mkdirSync(nm, { recursive: true })
		writeFileSync(join(nm, 'tool.exe'), pePayload())

		const icacls = (args: string[]): string => {
			const p = args[0] ?? ''
			if (p === nm) {
				return `${p}: Everyone:(R,W,D,DC)\r\nSuccessfully processed 1 files`
			}
			return `${p}: Everyone:(R,W,D,DC)\r\n    Mandatory Label\\Low Mandatory Level:(I)(NW)`
		}
		const fsutil = (): string => `${storeFile}\r\n`

		// storeDirs is empty: classification must come from the pattern alone.
		const outcome = await relinkNodeModules(repo, { icacls, fsutil, storeDirs: [] })
		assert.equal(outcome.blocked, undefined)
		assert.equal(outcome.fixed.length, 0)
		assert.equal(outcome.skipped, 1) // found the store, but the file does not exist
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
})

test('isStorePath: content-addressed pattern vs workspace paths', () => {
	const hash = '71d3a6b39fc64a5883133e2a32fe847ae17ee26b83a2603f35f62cb35b369064'
	const store = `D:\\dev\\pnpm\\store\\v11\\files\\90\\${hash}`
	assert.equal(isStorePath(store, []), true)
	assert.equal(isStorePath(store.toLowerCase(), []), true) // case-insensitive
	assert.equal(isStorePath('D:\\gh\\repo\\node_modules\\foo\\tsgo.exe', []), false)
	assert.equal(isStorePath('D:\\dev\\pnpm\\store\\v11\\tmp\\x', []), false)
	// fallback: configured store dir prefix still works
	assert.equal(isStorePath('D:\\custom\\store\\obj1', ['D:\\custom\\store']), true)
	assert.equal(isStorePath('D:\\custom\\store\\obj1', ['D:\\other']), false)
})

test('repairStore: reverse-maps labeled repo native to store, swaps PE inode', async () => {
	const dir = mkdtempSync(join(tmpdir(), 'dsh-ll-'))
	try {
		const storeDir = join(dir, 'store')
		const storeFile = join(storeDir, 'obj1')
		mkdirSync(storeDir, { recursive: true })
		writeFileSync(storeFile, pePayload())

		const repo = join(dir, 'repos', 'alpha')
		const nm = join(repo, 'node_modules')
		mkdirSync(nm, { recursive: true })
		writeFileSync(join(nm, 'tool.exe'), pePayload())

		const icacls = (args: string[]): string => {
			const p = args[0] ?? ''
			if (p.includes('store')) {
				return `${p}: Everyone:(R,W,D,DC)\r\nSuccessfully processed 1 files`
			}
			return `${p}: Everyone:(R,W,D,DC)\r\n    Mandatory Label\\Low Mandatory Level:(I)(NW)`
		}
		const fsutil = (): string => `${storeFile}\r\n`

		const before = statSync(storeFile).ino
		const outcome = await repairStore({
			icacls,
			fsutil,
			storeDirs: [storeDir],
			repoScanRoots: [join(dir, 'repos')],
		})
		assert.deepEqual(outcome.fixed, [storeFile])
		assert.notEqual(statSync(storeFile).ino, before) // inode swapped
		assert.equal(statSync(storeFile).size, pePayload().length) // content preserved
		assert.equal(existsSync(`${storeFile}.dsh-clean.tmp`), false) // temp cleaned by rename
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
})

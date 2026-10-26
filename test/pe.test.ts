import assert from 'node:assert/strict'
import test from 'node:test'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { isPeFileSync, isPeHeader, peOffset } from '../src/pe.ts'

function buildPe(e_lfanew: number, machine: number): Buffer {
	const buf = Buffer.alloc(e_lfanew + 24)
	buf.writeUInt16LE(0x5a4d, 0) // MZ
	buf.writeUInt32LE(e_lfanew, 0x3c)
	buf.writeUInt32LE(0x0000_4550, e_lfanew) // PE\0\0
	buf.writeUInt16LE(machine, e_lfanew + 4)
	return buf
}

test('peOffset: MZ + valid e_lfanew', () => {
	const buf = buildPe(0x80, 0x8664)
	assert.equal(peOffset(buf), 0x80)
})

test('peOffset: not MZ -> -1', () => {
	assert.equal(peOffset(Buffer.from('hello world')), -1)
	assert.equal(peOffset(Buffer.alloc(512)), -1) // zeroed
})

test('peOffset: too short or zero e_lfanew -> -1', () => {
	assert.equal(peOffset(Buffer.alloc(10)), -1)
	const buf = buildPe(0x80, 0x8664)
	buf.writeUInt32LE(0, 0x3c)
	assert.equal(peOffset(buf), -1)
})

test('isPeHeader: known machines pass, junk fails', () => {
	const pe = Buffer.alloc(64)
	pe.writeUInt32LE(0x0000_4550, 0)
	pe.writeUInt16LE(0x8664, 4)
	assert.equal(isPeHeader(pe, 0), true)
	assert.equal(isPeHeader(pe, 1), false) // misaligned offset
	const junk = Buffer.alloc(64)
	assert.equal(isPeHeader(junk, 0), false)
	const badMachine = buildPe(0x80, 0) // Machine == 0 is invalid for a real PE
	assert.equal(isPeHeader(badMachine, 0x80), false)
})

test('isPeFileSync: real PE file detected, text/truncated rejected', () => {
	const dir = mkdtempSync(join(tmpdir(), 'dsh-pe-'))
	try {
		const pe = join(dir, 'tool.exe')
		writeFileSync(pe, buildPe(0x80, 0xaa64))
		assert.equal(isPeFileSync(pe), true)

		const x64 = join(dir, 'x64.dll')
		writeFileSync(x64, buildPe(0x100, 0x8664))
		assert.equal(isPeFileSync(x64), true)

		const txt = join(dir, 'note.exe')
		writeFileSync(txt, 'MZ is not enough for this text file that is longer than 64 bytes padding padding padding padding')
		assert.equal(isPeFileSync(txt), false)

		const mzOnly = join(dir, 'mzonly.exe')
		writeFileSync(mzOnly, buildPe(0x80, 0x8664).subarray(0, 40)) // truncated header
		assert.equal(isPeFileSync(mzOnly), false)

		assert.equal(isPeFileSync(join(dir, 'missing.exe')), false)
	} finally {
		rmSync(dir, { recursive: true, force: true })
	}
})

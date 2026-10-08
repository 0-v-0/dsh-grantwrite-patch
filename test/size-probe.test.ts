import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { probeWorkspaceSize } from '../src/size-probe.ts'

function makeTree(root: string, dirs: number, filesPerDir: number): void {
	for (let d = 0; d < dirs; d++) {
		const dir = path.join(root, `d${d}`)
		mkdirSync(dir, { recursive: true })
		for (let f = 0; f < filesPerDir; f++) {writeFileSync(path.join(dir, `f${f}.txt`), 'x')}
	}
}

test('probe: small tree below threshold is not large', async () => {
	const ws = mkdtempSync(path.join(os.tmpdir(), 'dsh-grw-probe-'))
	try {
		makeTree(ws, 3, 3) // 3 dirs + 9 files = 12 objects
		const r = await probeWorkspaceSize(ws, 100, 5000)
		assert.equal(r.large, false)
		assert.equal(r.objects, 12)
	} finally {
		rmSync(ws, { force: true, recursive: true })
	}
})

test('probe: tree at/above threshold is large, count capped', async () => {
	const ws = mkdtempSync(path.join(os.tmpdir(), 'dsh-grw-probe-'))
	try {
		makeTree(ws, 5, 5) // 5 dirs + 25 files = 30 objects
		const r = await probeWorkspaceSize(ws, 10, 5000)
		assert.equal(r.large, true)
		assert.equal(r.objects, 10)
	} finally {
		rmSync(ws, { force: true, recursive: true })
	}
})

test('probe: timeout on a slow tree resolves large (conservative)', async () => {
	const ws = mkdtempSync(path.join(os.tmpdir(), 'dsh-grw-probe-'))
	try {
		makeTree(ws, 50, 100) // 50 dirs + 5000 files — far beyond a 1ms walk
		const r = await probeWorkspaceSize(ws, 1_000_000, 1) // 1ms timeout, tree larger than that
		assert.equal(r.large, true)
		assert.equal(r.objects, 1_000_000)
	} finally {
		rmSync(ws, { force: true, recursive: true })
	}
})

test('probe: missing root resolves not-large (FFI patch carries it)', async () => {
	const r = await probeWorkspaceSize(path.join(os.tmpdir(), 'dsh-grw-does-not-exist'), 100, 5000)
	assert.equal(r.large, false)
})

test('probe: unreadable subtree is skipped, not fatal', async () => {
	const ws = mkdtempSync(path.join(os.tmpdir(), 'dsh-grw-probe-'))
	try {
		makeTree(ws, 2, 2)
		const r = await probeWorkspaceSize(ws, 100, 5000)
		assert.equal(r.large, false)
		assert.ok(r.objects >= 0)
	} finally {
		rmSync(ws, { force: true, recursive: true })
	}
})

import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {
	decideWorkspace,
	ensureNodeOptions,
	makeRecoveryState,
	pickPreloadPath,
	resolveConfig,
	resolveSandboxScript,
} from '../src/index.ts'

function wait(ms: number): Promise<void> {
	return new Promise((r) => setTimeout(r, ms))
}

test('resolveConfig defaults: mode auto, threshold 20000, probe windows', () => {
	const opts = resolveConfig({})
	assert.equal(opts.mode, 'auto')
	assert.equal(opts.objectThreshold, 20000)
	assert.equal(opts.probeTimeoutMs, 10000)
	assert.equal(opts.probeCooldownMs, 3600000)
	const over = resolveConfig({
		mode: 'patch',
		objectThreshold: 1000,
		probeCooldownMs: 7,
		probeTimeoutMs: 5,
	})
	assert.equal(over.mode, 'patch')
	assert.equal(over.objectThreshold, 1000)
	assert.equal(over.probeTimeoutMs, 5)
	assert.equal(over.probeCooldownMs, 7)
})

test('decideWorkspace: strict label -> no probe, no repair', async () => {
	const opts = resolveConfig({ probeCooldownMs: 60000 })
	const state = makeRecoveryState()
	let probes = 0
	let repairs = 0
	await decideWorkspace('R', opts, state, {
		labelProbe: () => true,
		probe: async () => {
			probes += 1
			return { large: true, objects: opts.objectThreshold }
		},
		runner: async () => {
			repairs += 1
			return { ok: true }
		},
	})
	assert.equal(probes, 0)
	assert.equal(repairs, 0)
})

test('decideWorkspace: degraded large workspace -> proactive repair, cached', async () => {
	const opts = resolveConfig({ probeCooldownMs: 60000 })
	const state = makeRecoveryState()
	let probes = 0
	let repairs = 0
	const runner = async () => {
		repairs += 1
		return { ok: true }
	}
	const probe = async () => {
		probes += 1
		return { large: true, objects: opts.objectThreshold }
	}

	await decideWorkspace('R', opts, state, { labelProbe: () => false, probe, runner })
	assert.equal(probes, 1)
	assert.equal(repairs, 1)

	// Within cooldown: no second probe, no second repair.
	await decideWorkspace('R', opts, state, { labelProbe: () => false, probe, runner })
	assert.equal(probes, 1)
	assert.equal(repairs, 1)

	// Different root is not cached.
	await decideWorkspace('R2', opts, state, { labelProbe: () => false, probe, runner })
	assert.equal(probes, 2)
	assert.equal(repairs, 2)
})

test('decideWorkspace: small workspace -> no repair', async () => {
	const opts = resolveConfig({})
	const state = makeRecoveryState()
	let repairs = 0
	await decideWorkspace('R', opts, state, {
		labelProbe: () => false,
		probe: async () => ({ large: false, objects: 3 }),
		runner: async () => {
			repairs += 1
			return { ok: true }
		},
	})
	assert.equal(repairs, 0)
})

test('decideWorkspace: failing probe/repair never throws', async () => {
	const opts = resolveConfig({})
	const state = makeRecoveryState()
	await decideWorkspace('R', opts, state, {
		labelProbe: () => {
			throw new Error('label boom')
		},
		probe: async () => {
			throw new Error('probe boom')
		},
		runner: async () => {
			throw new Error('repair boom')
		},
	})
	assert.ok(true) // reached: nothing propagated
})

test('decideWorkspace: cooldown expiry re-decides', async () => {
	const opts = resolveConfig({ probeCooldownMs: 5 })
	const state = makeRecoveryState()
	let probes = 0
	let repairs = 0
	const probe = async () => {
		probes += 1
		return { large: false, objects: 1 }
	}
	const runner = async () => {
		repairs += 1
		return { ok: true }
	}
	await decideWorkspace('R', opts, state, { labelProbe: () => false, probe, runner })
	await wait(10)
	await decideWorkspace('R', opts, state, { labelProbe: () => false, probe, runner })
	assert.equal(probes, 2)
	assert.equal(repairs, 0)
})

test('pickPreloadPath returns a preload path; build ships preload.cjs next to index.js', () => {
	const p = pickPreloadPath()
	assert.match(p, /preload\.cjs$/)
	const shipped = fileURLToPath(new URL('../lib/preload.cjs', import.meta.url))
	assert.ok(existsSync(shipped))
})

test('ensureNodeOptions injects exactly once', () => {
	const before = process.env.NODE_OPTIONS ?? ''
	try {
		ensureNodeOptions()
		ensureNodeOptions()
		const after = process.env.NODE_OPTIONS ?? ''
		const arg = `--require=${pickPreloadPath()}`
		const hits = after.split(/\s+/).filter((s) => s === arg).length
		assert.equal(hits, 1)
	} finally {
		process.env.NODE_OPTIONS = before
	}
})

test('preload.cjs loads as CJS with expected exports', () => {
	const req = createRequire(import.meta.url)
	const preload = req('../lib/preload.cjs')
	for (const fn of [
		'install',
		'clearDegradedState',
		'isDegraded',
		'workspaceHasLowLabel',
		'markDegraded',
		'stateFilePaths',
		'workspaceFromArgv',
	]) {
		assert.equal(typeof preload[fn], 'function', fn)
	}
	// Marker: state paths anchored at the Harness home (not tmpdir).
	const primary = preload.stateFilePaths()[0]
	assert.ok(primary.endsWith('degraded.state'))
	assert.ok(primary.includes('grantwrite-patch'), 'primary state path must live under grantwrite-patch')
	assert.ok(!primary.startsWith(os.tmpdir()), 'primary state path must not be under tmpdir')
})

test('resolveSandboxScript resolves from sandbox package assets (fake pkg)', () => {
	const tmp = mkdtempSync(path.join(os.tmpdir(), 'dsh-grw-pkg-'))
	try {
		const pkgRoot = path.join(tmp, 'node_modules', '@deepseek-ai', 'dsh-sandbox-windows-acl')
		const scriptDir = path.join(pkgRoot, 'assets', 'diagnose-windows-sandbox-acl', 'scripts')
		mkdirSync(path.join(pkgRoot, 'lib'), { recursive: true })
		mkdirSync(scriptDir, { recursive: true })
		writeFileSync(path.join(pkgRoot, 'lib', 'index.js'), 'export {}')
		writeFileSync(
			path.join(pkgRoot, 'package.json'),
			JSON.stringify({ main: 'lib/index.js', name: '@deepseek-ai/dsh-sandbox-windows-acl' }),
		)
		const ps1 = path.join(scriptDir, 'diagnose-windows-sandbox-acl.ps1')
		writeFileSync(ps1, '# dummy\n')
		const resolved = resolveSandboxScript([tmp])
		assert.ok(resolved, 'expected the fake package assets script')
		assert.equal(resolved, ps1)
	} finally {
		rmSync(tmp, { force: true, recursive: true })
	}
})

test('resolveSandboxScript returns null without the sandbox package', () => {
	const tmp = mkdtempSync(path.join(os.tmpdir(), 'dsh-grw-nopkg-'))
	try {
		assert.equal(resolveSandboxScript([tmp]), null)
	} finally {
		rmSync(tmp, { force: true, recursive: true })
	}
})

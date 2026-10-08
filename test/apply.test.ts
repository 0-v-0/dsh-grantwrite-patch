import assert from 'node:assert/strict'
import test from 'node:test'
import { apply } from '../src/index.ts'

const WS = 'D:\\ws'
const WIN32_ERR = () => new Error('Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite')

function makeCtx(impl: (spec: unknown) => Promise<unknown> | unknown) {
	let calls = 0
	const shell = {
		execute: async (_spec: unknown) => {
			calls += 1
			return impl(_spec)
		},
	}
	return { count: () => calls, ctx: { shell } }
}

test('apply: repair then retry succeeds invisibly', async () => {
	const { ctx, count } = makeCtx(() => {
		if (count() === 1) {throw WIN32_ERR()}
		return { exitCode: 0, stdout: { text: 'ok' } }
	})
	let repairs = 0
	apply(
		ctx,
		{},
		{
			runner: async () => {
				repairs += 1
				return { ok: true, recap: '{"nextAction":"verify_original_confined_operation"}' }
			},
		},
	)
	const spec = {
		command: 'dir',
		sandboxPolicy: { mode: 'workspace-write', workspaceRoot: WS },
		workdir: WS,
	}
	const result = await ctx.shell.execute(spec)
	assert.deepEqual(result, { exitCode: 0, stdout: { text: 'ok' } })
	assert.equal(count(), 2) // original + retry
	assert.equal(repairs, 1)
})

test('apply: repair ok but retry still grantWrite-fails -> annotated error, no loop', async () => {
	const { ctx, count } = makeCtx(() => {
		throw WIN32_ERR()
	})
	let repairs = 0
	apply(
		ctx,
		{},
		{
			runner: async () => {
				repairs += 1
				return { ok: true }
			},
		},
	)
	const spec = { command: 'x', sandboxPolicy: { workspaceRoot: WS }, workdir: WS }
	await assert.rejects(ctx.shell.execute(spec), (e: Error) => {
		assert.match(e.message, /SetNamedSecurityInfoW failed \(Win32 5\): grantWrite/)
		assert.match(e.message, /dsh-grantwrite-patch/)
		return true
	})
	assert.equal(count(), 2) // exactly one retry, no infinite loop
	assert.equal(repairs, 1)
	// Second call: cooldown suppresses a second repair, so no retry round happens.
	await assert.rejects(ctx.shell.execute(spec))
	assert.equal(count(), 3)
	assert.equal(repairs, 1)
})

test('apply: repair not verified -> no retry, original error propagates', async () => {
	const { ctx, count } = makeCtx(() => {
		throw WIN32_ERR()
	})
	apply(ctx, {}, { runner: async () => ({ ok: false, recap: '{"nextAction":"stop"}' }) })
	const spec = { command: 'x', workdir: WS }
	await assert.rejects(ctx.shell.execute(spec), (e: Error) => e.message.includes('grantWrite'))
	assert.equal(count(), 1)
})

test('apply: unrelated errors are untouched', async () => {
	const other = new Error('npm error code EPERM')
	const { ctx, count } = makeCtx(() => {
		throw other
	})
	let repairs = 0
	apply(
		ctx,
		{},
		{
			runner: async () => {
				repairs += 1
				return { ok: true }
			},
		},
	)
	await assert.rejects(
		ctx.shell.execute({ command: 'npm i', workdir: WS }),
		(e: Error) => e === other,
	)
	assert.equal(count(), 1)
	assert.equal(repairs, 0)
})

test('apply: no workspace root in spec -> no repair, error propagates', async () => {
	const { ctx, count } = makeCtx(() => {
		throw WIN32_ERR()
	})
	let repairs = 0
	apply(
		ctx,
		{},
		{
			runner: async () => {
				repairs += 1
				return { ok: true }
			},
		},
	)
	await assert.rejects(ctx.shell.execute({ command: 'x' }))
	assert.equal(count(), 1)
	assert.equal(repairs, 0)
})

test('apply: no shell service or disabled -> inert', async () => {
	apply({}, {})
	apply({ shell: { execute: null as never } }, {})
	apply({ shell: { run: null as never } }, {})
	const shell = { execute: async (_spec: unknown) => 'orig' }
	const ctx = { shell }
	apply(ctx, { enable: false })
	assert.equal(await ctx.shell.execute({ command: 'x' }), 'orig')
})

test('apply: run-only shells are wrapped via the run fallback', async () => {
	let calls = 0
	const shell = {
		run: async (_spec: unknown) => {
			calls += 1
			if (calls === 1) {throw new Error('Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite')}
			return 'ok'
		},
	}
	const ctx = { shell }
	apply(
		ctx,
		{},
		{
			runner: async () => ({
				ok: true,
				recap: '{"nextAction":"verify_original_confined_operation"}',
			}),
		},
	)
	const spec = { command: 'x', sandboxPolicy: { workspaceRoot: WS }, workdir: WS }
	assert.equal(await ctx.shell.run(spec), 'ok')
	assert.equal(calls, 2)
})

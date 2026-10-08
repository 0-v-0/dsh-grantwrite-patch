import assert from 'node:assert/strict'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {
	GRANT_WRITE_RE,
	VERIFY_ACTION_RE,
	annotateError,
	isGrantWriteError,
	isVerifiedRepair,
	makeRecoveryState,
	repairAcl,
	resolveConfig,
	resolveDshHome,
	resolveRoot,
	runRepairScript,
} from '../lib/index.js'

test('GRANT_WRITE_RE matches the exact production signature', () => {
	assert.match('SetNamedSecurityInfoW failed (Win32 5): grantWrite', GRANT_WRITE_RE)
	assert.match('Error: SetNamedSecurityInfoW failed (Win32 5): grantWrite', GRANT_WRITE_RE)
})

test('GRANT_WRITE_RE ignores other Win32 failures', () => {
	assert.doesNotMatch('GetTempPathW failed (Win32 111): buffer', GRANT_WRITE_RE)
	assert.doesNotMatch('SetNamedSecurityInfoW failed (Win32 5): revokeWrite', GRANT_WRITE_RE)
	assert.doesNotMatch('child process exited with code 1', GRANT_WRITE_RE)
})

test('isGrantWriteError: bare, AggregateError-wrapped, cause-chained', () => {
	const winErr = new Error('SetNamedSecurityInfoW failed (Win32 5): grantWrite')
	assert.ok(isGrantWriteError(winErr))
	const agg = new AggregateError([new Error('x'), winErr], 'cleanup also failed')
	assert.ok(isGrantWriteError(agg))
	const chained = new Error('outer')
	chained.cause = winErr
	assert.ok(isGrantWriteError(chained))
	assert.ok(!isGrantWriteError(new Error('npm error EPERM')))
	assert.ok(!isGrantWriteError('SetNamedSecurityInfoW failed (Win32 5): grantWrite'))
})

test('resolveRoot prefers sandboxPolicy.workspaceRoot, falls back to workdir', () => {
	assert.equal(
		resolveRoot({
			command: 'x',
			sandboxPolicy: { mode: 'workspace-write', workspaceRoot: 'R' },
			workdir: 'W',
		}),
		'R',
	)
	assert.equal(resolveRoot({ command: 'x', workdir: 'W' }), 'W')
	assert.equal(resolveRoot({ command: 'x' }), undefined)
	assert.equal(resolveRoot(undefined), undefined)
})

test('resolveConfig defaults: sandbox-package script (empty in test env), DSH_HOME outDir', () => {
	const opts = resolveConfig({})
	assert.ok(opts.enable)
	// No @deepseek-ai/dsh-sandbox-windows-acl in this repo's deps -> default resolves to
	// an empty scriptPath (repair fails closed; FFI patch carries the command).
	assert.equal(opts.scriptPath, '')
	// Default outDir is a subdirectory of the resolved Harness home.
	assert.equal(opts.outDir, path.join(resolveDshHome(), 'grantwrite-patch'))
	assert.ok(opts.outDir.includes('grantwrite-patch'))
	assert.equal(opts.maxRetries, 1)
	assert.equal(opts.repairTimeoutMs, 120000)
	const over = resolveConfig({ maxRetries: 2, outDir: 'O', scriptPath: 'S' })
	assert.equal(over.scriptPath, 'S')
	assert.equal(over.outDir, 'O')
	assert.equal(over.maxRetries, 2)
})

test('resolveDshHome honors DSH_HOME and falls back to ~/.dsh', () => {
	assert.equal(resolveDshHome({ DSH_HOME: 'C:\\harness' }), path.resolve('C:\\harness'))
	assert.equal(resolveDshHome({ DSH_HOME: '~/harness' }), path.join(os.homedir(), 'harness'))
	assert.equal(resolveDshHome({ DSH_HOME: '   ' }), path.join(os.homedir(), '.dsh'))
	assert.equal(resolveDshHome({}), path.join(os.homedir(), '.dsh'))
})

test('VERIFY_ACTION_RE matches the RECAP nextAction token', () => {
	const recap = JSON.stringify({
		exitCode: 0,
		nextAction: 'verify_original_confined_operation',
		repaired: true,
		report: 'r.jsonl',
	})
	assert.match(recap, VERIFY_ACTION_RE)
	assert.doesNotMatch(JSON.stringify({ nextAction: 'stop' }), VERIFY_ACTION_RE)
})

test('repairAcl coalesces concurrent repairs and honors cooldown', async () => {
	const opts = resolveConfig({ cooldownMs: 60000 })
	const state = makeRecoveryState()
	let calls = 0
	const runner = async () => {
		calls += 1
		await new Promise((r) => setTimeout(r, 10))
		return { ok: true }
	}
	const [a, b] = await Promise.all([
		repairAcl('R', opts, state, runner),
		repairAcl('R', opts, state, runner),
	])
	assert.equal(a, true)
	assert.equal(b, true)
	assert.equal(calls, 1) // coalesced
	const after = await repairAcl('R', opts, state, runner)
	assert.equal(after, false) // cooldown: no second repair
	assert.equal(calls, 1)
})

test('repairAcl retries after cooldown expires', async () => {
	const opts = resolveConfig({ cooldownMs: 5 })
	const state = makeRecoveryState()
	let calls = 0
	const runner = async () => {
		calls += 1
		return { ok: true }
	}
	assert.equal(await repairAcl('R', opts, state, runner), true)
	await new Promise((r) => setTimeout(r, 10))
	assert.equal(await repairAcl('R', opts, state, runner), true)
	assert.equal(calls, 2)
})

test('annotateError appends the summary without mutating the original', () => {
	const err = new Error('SetNamedSecurityInfoW failed (Win32 5): grantWrite')
	const annotated = annotateError(err, 'D:\\ws', '{"nextAction":"stop"}')
	assert.notEqual(annotated, err)
	assert.match(
		(annotated as Error).message,
		/dsh-grantwrite-patch: ACL repair of D:\\ws did not help/,
	)
	assert.doesNotMatch(err.message, /dsh-grantwrite-patch/)
	assert.equal(annotateError(err, 'D:\\ws', undefined), err)
	assert.equal(annotateError('not an error', 'R', 'x'), 'not an error')
})

test('isVerifiedRepair: real script output shapes', () => {
	// Successful package-ACE removal: RECAP carries no nextAction; evidence is
	// the verified verification record + SUMMARY FIXED count.
	const fixedOut = [
		'RECAP {"verdicts":[{"verdict":"CULPRIT","packageObjects":["D:\\ws"],"writeDac":true,"writeOwner":true,"path":"D:\\ws"}],"changes":[{"path":"D:\\ws","operation":"remove_package_allow"}],"verifications":[{"path":"D:\\ws","status":"verified","operation":"fix"}],"refusals":[],"scans":[{"packageSources":[],"truncated":false,"unreadable":0,"visited":0,"path":"D:\\ws"}],"report":"r.jsonl"}',
		'REPORT_FILE r.jsonl',
		'SUMMARY FIXED=1 GRANTED=0 REFUSED=0 RESTORED=0',
	].join('\n')
	assert.ok(isVerifiedRepair(fixedOut, 0))

	// REFUSED run: exit 2, FIXED=0 -> not verified.
	const refusedOut = [
		'REPAIR_REFUSED D:\\ws needs WRITE_DAC; stop for permission-policy review',
		'SUMMARY FIXED=0 GRANTED=0 REFUSED=1 RESTORED=0',
	].join('\n')
	assert.ok(!isVerifiedRepair(refusedOut, 0))
	assert.ok(!isVerifiedRepair(refusedOut, 2))

	// Verify token in a REPORT summary row also counts.
	const summaryWithAction =
		'REPORT {"kind":"summary","details":{"nextAction":"verify_original_confined_operation","fixed":1}}'
	assert.ok(isVerifiedRepair(summaryWithAction, 0))
})

test('runRepairScript fails closed when no sandbox-package script is resolvable (DSH 0.1.7)', async () => {
	// DSH 0.1.7: the sandbox package ships no assets -> default scriptPath is empty.
	const opts = resolveConfig({})
	assert.equal(opts.scriptPath, '')
	const outcome = await runRepairScript('R', opts)
	assert.equal(outcome.ok, false)
	assert.match(outcome.stderr ?? '', /repair script not found/)
})

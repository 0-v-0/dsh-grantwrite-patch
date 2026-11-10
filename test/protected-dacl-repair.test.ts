import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import {
	findProtectedDirs,
	grantProtectedDirs,
	isProtectedSddl,
	loadAclModule,
	parseScanOutcome,
	repairProtectedDaclTree,
	workspaceCapabilitySid,
	type AclGrantLike,
	type GrantFactory,
} from '../src/protected-dacl-repair.ts'
import { capabilitySids, readAclText } from '../src/capability-repair.ts'
import { SCRATCH_ROOT } from './scratch.ts'

/** Synthetic capability SID (Set-Acl accepts it even though it does not exist). */
const FAKE_CAPABILITY_SID = 'S-1-4-21-77777-88888'

function makeTempDir(): string {
	return mkdtempSync(path.join(SCRATCH_ROOT, 'prot-'))
}

function powershell(program: string): void {
	execFileSync('powershell', ['-NoProfile', '-NonInteractive', '-Command', program], {
		encoding: 'utf8',
		stdio: 'pipe',
	})
}

/** Seed the capability SID on `dir` (non-propagating), like the workspace root. */
function seedCapabilitySid(dir: string): void {
	powershell(
		`$sid = New-Object System.Security.Principal.SecurityIdentifier('${FAKE_CAPABILITY_SID}');` +
			`$rights = [System.Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,Read';` +
			`$acl = Get-Acl '${dir}';` +
			`$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$rights,'None','None','Allow');` +
			`$acl.AddAccessRule($rule);Set-Acl '${dir}' $acl`,
	)
}

/** Protect `dir`'s DACL (SE_DACL_PROTECTED) and grant the user full control —
 * the state left behind by `icacls /inheritance:r`, ACL-preserving copies and
 * backup restores. Explicit ACEs survive, inherited ones are dropped. */
function protectDir(dir: string): void {
	execFileSync('icacls', [dir, '/inheritance:r', '/grant', `${process.env.USERNAME}:(OI)(CI)F`])
}

/** Read `dir`'s DACL SDDL form (the flag prefix distinguishes D:P from D:AI). */
function sddlOf(dir: string): string {
	return execFileSync(
		'powershell',
		['-NoProfile', '-NonInteractive', '-Command', `(Get-Acl '${dir}').GetSecurityDescriptorSddlForm('Access')`],
		{ encoding: 'utf8' },
	).trim()
}

function cleanupTree(base: string): void {
	try {
		execFileSync('icacls', [base, '/inheritance:e', '/grant', 'Everyone:(OI)(CI)F', '/T'], {
			stdio: 'ignore',
		})
	} catch {
		// best effort: removal below still attempts
	}
	rmSync(base, { force: true, recursive: true })
}

/** Recording stub for the official grant: no ACL is touched. */
function stubFactory(): { factory: GrantFactory; added: string[]; disposed: () => boolean } {
	const added: string[] = []
	let disposed = false
	const grant: AclGrantLike = {
		add(dir: string, standing?: boolean) {
			assert.equal(standing, true, 'the backfill must use a standing grant')
			added.push(dir)
		},
		dispose() {
			disposed = true
		},
	}
	return {
		added,
		disposed: () => disposed,
		factory: async () => ({ grant, sid: FAKE_CAPABILITY_SID }),
	}
}

/** Skip reason when this host cannot read ACLs at all. */
function probeAcl(): string | false {
	if (process.platform !== 'win32') {
		return 'ACL tests are Windows-only'
	}
	const dir = makeTempDir()
	try {
		execFileSync('icacls', [dir], { stdio: 'ignore' })
		execFileSync(
			'powershell',
			['-NoProfile', '-NonInteractive', '-Command', `(Get-Acl '${dir}').GetSecurityDescriptorSddlForm('Access')`],
			{ encoding: 'utf8' },
		)
		return false
	} catch (e) {
		return `ACL read tooling unavailable: ${(e as Error).message.split('\n')[0]}`
	} finally {
		rmSync(dir, { force: true, recursive: true })
	}
}

const aclSkip = probeAcl()

test('isProtectedSddl: the P flag between D: and the first ACE', () => {
	assert.equal(isProtectedSddl('D:P(A;OICI;FA;;;BA)'), true)
	assert.equal(isProtectedSddl('D:PAI(A;OICI;FA;;;BA)'), true)
	assert.equal(isProtectedSddl('D:AI(A;OICI;FA;;;BA)'), false)
	assert.equal(isProtectedSddl('D:(A;;FA;;;BA)'), false)
	assert.equal(isProtectedSddl(''), false)
})

test('parseScanOutcome: one JSON line, noise tolerated, garbage rejected', () => {
	assert.deepEqual(parseScanOutcome('{"hits":["D:\\\\a"],"errors":[]}'), { errors: [], hits: ['D:\\a'] })
	assert.deepEqual(parseScanOutcome('warning\n{"hits":[],"errors":["x"]}\n'), { errors: ['x'], hits: [] })
	assert.deepEqual(parseScanOutcome('{"hits":["a",1],"errors":[]}'), { errors: [], hits: ['a'] })
	assert.equal(parseScanOutcome('not json'), undefined)
	assert.equal(parseScanOutcome(''), undefined)
})

test('workspaceCapabilitySid returns the injected S-1-4 SID', { skip: aclSkip }, () => {
	const dir = makeTempDir()
	try {
		seedCapabilitySid(dir)
		assert.equal(workspaceCapabilitySid(dir), capabilitySids(dir)[0])
	} finally {
		rmSync(dir, { force: true, recursive: true })
	}
})

test('findProtectedDirs reports a protected subdir and never edits the DACL', { skip: aclSkip }, () => {
	const base = makeTempDir()
	const sub = path.join(base, 'sub-protected')
	mkdirSync(sub, { recursive: true })
	protectDir(sub)
	try {
		seedCapabilitySid(base)
		const sid = workspaceCapabilitySid(base)
		assert.ok(sid, 'seeded root should carry a capability SID')
		assert.ok(isProtectedSddl(sddlOf(sub)), 'fixture subdir must be a protected DACL')
		const before = readAclText(sub)

		const scan = findProtectedDirs(base, { recurse: true })
		assert.equal(scan.error, undefined, scan.error)
		assert.deepEqual(scan.hits, [sub])
		assert.deepEqual(scan.errors, [])
		assert.equal(readAclText(sub).trim(), before.trim(), 'detection must not edit the DACL')

		// Shallow scan does not descend into `sub`.
		assert.deepEqual(findProtectedDirs(base).hits, [])
	} finally {
		cleanupTree(base)
	}
})

test('findProtectedDirs skips a protected dir that already carries the capability Allow', { skip: aclSkip }, () => {
	const base = makeTempDir()
	const sub = path.join(base, 'sub-fixed')
	mkdirSync(sub, { recursive: true })
	try {
		seedCapabilitySid(base)
		const sid = workspaceCapabilitySid(base)
		// Simulate a completed backfill: `icacls /inheritance:r` keeps explicit
		// ACEs, so seeding the ACE first and protecting afterwards reproduces the
		// fixed state without writing to a protected DACL.
		seedCapabilitySid(sub)
		protectDir(sub)
		assert.ok(isProtectedSddl(sddlOf(sub)), 'fixture must still be protected')
		assert.ok(readAclText(sub).includes(sid), 'the seeded ACE must survive /inheritance:r')
		assert.deepEqual(findProtectedDirs(base, { recurse: true }).hits, [])
	} finally {
		cleanupTree(base)
	}
})

test('grantProtectedDirs uses the official API: standing add per dir, then dispose', async () => {
	const stub = stubFactory()
	const out = await grantProtectedDirs('D:\\ws', ['D:\\ws\\a', 'D:\\ws\\b'], { grantFactory: stub.factory })
	assert.deepEqual(out.fixed, ['D:\\ws\\a', 'D:\\ws\\b'])
	assert.deepEqual(out.errors, [])
	assert.equal(out.seen, 2)
	assert.deepEqual(stub.added, ['D:\\ws\\a', 'D:\\ws\\b'])
	assert.equal(stub.disposed(), true)
})

test('grantProtectedDirs reports a missing official module instead of guessing', async () => {
	const out = await grantProtectedDirs('D:\\ws', ['D:\\ws\\a'], { grantFactory: async () => undefined })
	assert.match(out.error ?? '', /cannot resolve/)
	assert.deepEqual(out.fixed, [])
})

test('repairProtectedDaclTree: detection + grant, stub keeps the DACL untouched', { skip: aclSkip }, async () => {
	const base = makeTempDir()
	const sub = path.join(base, 'sub-protected')
	mkdirSync(sub, { recursive: true })
	protectDir(sub)
	try {
		seedCapabilitySid(base)
		const before = readAclText(sub)
		const stub = stubFactory()
		const out = await repairProtectedDaclTree(base, { grantFactory: stub.factory, recurse: true })
		assert.equal(out.error, undefined, out.error)
		assert.deepEqual(out.fixed, [sub])
		assert.deepEqual(stub.added, [sub])
		assert.equal(readAclText(sub).trim(), before.trim())
	} finally {
		cleanupTree(base)
	}
})

test('repairProtectedDaclTree is a no-op on an inheriting tree', { skip: aclSkip }, async () => {
	const base = makeTempDir()
	mkdirSync(path.join(base, 'plain'), { recursive: true })
	try {
		seedCapabilitySid(base)
		const stub = stubFactory()
		const out = await repairProtectedDaclTree(base, { grantFactory: stub.factory, recurse: true })
		assert.deepEqual(out.fixed, [])
		assert.equal(out.seen, 0)
		assert.deepEqual(stub.added, [])
	} finally {
		cleanupTree(base)
	}
})

test('loadAclModule resolves the official package or reports the miss', async () => {
	const mod = await loadAclModule([process.argv[1] ?? process.cwd()])
	if (mod === undefined) {
		// A host that cannot be located is a supported outcome (reported, not guessed).
		return
	}
	assert.equal(typeof mod.workspaceWriteSid, 'function')
	assert.equal(typeof mod.AclWriteGrant.create, 'function')
})

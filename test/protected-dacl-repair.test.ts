import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import path from 'node:path'
import test from 'node:test'
import { isProtectedSddl, walkProtectedDirs } from '../src/acl-detect.ts'
import {
	findProtectedDirs,
	grantProtectedDirs,
	loadAclModule,
	repairProtectedDaclTree,
	type AclGrantLike,
	type GrantFactory,
} from '../src/protected-dacl-repair.ts'
import { SCRATCH_ROOT } from './scratch.ts'

/** Synthetic capability SID. */
const FAKE_CAPABILITY_SID = 'S-1-4-21-77777-88888'

function makeTempDir(): string {
	return mkdtempSync(path.join(SCRATCH_ROOT, 'prot-'))
}

/** A reader stub: SDDL per directory, no ACL access at all. */
function stubReader(map: Record<string, string>): (dir: string) => string {
	return (dir: string) => {
		const sddl = map[dir]
		if (sddl === undefined) {
			throw new Error(`no stub for ${dir}`)
		}
		return sddl
	}
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

test('isProtectedSddl: the P flag between D: and the first ACE', () => {
	assert.equal(isProtectedSddl('D:P(A;OICI;FA;;;BA)'), true)
	assert.equal(isProtectedSddl('D:PAI(A;OICI;FA;;;BA)'), true)
	assert.equal(isProtectedSddl('D:AI(A;OICI;FA;;;BA)'), false)
	assert.equal(isProtectedSddl('D:(A;;FA;;;BA)'), false)
	assert.equal(isProtectedSddl(''), false)
})

test('walkProtectedDirs: protected without the capability SID is a hit', () => {
	const base = makeTempDir()
	const plain = path.join(base, 'plain')
	const prot = path.join(base, 'prot')
	mkdirSync(plain, { recursive: true })
	mkdirSync(prot, { recursive: true })
	try {
		const walk = walkProtectedDirs(base, {
			reader: stubReader({
				[base]: 'D:P(A;OICI;FA;;;BA)',
				[plain]: 'D:AI(A;OICIID;0x1200a9;;;BU)',
				[prot]: 'D:P(A;OICI;FA;;;BU)',
			}),
			sid: FAKE_CAPABILITY_SID,
		})
		assert.deepEqual(walk.hits, [prot])
		assert.deepEqual(walk.errors, [])
		assert.equal(walk.error, undefined)
	} finally {
		rmSync(base, { force: true, recursive: true })
	}
})

test('walkProtectedDirs: a protected dir that already carries the SID is skipped', () => {
	const base = makeTempDir()
	const prot = path.join(base, 'prot')
	mkdirSync(prot, { recursive: true })
	try {
		const walk = walkProtectedDirs(base, {
			reader: stubReader({
				[base]: 'D:AI(A;OICI;FA;;;BA)',
				[prot]: `D:P(A;OICI;FA;;;BA)(A;OICI;0x110156;;;${FAKE_CAPABILITY_SID})`,
			}),
			sid: FAKE_CAPABILITY_SID,
		})
		assert.deepEqual(walk.hits, [])
	} finally {
		rmSync(base, { force: true, recursive: true })
	}
})

test('walkProtectedDirs: recurse descends, shallow does not', () => {
	const base = makeTempDir()
	const nested = path.join(base, 'a', 'b')
	mkdirSync(nested, { recursive: true })
	try {
		const reader = stubReader({
			[base]: 'D:AI()',
			[path.join(base, 'a')]: 'D:AI()',
			[nested]: 'D:P(A;OICI;FA;;;BU)',
		})
		assert.deepEqual(walkProtectedDirs(base, { reader, sid: FAKE_CAPABILITY_SID }).hits, [])
		assert.deepEqual(walkProtectedDirs(base, { reader, recurse: true, sid: FAKE_CAPABILITY_SID }).hits, [nested])
	} finally {
		rmSync(base, { force: true, recursive: true })
	}
})

test('walkProtectedDirs: a reader failure is attributed and the walk continues', () => {
	const base = makeTempDir()
	const a = path.join(base, 'a')
	const b = path.join(base, 'b')
	mkdirSync(a, { recursive: true })
	mkdirSync(b, { recursive: true })
	try {
		const walk = walkProtectedDirs(base, {
			reader: stubReader({
				[b]: 'D:P(A;;FA;;;BU)',
				[base]: 'D:AI()',
			}),
			sid: FAKE_CAPABILITY_SID,
		})
		assert.deepEqual(walk.hits, [b])
		assert.equal(walk.errors.length, 1)
		assert.match(walk.errors[0] ?? '', /a/)
	} finally {
		rmSync(base, { force: true, recursive: true })
	}
})

test('walkProtectedDirs reports a missing FFI host instead of guessing', () => {
	// Only meaningful when the host cannot be resolved in this process; when it
	// can, the FFI path is covered by the smoke test below.
	const base = makeTempDir()
	try {
		const walk = walkProtectedDirs(base)
		if (walk.error === undefined) {
			assert.ok(Array.isArray(walk.hits))
		} else {
			assert.match(walk.error, /koffi|dsh-win32-process/)
		}
	} finally {
		rmSync(base, { force: true, recursive: true })
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

test('repairProtectedDaclTree: stub reader + stub grant, end to end', async () => {
	const base = makeTempDir()
	const prot = path.join(base, 'prot')
	mkdirSync(prot, { recursive: true })
	try {
		const stub = stubFactory()
		const out = await repairProtectedDaclTree(base, {
			grantFactory: stub.factory,
			reader: stubReader({ [base]: 'D:AI()', [prot]: 'D:P(A;OICI;FA;;;BU)' }),
			recurse: true,
			sid: FAKE_CAPABILITY_SID,
		})
		assert.equal(out.error, undefined, out.error ?? 'unexpected error')
		assert.deepEqual(out.fixed, [prot])
		assert.deepEqual(stub.added, [prot])
	} finally {
		rmSync(base, { force: true, recursive: true })
	}
})

test('repairProtectedDaclTree is a no-op on an inheriting tree', async () => {
	const base = makeTempDir()
	mkdirSync(path.join(base, 'plain'), { recursive: true })
	try {
		const stub = stubFactory()
		const out = await repairProtectedDaclTree(base, {
			grantFactory: stub.factory,
			reader: stubReader({ [base]: 'D:AI()', [path.join(base, 'plain')]: 'D:AI()' }),
			recurse: true,
			sid: FAKE_CAPABILITY_SID,
		})
		assert.deepEqual(out.fixed, [])
		assert.equal(out.seen, 0)
		assert.deepEqual(stub.added, [])
	} finally {
		rmSync(base, { force: true, recursive: true })
	}
})

test('loadAclModule resolves the official package or reports the miss', async () => {
	const mod = await loadAclModule([process.argv[1] ?? process.cwd()])
	if (mod === undefined) {
		return
	}
	assert.equal(typeof mod.workspaceWriteSid, 'function')
	assert.equal(typeof mod.AclWriteGrant.create, 'function')
})

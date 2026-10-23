import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdirSync, rmSync } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import {
	capabilitySids,
	findHardenedDirs,
	grantCapability,
	isHardenedDir,
	readAclText,
	repairCapabilityTree,
	repairCapabilityTreeDeep,
	scanTree,
} from '../src/capability-repair.ts'

/** Simulate a real hardened subdir: add the world Deny DC while keeping
 * inheritance alive (as upstream #423/#9559 dirs are). The capability SID is
 * seeded non-propagating (see seedCapabilitySid), so it never reaches the
 * subdir — exactly the "missing capability Allow" state. */
function hardenDir(dir: string): void {
	execFileSync('icacls', [dir, '/deny', 'Everyone:(DC)'])
}

/** rmSync a tree whose subdirs were hardened: restore Everyone FullControl
 * recursively first, or the DELETE-DENIED dirs would EPERM the removal. */
function cleanupTree(base: string): void {
	try {
		execFileSync('icacls', [base, '/grant', 'Everyone:(OI)(CI)F', '/T'], { stdio: 'ignore' })
	} catch {
		// best effort: removal below still attempts
	}
	rmSync(base, { force: true, recursive: true })
}

function makeTempDir(): string {
	return path.join(os.tmpdir(), `dsh-grantwrite-patch-test-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`)
}

/** A synthetic capability SID (S-1-4-21 = SECURITY_CAPABILITY_BASE_RID).
 * Set-Acl accepts it without the SID existing; icacls renders it back. */
const FAKE_CAPABILITY_SID = 'S-1-4-21-12345-67890'

/** Inject a capability-SID Allow onto `dir` so capabilitySids(dir) returns it
 * (Set-Acl; icacls cannot name S-1-4-*). The ACE is added with inheritance
 * flags 'None', i.e. it does NOT propagate to existing children — so tests
 * can harden a subdir (deny DC, no capability Allow) exactly like the real
 * "DACL-replaced pre-existing dir" from upstream #423/#9559. Self-contained:
 * no dependency on the host workspace's hardened ACL. */
function seedCapabilitySid(dir: string): void {
	const ps = [
		'-NoProfile',
		'-NonInteractive',
		'-Command',
		`$sid = New-Object System.Security.Principal.SecurityIdentifier('${FAKE_CAPABILITY_SID}');` +
			`$rights = [System.Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,Read';` +
			`$acl = Get-Acl '${dir}';` +
			`$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($sid,$rights,'None','None','Allow');` +
			`$acl.AddAccessRule($rule);Set-Acl '${dir}' $acl`,
	]
	execFileSync('powershell', ps, { encoding: 'utf8' })
}

test('capabilitySids reads injected S-1-4-* SIDs off a directory', () => {
	const dir = makeTempDir()
	mkdirSync(dir)
	try {
		seedCapabilitySid(dir)
		const sids = capabilitySids(dir)
		assert.ok(Array.isArray(sids))
		assert.ok(sids.includes(FAKE_CAPABILITY_SID), JSON.stringify(sids))
		assert.ok(sids.every((s) => /^S-1-4-\d+(-\d+)+$/.test(s)), JSON.stringify(sids))
	} finally {
		rmSync(dir, { force: true, recursive: true })
	}
})

test('grantCapability adds an (OI)(CI)(R,W,D,DC) Allow ACE for the SID', () => {
	const base = makeTempDir()
	mkdirSync(base)
	const dir = makeTempDir()
	mkdirSync(dir)
	try {
		seedCapabilitySid(base)
		const [sid] = capabilitySids(base)
		assert.ok(sid, 'seeded dir should carry the injected capability SID')
		assert.equal(grantCapability(dir, sid), true)
		const acl = readAclText(dir)
		assert.ok(
			new RegExp(`${sid}:\\s*\\(OI\\)\\(CI\\)\\(R,W,D,DC\\)`).test(acl),
			`expected capability Allow in ACL:\n${acl}`,
		)
	} finally {
		cleanupTree(base)
		rmSync(dir, { force: true, recursive: true })
	}
})

test('findHardenedDirs flags subdirs with world Deny DC but no capability Allow', () => {
	const base = makeTempDir()
	const sub = path.join(base, 'sub')
	mkdirSync(sub, { recursive: true })
	hardenDir(sub)
	try {
		seedCapabilitySid(base)
		const sids = capabilitySids(base)
		const hits = findHardenedDirs(base, sids)
		assert.ok(hits.includes(sub), `expected ${sub} among ${JSON.stringify(hits)}`)
	} finally {
		cleanupTree(base)
	}
})

test('repairCapabilityTree back-fills a hardened subdir and is idempotent', () => {
	const base = makeTempDir()
	const sub = path.join(base, 'sub')
	mkdirSync(sub, { recursive: true })
	hardenDir(sub)
	try {
		seedCapabilitySid(base)
		// repairCapabilityTree reads the SIDs from the root itself.
		const out = repairCapabilityTree(base)
		assert.deepEqual(out.fixed, [sub])
		assert.equal(out.error, undefined)
		// Second run: nothing left to fix.
		const again = repairCapabilityTree(base)
		assert.deepEqual(again.fixed, [])
		// And the subdir is no longer hardened.
		assert.ok(!findHardenedDirs(base, capabilitySids(base)).includes(sub))
	} finally {
		cleanupTree(base)
	}
})

test('repairCapabilityTree returns skipped for a root without capability SIDs', () => {
	const dir = makeTempDir()
	mkdirSync(dir)
	try {
		// A plain temp dir has no S-1-4-* capability SID: nothing to back-fill.
		const out = repairCapabilityTree(dir)
		assert.equal(out.fixed.length, 0)
		assert.ok(out.skipped >= 1)
	} finally {
		rmSync(dir, { force: true, recursive: true })
	}
})

test('isHardenedDir: Deny DC without capability Allow, and the fixed state', () => {
	const base = makeTempDir()
	const sub = path.join(base, 'sub')
	mkdirSync(sub, { recursive: true })
	hardenDir(sub)
	try {
		seedCapabilitySid(base)
		const sids = capabilitySids(base)
		const [firstSid] = sids
		assert.ok(firstSid, 'seeded dir should carry the injected capability SID')
		assert.ok(isHardenedDir(sub, sids))
		// After the grant the same dir is no longer hardened.
		assert.equal(grantCapability(sub, firstSid), true)
		assert.ok(!isHardenedDir(sub, sids))
	} finally {
		cleanupTree(base)
	}
})

test('scanTree finds hardened dirs at any depth via icacls /T', async () => {
	const base = makeTempDir()
	const nested = path.join(base, 'a', 'b', 'c')
	mkdirSync(nested, { recursive: true })
	hardenDir(nested)
	try {
		const hits = await scanTree(base)
		assert.ok(hits.includes(nested), `expected ${nested} among ${JSON.stringify(hits)}`)
		assert.ok(!hits.includes(base), 'root itself is excluded')
		// A clean dir yields no hits at all.
		const clean = path.join(base, 'clean')
		mkdirSync(clean)
		const cleanHits = await scanTree(base)
		assert.ok(!cleanHits.includes(clean))
	} finally {
		cleanupTree(base)
	}
})

test('repairCapabilityTreeDeep back-fills deep hardened dirs, idempotent, skips fixed ones', async () => {
	const base = makeTempDir()
	const deep1 = path.join(base, 'x', 'y')
	const deep2 = path.join(base, 'x', 'z')
	mkdirSync(deep1, { recursive: true })
	mkdirSync(deep2, { recursive: true })
	hardenDir(deep1)
	hardenDir(deep2)
	try {
		seedCapabilitySid(base)
		// repairCapabilityTreeDeep reads the SIDs from the root itself.
		const out = await repairCapabilityTreeDeep(base)
		assert.deepEqual(new Set(out.fixed), new Set([deep1, deep2]))
		assert.equal(out.error, undefined)
		// Second run: nothing left to fix.
		const again = await repairCapabilityTreeDeep(base)
		assert.deepEqual(again.fixed, [])
		const sids = capabilitySids(base)
		assert.ok(!isHardenedDir(deep1, sids))
		assert.ok(!isHardenedDir(deep2, sids))
	} finally {
		cleanupTree(base)
	}
})

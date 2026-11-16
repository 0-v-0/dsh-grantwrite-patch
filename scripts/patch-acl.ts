#!/usr/bin/env node
// Generate the pnpm patch that turns the dsh Windows ACL sandbox into acl-only mode:
//
//   1. add the grant-root guard (refuse drive roots, the user profile, DSH-home
//      ancestors and subtrees that carry PE executables)
//   2. stop writing the permanent, inheritable Low mandatory label
//   3. keep the confined token at its ambient integrity
//
// The patch is written for `pnpm.patchedDependencies`; the installed package is
// never edited in place. Non-Windows hosts skip.
//
// Run with Node's type stripping: `node scripts/patch-acl.ts`.

import { execFileSync } from 'node:child_process'
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'

const PKG = '@deepseek-ai/dsh-sandbox-windows-acl'
const NL = '\n'
const T = '\t'

/** Guard snippet injected into the bundled implementation (2-space indent, generated code style). */
const GUARD = "const GRANT_ROOT_GUARD_LIMIT = 20000;\n/** Verdict cache: normalizeGrantRoot(resolved) -> null (safe) | reason string. */\nconst grantRootVerdicts = /* @__PURE__ */ new Map();\nfunction normalizeGrantRoot(path) {\n  return path.replace(/[\\\\/]+$/, \"\").toLowerCase();\n}\nfunction refuseGrantRoot(path, reason) {\n  throw new Error('sandbox windows-acl: refusing to grant write access to ' + path + ' (' + reason + '). Point the workspace or store at a project-local directory, or set DSH_SANDBOX_ALLOW_EXEC_TREE=1.');\n}\n/**\n* Refuse to grant write on a broad shared directory (drive root, user profile\n* root, ancestor of the DSH home) or on a subtree that carries PE executables.\n* The grant ACE this backend writes is inheritable and never revoked, so a\n* sloppy allowedDirs entry would hand every later confined process write\n* access to that tree.\n* @param path - the directory about to receive the write grant.\n*/\nfunction assertGrantRootSafe(path) {\n  const override = process.env.DSH_SANDBOX_ALLOW_EXEC_TREE;\n  if (override === \"1\" || override === \"true\") return;\n  let resolved;\n  try { resolved = realpathSync(path); } catch { return; }\n  const key = normalizeGrantRoot(resolved);\n  const cached = grantRootVerdicts.get(key);\n  if (cached !== void 0) {\n    if (cached !== null) refuseGrantRoot(resolved, cached);\n    return;\n  }\n  const verdict = grantRootVerdict(resolved);\n  grantRootVerdicts.set(key, verdict);\n  if (verdict !== null) refuseGrantRoot(resolved, verdict);\n}\nfunction grantRootVerdict(resolved) {\n  const home = (process.env.USERPROFILE ?? \"\").trim();\n  const dshHome = (process.env.DSH_HOME ?? (home.length > 0 ? join(home, \".dsh\") : \"\")).trim();\n  const candidate = normalizeGrantRoot(resolved);\n  if (/^[a-z]:$/.test(candidate)) return \"drive root\";\n  if (home.length > 0 && candidate === normalizeGrantRoot(home)) return \"user profile root\";\n  if (dshHome.length > 0 && normalizeGrantRoot(dshHome).startsWith(candidate + sep)) return \"ancestor of the DSH home directory\";\n  if (!existsSync(resolved)) return null;\n  let entries = 0;\n  const queue = [resolved];\n  while (queue.length > 0) {\n    const current = queue.pop();\n    let children;\n    try { children = readdirSync(current, { withFileTypes: true }); } catch { continue; }\n    for (const child of children) {\n      entries += 1;\n      if (entries > GRANT_ROOT_GUARD_LIMIT) return GRANT_ROOT_GUARD_LIMIT + \"+ entries, too large to verify\";\n      if (child.name === \"node_modules\" || child.name === \".git\") continue;\n      const full = join(current, child.name);\n      if (child.isDirectory()) queue.push(full);\n      else if (/\\\\.(exe|dll|sys|scr|com|msi)$/i.test(child.name)) return \"executable \" + full;\n    }\n  }\n  return null;\n}\n\n"

interface Options {
	check: boolean
	help: boolean
	out: string
	target: string
}

function log(message: string): void {
	process.stdout.write(`${message}${NL}`)
}

function parseArgs(argv: string[]): Options {
	const opts: Options = { check: false, help: false, out: '', target: '' }
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i] ?? ''
		if (arg === '--check' || arg === '-c') {
			opts.check = true
		} else if (arg === '--target' || arg === '-t') {
			opts.target = argv[++i] ?? ''
		} else if (arg.startsWith('--target=')) {
			opts.target = arg.slice('--target='.length)
		} else if (arg === '--out' || arg === '-o') {
			opts.out = argv[++i] ?? ''
		} else if (arg.startsWith('--out=')) {
			opts.out = arg.slice('--out='.length)
		} else if (arg === '--help' || arg === '-h') {
			opts.help = true
		} else {
			throw new Error(`unknown argument: ${arg}`)
		}
	}
	return opts
}

function usage(): string {
	return [
		'usage: node scripts/patch-acl.ts [--check] [--target <package-dir>] [--out <patches-dir>]',
		'',
		'  --check          report the edits without writing a patch',
		`  --target <dir>   installed ${PKG} directory (default: resolved from cwd)`,
		'  --out <dir>      destination for the .patch file (default: ./patches)',
		'',
		'Skipped on non-Windows hosts.',
	].join(NL)
}

/** Directory holding the package.json nearest to the cwd, for nested installs. */
function cwdPackageDir(): string {
	let dir = process.cwd()
	for (;;) {
		if (existsSync(path.join(dir, 'package.json'))) {
			return dir
		}
		const parent = path.dirname(dir)
		if (parent === dir) {
			return process.cwd()
		}
		dir = parent
	}
}

/** Installed acl package directory: explicit target, env, node resolution, then the .pnpm store. */
function resolveTarget(explicit: string): string {
	if (explicit) {
		return path.resolve(explicit)
	}
	const env = (process.env.DSH_ACL_DIR ?? '').trim()
	if (env) {
		return path.resolve(env)
	}
	try {
		const require = createRequire(path.join(process.cwd(), 'noop.js'))
		return path.dirname(require.resolve(`${PKG}/package.json`))
	} catch {
		/* fall through to the .pnpm scan */
	}
	const roots = [path.join(process.cwd(), 'node_modules', '.pnpm'), path.join(cwdPackageDir(), 'node_modules', '.pnpm')]
	const found: string[] = []
	for (const root of roots) {
		if (!existsSync(root)) {
			continue
		}
		for (const entry of readdirSync(root)) {
			if (!entry.startsWith('@deepseek-ai+dsh-sandbox-wi_')) {
				continue
			}
			const candidate = path.join(root, entry, 'node_modules', ...PKG.split('/'))
			if (existsSync(path.join(candidate, 'package.json'))) {
				found.push(candidate)
			}
		}
	}
	return found.sort().at(-1) ?? ''
}

/** The bundled implementation file that owns grantWrite / the Low label. */
function findBundle(dir: string): string {
	const lib = path.join(dir, 'lib')
	if (!existsSync(lib)) {
		return ''
	}
	for (const entry of readdirSync(lib)) {
		if (!/^types-.*\.js$/.test(entry)) {
			continue
		}
		const file = path.join(lib, entry)
		const text = readFileSync(file, 'utf8')
		if (text.includes('function grantWrite(') && text.includes('buildLowLabelAcl')) {
			return file
		}
	}
	return ''
}

function stage(source: string, target: string): void {
	cpSync(path.join(source, 'lib'), path.join(target, 'lib'), { recursive: true })
	cpSync(path.join(source, 'package.json'), path.join(target, 'package.json'))
}

function git(dir: string, args: string[]): string {
	return execFileSync('git', args, { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
}

/** Apply every missing edit to the staged bundle; returns the applied edit names. */
function applyEdits(dir: string): string[] {
	const bundle = findBundle(dir)
	if (!bundle) {
		throw new Error(`no bundled ACL implementation found under ${dir}/lib`)
	}
	let text = readFileSync(bundle, 'utf8')
	const applied: string[] = []
	const fsImport = 'import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";'
	const fsImportPatched = 'import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";'
	if (!text.includes('function assertGrantRootSafe(')) {
		if (!text.includes(fsImport)) {
			throw new Error('unsupported acl bundle: fs import anchor missing')
		}
		const anchor = `function grantWrite(api, path, sidPtr, lowLabelSidPtr, worldSidPtr) {${NL}${T}withPathLock(api, path, () => {`
		if (!text.includes(anchor)) {
			throw new Error('unsupported acl bundle: grantWrite anchor missing')
		}
		const guarded = `${GUARD}function grantWrite(api, path, sidPtr, lowLabelSidPtr, worldSidPtr) {${NL}${T}assertGrantRootSafe(path);${NL}${T}withPathLock(api, path, () => {`
		text = text.replace(fsImport, fsImportPatched)
		text = text.replace(anchor, guarded)
		applied.push('grant-root guard')
	}
	const reuse = 'if (oldAcl !== null && labelAcl !== null && hasExactGrant(oldAcl, sidPtr) && hasExactDeny(oldAcl, worldSidPtr) && hasExactLabel(labelAcl, lowLabelSidPtr)) {'
	if (text.includes(reuse)) {
		text = text.replace(reuse, 'if (oldAcl !== null && hasExactGrant(oldAcl, sidPtr) && hasExactDeny(oldAcl, worldSidPtr)) {')
		applied.push('grant reuse check without the Low label')
	}
	const merge = `${T}${T}mergeAndApply(api, path, Buffer.concat([buildExplicitAccess(worldSidPtr, 3, 64, 2), buildExplicitAccess(sidPtr, 1, GRANT_MASK)]), oldAcl, {`
	const labelBlock = [
		`${T}${T}let label;`,
		`${T}${T}try {`,
		`${T}${T}${T}label = buildLowLabelAcl(api, lowLabelSidPtr);`,
		`${T}${T}} catch (error) {`,
		`${T}${T}${T}if (descriptor !== null) api.localFree(descriptor);`,
		`${T}${T}${T}throw error;`,
		`${T}${T}}`,
		merge,
		`${T}${T}${T}kind: "apply",`,
		`${T}${T}${T}acl: label`,
		`${T}${T}}, descriptor, "grantWrite");`,
	].join(NL)
	if (text.includes(labelBlock)) {
		const noLabel = [
			merge,
			`${T}${T}${T}kind: "keep"`,
			`${T}${T}}, descriptor, "grantWrite");`,
		].join(NL)
		text = text.replace(labelBlock, noLabel)
		applied.push('no Low mandatory label on the grant')
	}
	const tokenCall = `${T}${T}${T}restrictTokenIntegrity(api, restrictedToken, lowLabelSid);`
	if (text.includes(tokenCall)) {
		text = text.replace(tokenCall, `${T}${T}${T}// acl-only mode: the token keeps its ambient integrity; no Low mandatory label is applied.`)
		applied.push('ambient token integrity')
	}
	writeFileSync(bundle, text)
	return applied
}

function main(): number {
	const opts = parseArgs(process.argv.slice(2))
	if (opts.help) {
		log(usage())
		return 0
	}
	if (process.platform !== 'win32') {
		log(`skip: ${process.platform} is not Windows; the ACL sandbox and its Low-integrity label are Windows-only`)
		return 0
	}
	const target = resolveTarget(opts.target)
	if (!target) {
		log(`skip: cannot locate ${PKG}; pass --target <package-dir>`)
		return 0
	}
	const { version } = JSON.parse(readFileSync(path.join(target, 'package.json'), 'utf8')) as { version: string }
	log(`target: ${target} (v${version})`)
	const sourceBundle = findBundle(target)
	if (!sourceBundle) {
		log(`skip: ${target} does not carry the bundled ACL implementation this script patches`)
		return 0
	}
	const original = readFileSync(sourceBundle, 'utf8')
	if (original.includes('acl-only mode') || original.includes('assertGrantRootSafe(path);')) {
		log('already patched: the installed package is already acl-only; nothing to generate')
		return 0
	}
	const scratch = mkdtempSync(path.join(os.tmpdir(), 'dsh-acl-patch-'))
	stage(target, scratch)
	git(scratch, ['init', '-q'])
	git(scratch, ['add', '-A'])
	git(scratch, ['-c', 'user.email=patch@example.invalid', '-c', 'user.name=patch-acl', 'commit', '-qm', 'base'])
	const applied = applyEdits(scratch)
	if (applied.length === 0) {
		log('already patched: every edit is present; nothing to generate')
		return 0
	}
	const diff = git(scratch, ['diff'])
	if (opts.check) {
		log(`check: ${applied.length} edit(s) would apply, patch ${diff.length} bytes`)
		for (const item of applied) {
			log(`  - ${item}`)
		}
		return 0
	}
	const outDir = path.resolve(opts.out || path.join(process.cwd(), 'patches'))
	mkdirSync(outDir, { recursive: true })
	const file = path.join(outDir, `${PKG.replace('/', '__')}@${version}.patch`)
	writeFileSync(file, diff)
	log(`wrote ${file} (${diff.length} bytes)`)
	log('register it in the hosting pnpm-workspace.yaml:')
	log('  patchedDependencies:')
	log(`    "${PKG}@${version}": patches/${path.basename(file)}`)
	for (const item of applied) {
		log(`  - ${item}`)
	}
	return 0
}

try {
	process.exitCode = main()
} catch (e) {
	process.stderr.write(`patch-acl: ${e instanceof Error ? e.message : String(e)}${NL}`)
	process.exitCode = 1
}

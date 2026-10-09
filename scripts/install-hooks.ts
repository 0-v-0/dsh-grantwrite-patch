/**
 * 配置 core.hooksPath 为 .githooks 并生成 node 版钩子;由 package.json 的 "prepare" 调用
 * 1. git config core.hooksPath .githooks(非 git 检出下跳过,钩子仍生成)
 * 2. 生成 .githooks/commit-msg 与 pre-commit:共享片段由 hook-logic.ts 展开,再注入本机 node shebang:
 *    - Windows 写 #!<node 绝对路径>(含空格加引号),git 直接 CreateProcess 绕过 sh.exe
 *      (sh 依赖 signal pipe,受限沙箱下创建失败 Win32 error 5);
 *    - 其他平台用 env node;
 *    - 内容感知再生成;生成物不入库(.githooks/ 在 .gitignore),克隆后本地重建
 * 3. chmod +x 生成物(Unix)
 */
import { execSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readSharedSnippet } from './hook-logic.ts'

const __dirname = dirname(fileURLToPath(import.meta.url))
const repoRoot = join(__dirname, '..')
const hooksDir = join(repoRoot, '.githooks')
const gitDir = join(repoRoot, '.git')

// .githooks 不入库,新克隆中不存在,主动创建
mkdirSync(hooksDir, { recursive: true })

// 仅 hooksPath 依赖 git;钩子生成在非 git 检出下也执行
if (existsSync(gitDir)) {
	try {
		execSync('git config core.hooksPath .githooks', { cwd: repoRoot, stdio: 'ignore' })
		console.log('[install-hooks] core.hooksPath set to .githooks')
	} catch {
		console.error(
			'[install-hooks] could not set core.hooksPath, set it manually: git config core.hooksPath .githooks',
		)
	}
} else {
	console.error(
		'[install-hooks] not in a git repo (.git not found), skipping core.hooksPath setup.',
	)
}

// ---------------------------------------------------------------------------
// 钩子模板:占位符 /*@HOOK_SHARED:<region>@*/ 由 hook-logic.ts 展开
// 须用 String.raw 保留转义;内部字符串用 + 拼接,避免反引号/${} 干扰外层模板
// ---------------------------------------------------------------------------
const COMMIT_MSG_TEMPLATE = String.raw`
// node 是原生 Windows 程序,经 #!<node路径> shebang 由 git 直接 CreateProcess,绕过 sh/env
// (受限沙箱/受限 token 下 sh.exe 因 signal pipe 创建失败,Win32 error 5)
// 校验 Conventional Commits 与 fixup 目标;拦截机器绝对路径
// type 限常规集合、可选 scope/(!),描述 \S 开头;fixup 目标为 Conventional 或 ≥7 位短哈希
import fs from "node:fs";

/*@HOOK_SHARED:constants@*/

/*@HOOK_SHARED:commitMsg@*/

// git 以 $1 传入提交信息文件;$1 可能不存在,视为空
const file = process.argv[2];
let lines = [];
if (file && fs.existsSync(file)) {
	lines = filterCommitLines(fs.readFileSync(file, "utf8"));
}

const verdict = checkCommitSubject(lines);
if (!verdict.pass) {
	if (verdict.kind === "abs") {
		process.stderr.write(
			"ERROR: commit-msg hook rejected message: absolute path in commit message leaks machine/user info (replace with ./ or ~):\n" +
				"  " + verdict.hit + "\n",
		);
	} else if (verdict.kind === "target") {
		process.stderr.write(
			"ERROR: commit-msg hook rejected message: fixup!/squash!/amend! 目标不匹配:\n" +
				"  subject: " + verdict.hit + "\n" +
				"  expected: fixup!/squash!/amend! <type>(<scope>)?(!)?: <description>\n" +
				"        or: fixup!/squash!/amend! <hash 至少 7 位>\n",
		);
	} else {
		process.stderr.write(
			"ERROR: commit-msg hook rejected message (Conventional Commits required):\n" +
				"  subject: " + verdict.hit + "\n" +
				"  expected: <type>(<scope>)?(!)?: <description>\n" +
				"  type: feat|fix|refactor|docs|chore|perf|test|build|ci|style|revert\n",
		);
	}
	process.exit(1);
}
process.exit(0);
`
const PRE_COMMIT_TEMPLATE = String.raw`
// sh.exe 依赖 signal pipe(cygwin fork),受限沙箱下创建失败;node 经 #!<node路径> shebang 由 git 直接 CreateProcess 绕过 sh/env
// 钩子内调 git 避开 stdio pipe(受限环境 EPERM),改用文件句柄继承捕获输出
// 扫描暂存内容中 ^+ 开头的行,拦截绝对路径
// 两阶段:1) 扫描暂存 ^+ 行拦截绝对路径;2) oxlint 检查暂存源码(.oxlintrc.staged.json,typeAware=false)
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

/*@HOOK_SHARED:constants@*/

/*@HOOK_SHARED:preCommit@*/

// 受限环境 stdio pipe 可能 EPERM,改用文件句柄继承捕获输出
function spawnOut(exe, args, cwd) {
	// 独立临时目录避免可预测路径竞态;finally 整体删除
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), "precommit-"));
	const outF = path.join(dir, "out");
	const errF = path.join(dir, "err");
	let outFd = null;
	let errFd = null;
	try {
		outFd = fs.openSync(outF, "w");
		errFd = fs.openSync(errF, "w");
		const r = spawnSync(exe, args, { stdio: ["ignore", outFd, errFd], cwd });
		const out = fs.readFileSync(outF, "utf8");
		const err = fs.readFileSync(errF, "utf8");
		return { status: r.status, error: r.error, out, err };
	} finally {
		for (const fd of [outFd, errFd]) {
			if (fd !== null) {
				try {
					fs.closeSync(fd);
				} catch {}
			}
		}
		fs.rmSync(dir, { recursive: true, force: true });
	}
}
// 钩子 cwd 恒为仓库根(git 启动钩子时保证);子目录内 commit 亦然
function git(args) {
	return spawnOut("git", args, process.cwd());
}

// 单次调用取全部暂存 diff(--no-color),按 hunk 头归并到文件;仍只扫 ^+ 变更行
// 单次调用省 N-1 次进程启动(Windows ~70ms/次);扫描量恒为变更行,大文件不退化
const diff = git(["diff", "--cached", "--no-color"]);
if (diff.error) {
	process.stderr.write("ERROR: pre-commit hook could not diff staged changes: " + diff.error.message + "\n");
	process.exit(1);
}

let exitCode = 0;
let failMsg = "";
let current = null
const flusher = (target) => {
	if (current && (target === null || target !== current.file)) {
		const offending = current.lines.filter((line) => isOffendingAddedLine(line));
		if (offending.length > 0) {
			exitCode = 1;
			failMsg += "\n\n  " + current.file + ":\n" + offending.join("\n");
		}
		current = null;
	}
	if (target !== null) current = { file: target, lines: [] };
};

for (const line of diff.out.split(/\r?\n/)) {
	const m = line.match(/^diff --git a\/(.*) b\/(.*)$/);
	if (m) {
		// 跳过 SKIP 表命中的文件(rename 时 a/ 侧为旧路径、b/ 侧为新路径,双侧参与判定)。
		// 命中时同样走 flusher(null) 结算:此前直接置 current = null 会把上一个文件的
		// offending 行静默丢弃,造成「跳过表之后的文件一律漏报」的假阴性。
		flusher(isSkippedPath(m[1], m[2]) ? null : m[1]);
	} else if (current) {
		current.lines.push(line);
	} else {
		// 版本头等无归属输出不参与扫描
	}
}
flusher(null);

if (exitCode !== 0) {
	process.stderr.write("ERROR: pre-commit hook detected absolute paths in staged changes:");
	process.stderr.write(failMsg + "\n\n");
	process.stderr.write("Absolute paths leak machine/user info and are non-portable.\n");
	process.stderr.write("Replace them with project-relative paths (./) or home placeholders (~).\n");
	process.exit(1);
}
// ---------------------------------------------------------------------------
// 阶段 2:oxlint 检查暂存源码(轻量配置 .oxlintrc.staged.json,typeAware=false,
// 避免全量类型程序图开销;仅 lint 新提交的源码文件,成功静默)
// 显式传文件列表而非 --staged:扩展名过滤在钩子内完成,oxlint 再应用配置 ignorePatterns
// (ignorePatterns 继承自主配置 .oxlintrc.json,已排除 *.js/*.mjs/*.cjs/*.config.ts、lib/dist/docs/profiles/.dsh-smoke)
// ---------------------------------------------------------------------------
const OXLINT_BIN = path.join(process.cwd(), "node_modules", "oxlint", "bin", "oxlint");
const OXLINT_CONFIG = path.join(process.cwd(), ".oxlintrc.staged.json");
const LINT_EXT = /\.(?:ts|mts|cts|tsx|jsx|vue)$/;

const stagedFiles = git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "--no-color"]);
if (stagedFiles.error) {
	process.stderr.write("ERROR: pre-commit hook could not list staged files: " + stagedFiles.error.message + "\n");
	process.exit(1);
}
const lintFiles = stagedFiles.out
	.split(/\r?\n/)
	.filter((file) => file.length > 0 && LINT_EXT.test(file));

if (lintFiles.length > 0) {
	if (!fs.existsSync(OXLINT_CONFIG)) {
		process.stderr.write("ERROR: pre-commit hook could not lint: missing " + OXLINT_CONFIG + "\n");
		process.exit(1);
	}
	const lint = spawnOut(process.execPath, [OXLINT_BIN, "--config", OXLINT_CONFIG].concat(lintFiles), process.cwd());
	if (lint.error) {
		process.stderr.write("ERROR: pre-commit hook could not run oxlint: " + lint.error.message + "\n");
		process.exit(1);
	}
	if (lint.status !== 0) {
		process.stderr.write("\nERROR: pre-commit hook lint failed (oxlint):\n");
		process.stderr.write(lint.out + lint.err);
		process.stderr.write("Fix with: pnpm lint:fix  (or npx oxlint --fix <files>)\n");
		process.exit(1);
	}
}
process.exit(0);
`

// 展开占位符;未知 region 抛错提示检查标记拼写
function expandTemplate(tpl, name) {
	return tpl.replace(/\/\*@HOOK_SHARED:([A-Za-z]+)@\*\//g, (_m0, region) => {
		try {
			return readSharedSnippet(region)
		} catch (err) {
			throw new Error(
				`[install-hooks] 未知的共享片段占位符: ${region}(${name})(检查 install-hooks.ts 与 hook-logic.ts 的标记拼写一致): ${err.message}`,
			)
		}
	})
}

// 写入生成物并赋可执行位(Unix);reason 为日志尾串
function writeGeneratedHook(outPath, expected, reason) {
	writeFileSync(outPath, expected)
	try {
		chmodSync(outPath, 0o755)
	} catch {
		// Windows 上 chmod 无效,忽略
	}
	console.log(`[install-hooks] ${reason}`)
}

// 内容感知再生成:正文一致仅 shebang 过期则重写,正文不同按模板重写
// 生成物不入库,不接受手改;自定义请改本文件模板
const HOOK_CONFIGS = [
	['commit-msg', COMMIT_MSG_TEMPLATE],
	['pre-commit', PRE_COMMIT_TEMPLATE],
]
const nodePath = process.execPath
const shebang =
	process.platform === 'win32'
		? `#!${/ /.test(nodePath) ? `"${nodePath}"` : nodePath}`
		: '#!/usr/bin/env node'
for (const [name, tpl] of HOOK_CONFIGS) {
	const outPath = join(hooksDir, name)
	const body = expandTemplate(tpl, name)
	const expectedContent = `${shebang}\n${body}`
	if (!existsSync(outPath)) {
		writeGeneratedHook(outPath, expectedContent, `generated .githooks/${name}`)
		continue
	}
	const existing = readFileSync(outPath, 'utf8')
	const nl = existing.indexOf('\n')
	const existingFirstLine = nl === -1 ? existing : existing.slice(0, nl)
	const existingBody = nl === -1 ? '' : existing.slice(nl + 1)
	if (existingBody === body) {
		if (existingFirstLine === shebang) {
			console.log(`[install-hooks] .githooks/${name} already up to date`)
		} else {
			writeGeneratedHook(outPath, expectedContent, `regenerated .githooks/${name}`)
		}
	} else {
		writeGeneratedHook(
			outPath,
			expectedContent,
			`regenerated .githooks/${name} (content differs from template)`,
		)
	}
}

const expectedFiles = ['pre-commit', 'commit-msg']
const missing = expectedFiles.filter((base) => !existsSync(join(hooksDir, base)))
if (missing.length === 0) {
	console.log('[install-hooks] git hooks installed successfully.')
} else {
	console.error(`[install-hooks] git hooks NOT installed, missing: ${missing.join(', ')}`)
	process.exit(1)
}
